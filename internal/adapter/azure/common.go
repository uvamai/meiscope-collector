package azure

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is the certificate fingerprint the platforms report, not a security function
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// ProviderAzure is target.provider of every cloud_resource these adapters
// report (proposed contract 0.10.0).
const ProviderAzure = "azure"

// base is what every Azure adapter shares.
type base struct {
	env  adapter.Env
	desc adapter.Description
}

func (b *base) Describe() adapter.Description { return b.desc }

// newClient prepares a client for one sync.
func (b *base) newClient(cfg adapter.Config, defRate float64) *client {
	hc := b.env.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	rate := defRate
	if v, err := strconv.ParseFloat(cfg.Setting("rate_per_second", ""), 64); err == nil && v > 0 {
		rate = v
	}
	return &client{
		hc:    hc,
		ts:    newTokenSource(cfg, b.env, hc),
		lim:   adapter.NewLimiter(b.env.Clock, rate),
		env:   b.env,
		stats: map[string]int{},
	}
}

func (b *base) now() time.Time { return b.env.Clock.Now().UTC().Truncate(time.Second) }

// finish applies the feature switches. Observations whose shape the core's
// current contract would reject are dropped and counted, and the cursor is
// not advanced, so nothing is lost for the day the switch is turned on:
// cloud_resource targets need MEISCOPE_FEATURE_CLOUD_RESOURCE_V1, store
// targets MEISCOPE_FEATURE_LOCAL_STORE_V1.
func (b *base) finish(cfg adapter.Config, obs []submit.Observation, st map[string]int, next, since adapter.Cursor) adapter.Result {
	out := make([]submit.Observation, 0, len(obs))
	var off []string
	for _, o := range obs {
		switch {
		case o.Target.Kind == submit.KindCloudResource && !b.env.Features.CloudResourceV1:
			st[StatSkippedFeatureDisabled]++
			off = appendOnce(off, adapter.EnvCloudResourceV1)
		case (o.Target.Kind == submit.KindStore || o.Target.Kind == submit.KindFile) && !b.env.Features.LocalStoreV1:
			st[StatSkippedFeatureDisabled]++
			off = appendOnce(off, adapter.EnvLocalStoreV1)
		default:
			out = append(out, o)
		}
	}
	cursor := next
	if len(off) > 0 {
		cursor = since
	}
	if b.env.Log != nil {
		if len(off) > 0 {
			b.env.Log.Warn(b.desc.Name+" observations were not sent because a feature switch is off; the core has not adopted their shape yet, and the cursor was not advanced",
				"instance", cfg.Name, "switches", strings.Join(off, ","), StatSkippedFeatureDisabled, st[StatSkippedFeatureDisabled])
		}
		keys := make([]string, 0, len(st))
		for k := range st {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		args := []any{"instance", cfg.Name, "observations", len(out)}
		for _, k := range keys {
			args = append(args, k, st[k])
		}
		b.env.Log.Info(b.desc.Name+" sync", args...)
	}
	return adapter.Result{Observations: out, Cursor: cursor, Stats: st}
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func mergeStats(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

// cloudObservation starts an observation of a cloud resource.
func cloudObservation(host, resourceID, resourceType, region, source string, at time.Time) submit.Observation {
	return submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: strings.ToLower(host),
			Provider: ProviderAzure, ResourceID: resourceID, ResourceType: resourceType, Region: region,
		},
		Method:     submit.MethodAdapter,
		ObservedAt: at,
		Outcome:    submit.OutcomeReached,
		Adapter:    &submit.AdapterEvidence{Source: source},
	}
}

// withCertificate sets the certificate metadata and outcome cert_seen.
func withCertificate(o *submit.Observation, m *submit.CertificateMetadata) {
	o.Outcome = submit.OutcomeCertSeen
	o.Adapter.Certificate = m
}

var sha1Hex = regexp.MustCompile(`^[0-9a-f]{40}$`)

// normThumbprint returns a SHA-1 thumbprint as lower-case hex, or "".
func normThumbprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if sha1Hex.MatchString(s) {
		return s
	}
	return ""
}

// certMetadata parses a DER certificate into the public metadata the
// contract carries. Only the certificate is parsed; there is no key here.
func certMetadata(der []byte) (*submit.CertificateMetadata, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha1.Sum(der) //nolint:gosec // fingerprint, not a security function
	nb, na := c.NotBefore.UTC(), c.NotAfter.UTC()
	ca := c.IsCA
	self := bytes.Equal(c.RawIssuer, c.RawSubject)
	m := &submit.CertificateMetadata{
		SHA1:             hex.EncodeToString(sum[:]),
		Serial:           strings.ToLower(c.SerialNumber.Text(16)),
		Subject:          c.Subject.String(),
		Issuer:           c.Issuer.String(),
		CommonName:       c.Subject.CommonName,
		NotBefore:        &nb,
		NotAfter:         &na,
		CA:               &ca,
		SelfSigned:       &self,
		KeyAlgorithm:     c.PublicKeyAlgorithm.String(),
		SigningAlgorithm: c.SignatureAlgorithm.String(),
	}
	if len(c.SubjectKeyId) > 0 {
		m.SubjectKeyID = hex.EncodeToString(c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		m.AuthorityKeyID = hex.EncodeToString(c.AuthorityKeyId)
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		m.KeyStrength = strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		m.KeyStrength = strconv.Itoa(k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		m.KeyStrength = "256"
	}
	return m, nil
}

// pkcs7Certificates returns the certificates of a degenerate PKCS#7
// SignedData (RFC 2315: the "certs-only" form App Gateway reports as
// publicCertData). Nothing else of the structure is used.
func pkcs7Certificates(b []byte) ([][]byte, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if rest, err := asn1.Unmarshal(b, &ci); err != nil || len(rest) > 0 {
		return nil, errors.New("pkcs7: not a ContentInfo")
	}
	if !ci.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, errors.New("pkcs7: not SignedData")
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		Rest             asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("pkcs7: SignedData: %w", err)
	}
	var out [][]byte
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: certificate: %w", err)
		}
		out = append(out, raw.FullBytes)
	}
	if len(out) == 0 {
		return nil, errors.New("pkcs7: no certificates")
	}
	return out, nil
}

// leafOf picks the leaf of a certificate set: the one that issued no other
// certificate in the set (the first when that is ambiguous).
func leafOf(ders [][]byte) []byte {
	certs := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return ders[0]
		}
		certs = append(certs, c)
	}
	for i, c := range certs {
		issuer := false
		for j, o := range certs {
			if i != j && bytes.Equal(o.RawIssuer, c.RawSubject) && !bytes.Equal(o.RawSubject, c.RawSubject) {
				issuer = true
				break
			}
		}
		if !issuer {
			return ders[i]
		}
	}
	return ders[0]
}

// digestCursor holds, per resource ID, a digest of what was last reported,
// so a sync reports only what changed (APIs without a server-side delta).
type digestCursor struct {
	Digests map[string]string `json:"digests"`
}

func digestOf(o submit.Observation) string {
	o.ObservedAt = time.Time{}
	b, _ := json.Marshal(o)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:12])
}

// deltaByDigest keeps the observations whose digest changed since prev and
// returns the digests of everything seen now (resources that vanished drop
// out of the cursor).
func deltaByDigest(prev map[string]string, obs []submit.Observation, st map[string]int) ([]submit.Observation, map[string]string) {
	next := make(map[string]string, len(obs))
	var out []submit.Observation
	for _, o := range obs {
		id := o.Target.ResourceID
		d := digestOf(o)
		next[id] = d
		if prev[id] == d {
			st[StatUnchanged]++
			continue
		}
		out = append(out, o)
	}
	return out, next
}

// splitList splits a comma or whitespace separated setting.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}

// subscriptionsOf validates and returns the subscriptions setting.
func subscriptionsOf(cfg adapter.Config) ([]string, error) {
	subs := splitList(cfg.Setting("subscriptions", ""))
	if len(subs) == 0 {
		return nil, errors.New("subscriptions is required (subscription GUIDs, comma separated)")
	}
	for _, s := range subs {
		if !guidPattern.MatchString(s) {
			return nil, fmt.Errorf("subscription %q is not a GUID", s)
		}
	}
	return subs, nil
}

// runSubscriptions calls f for each subscription, in order.
func runSubscriptions(ctx context.Context, subs []string, f func(ctx context.Context, sub string) error) error {
	for _, s := range subs {
		if err := f(ctx, strings.ToLower(s)); err != nil {
			return err
		}
	}
	return nil
}

// parseTime parses the date-time forms the APIs use.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04:05.9999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
