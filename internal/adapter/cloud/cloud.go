// Package cloud holds what the cloud-provider adapters (aws, cloudflare)
// share: the content-hash delta cursor, the MEISCOPE_FEATURE_CLOUD_RESOURCE_V1
// gate, public-certificate parsing and certificate metadata. It never parses
// or carries private keys: a PEM private-key block in an API answer is an
// error, and nothing of it is kept.
package cloud

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is the certificate fingerprint the contract names, not a security control
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Statistic keys shared by the cloud adapters.
const (
	// StatSkippedFeatureDisabled counts observations not sent because
	// MEISCOPE_FEATURE_CLOUD_RESOURCE_V1 is off.
	StatSkippedFeatureDisabled = "skipped_feature_disabled"
	// StatUnchanged counts resources unchanged since the cursor.
	StatUnchanged = "unchanged"
	// StatObserved counts resources read in this sync.
	StatObserved = "observed"
)

// MaxChain is the longest chain kept (Observation.served_chain maxItems).
const MaxChain = 20

// ErrKeyMaterial is returned when an API answer holds a private key. The
// adapters only call read operations that return public certificates, so
// this means a misconfigured or unexpected endpoint; nothing of it is kept.
var ErrKeyMaterial = errors.New("the answer contains private-key material; refusing it")

// Delta is the cursor of a cloud adapter: per resource the digest of the
// last observation sent, and when everything was last re-sent.
type Delta struct {
	Seen   map[string]string `json:"seen"`
	FullAt time.Time         `json:"full_at"`
}

// Key identifies an observation's resource.
func Key(o submit.Observation) string {
	if c := o.Target.Cloud; c != nil {
		return c.Provider + "|" + c.Service + "|" + c.Region + "|" + c.ResourceID
	}
	b, _ := json.Marshal(o.Target)
	return string(b)
}

func digest(o submit.Observation) string {
	o.ObservedAt = time.Time{}
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Filter keeps the observations whose resource is new or changed since the
// cursor; every refresh (when positive) it keeps all of them, so the core
// keeps seeing resources that have not changed. Resources no longer listed
// are dropped from the next cursor. The order of obs is kept.
func Filter(since adapter.Cursor, obs []submit.Observation, now time.Time, refresh time.Duration, st map[string]int) ([]submit.Observation, adapter.Cursor, error) {
	var d Delta
	if err := adapter.DecodeCursor(since, &d); err != nil {
		return nil, "", err
	}
	full := d.FullAt.IsZero() || (refresh > 0 && !now.Before(d.FullAt.Add(refresh)))
	next := Delta{Seen: make(map[string]string, len(obs)), FullAt: d.FullAt}
	if full {
		next.FullAt = now.UTC()
	}
	var out []submit.Observation
	for _, o := range obs {
		k, h := Key(o), digest(o)
		if prev, dup := next.Seen[k]; dup && prev == h {
			continue
		}
		next.Seen[k] = h
		if !full && d.Seen[k] == h {
			st[StatUnchanged]++
			continue
		}
		out = append(out, o)
	}
	c, err := adapter.EncodeCursor(next)
	return out, c, err
}

// Finish applies the feature gate: with MEISCOPE_FEATURE_CLOUD_RESOURCE_V1
// off nothing is returned and the cursor stays where it was, so the core's
// current contract (0.9.0, no cloud_resource kind) is never broken and no
// change is lost for the day the switch is turned on.
func Finish(env adapter.Env, adapterName string, cfg adapter.Config, obs []submit.Observation, st map[string]int, since, next adapter.Cursor) adapter.Result {
	if !env.Features.CloudResourceV1 {
		st[StatSkippedFeatureDisabled] += len(obs)
		if env.Log != nil && len(obs) > 0 {
			env.Log.Warn(adapterName+" observations were not sent because "+adapter.EnvCloudResourceV1+" is off; the core has not adopted cloud_resource targets yet, and the cursor was not advanced",
				"instance", cfg.Name, StatSkippedFeatureDisabled, len(obs))
		}
		return adapter.Result{Cursor: since, Stats: st}
	}
	if env.Log != nil {
		env.Log.Info(adapterName+" sync", "instance", cfg.Name, "observations", len(obs),
			StatObserved, st[StatObserved], StatUnchanged, st[StatUnchanged])
	}
	return adapter.Result{Observations: obs, Cursor: next, Stats: st}
}

// ParsePEMChain decodes the CERTIFICATE blocks of PEM text into DER, in
// order, keeping at most MaxChain. A private-key block is an error.
func ParsePEMChain(texts ...string) ([][]byte, error) {
	var out [][]byte
	for _, t := range texts {
		rest := []byte(t)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if strings.Contains(b.Type, "PRIVATE KEY") {
				return nil, ErrKeyMaterial
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			if _, err := x509.ParseCertificate(b.Bytes); err != nil {
				return nil, fmt.Errorf("certificate %d: %w", len(out), err)
			}
			if len(out) < MaxChain {
				out = append(out, b.Bytes)
			}
		}
	}
	return out, nil
}

// Metadata derives the contract's CertificateMetadata from a DER certificate.
func Metadata(der []byte) (*submit.CertificateMetadata, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(der) //nolint:gosec // fingerprint, see import
	ca := c.IsCA
	self := bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
	m := &submit.CertificateMetadata{
		SHA1:             hex.EncodeToString(sum[:]),
		Serial:           clip(c.SerialNumber.Text(16), 128),
		Subject:          clip(c.Subject.String(), 4096),
		Issuer:           clip(c.Issuer.String(), 4096),
		CommonName:       clip(c.Subject.CommonName, 1024),
		NotBefore:        TimePtr(c.NotBefore),
		NotAfter:         TimePtr(c.NotAfter),
		CA:               &ca,
		SelfSigned:       &self,
		KeyAlgorithm:     c.PublicKeyAlgorithm.String(),
		SigningAlgorithm: c.SignatureAlgorithm.String(),
		SubjectKeyID:     hex.EncodeToString(c.SubjectKeyId),
		AuthorityKeyID:   hex.EncodeToString(c.AuthorityKeyId),
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		m.KeyStrength = fmt.Sprint(k.N.BitLen())
	case *ecdsa.PublicKey:
		m.KeyStrength = fmt.Sprint(k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		m.KeyStrength = "256"
	}
	return m, nil
}

// Hostnames merges name lists: lower case, no trailing dot, no duplicates,
// sorted, at most 1000, each at most 253 characters.
func Hostnames(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, n := range l {
			n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
			if n == "" || len(n) > 253 || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out
}

// TimePtr returns t in UTC, or nil for the zero time.
func TimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
