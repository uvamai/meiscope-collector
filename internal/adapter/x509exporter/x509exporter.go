// Package x509exporter is the x509-certificate-exporter adapter
// (FR-DISC-028). It reads the Prometheus metrics endpoint of an
// x509-certificate-exporter the customer already runs (x509_cert_not_after,
// x509_cert_not_before and the certificate labels) and maps every
// certificate series to a store observation with method adapter and source
// x509_certificate_exporter. The exporter publishes no fingerprint, so the
// certificate is identified by issuer and serial (proposed contract 0.10.0,
// behind MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2). It reads one URL and
// connects to nothing else.
package x509exporter

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Name is the registry name, Source the evidence source.
const (
	Name   = "x509-certificate-exporter"
	Source = "x509_certificate_exporter"
)

// FileStore is the store locator of certificates the exporter read from
// files on its host (target.path is the file).
const FileStore = "x509-certificate-exporter/host/files"

// Metric names read from the exporter.
const (
	metricNotAfter   = "x509_cert_not_after"
	metricNotBefore  = "x509_cert_not_before"
	metricReadErrors = "x509_read_errors"
)

// Run statistics keys.
const (
	StatSeries                 = "series"
	StatUnchanged              = "unchanged"
	StatMalformedLines         = "skipped_malformed_line"
	StatNoIdentity             = "skipped_no_identity"
	StatNoNotAfter             = "skipped_no_not_after"
	StatNoLocator              = "skipped_no_locator"
	StatReadErrors             = "exporter_read_errors"
	StatSkippedFeatureDisabled = "skipped_feature_disabled"
)

func init() {
	adapter.Register(Name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env} })
}

// Adapter is the x509-certificate-exporter adapter.
type Adapter struct {
	env adapter.Env
}

var clusterPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    Name,
		Source:  Source,
		Summary: "certificates from an x509-certificate-exporter metrics endpoint (Prometheus text format)",
		Settings: []string{
			"url (the exporter's /metrics URL; https, or http with allow_http=true and no credential)",
			"host (the host name observations are filed under: the node of a file exporter, or the Kubernetes API server host so Secrets line up with the kubernetes adapter)",
			"cluster (the cluster name used in kubernetes/<cluster>/<namespace>/<secret> locators; required when the exporter watches Secrets)",
		},
		Credentials: []string{"bearer_token (optional)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	u, err := url.Parse(cfg.Setting("url", ""))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("x509-certificate-exporter: url must be an absolute http(s) URL without user information")
	}
	allowHTTP, err := strconv.ParseBool(cfg.Setting("allow_http", "false"))
	if err != nil {
		return errors.New("x509-certificate-exporter: allow_http must be true or false")
	}
	if u.Scheme == "http" {
		if !allowHTTP {
			return errors.New("x509-certificate-exporter: an http url needs allow_http=true")
		}
		if _, ok := cfg.Credentials["bearer_token"]; ok {
			return errors.New("x509-certificate-exporter: a bearer_token is never sent over http")
		}
	}
	if h := cfg.Setting("host", ""); h == "" || len(h) > 253 || strings.ContainsAny(h, "/ ") {
		return errors.New("x509-certificate-exporter: host is required (a host name)")
	}
	if c := cfg.Setting("cluster", ""); c != "" && !clusterPattern.MatchString(c) {
		return fmt.Errorf("x509-certificate-exporter: cluster must match %s", clusterPattern)
	}
	return nil
}

// series is one certificate: the labels shared by its samples.
type series struct {
	labels    map[string]string
	notAfter  *float64
	notBefore *float64
}

// Sync scrapes the endpoint once and returns the certificates that changed.
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := map[string]string{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	u, err := url.Parse(cfg.Setting("url", ""))
	if err != nil {
		return adapter.Result{}, errors.New("x509-certificate-exporter: invalid url")
	}
	var tok credential.Secret
	if _, ok := cfg.Credentials["bearer_token"]; ok {
		if tok, err = cfg.Credential(ctx, a.env.Creds, "bearer_token"); err != nil {
			return adapter.Result{}, fmt.Errorf("x509-certificate-exporter: %w", err)
		}
	}
	g := &adapter.Getter{HTTP: a.env.HTTP, Env: a.env, Bearer: tok, MaxBody: 128 << 20}
	body, err := g.Get(ctx, u, "text/plain;version=0.0.4")
	if err != nil {
		return adapter.Result{}, fmt.Errorf("x509-certificate-exporter: %w", err)
	}
	st := map[string]int{StatSeries: 0, StatUnchanged: 0, StatMalformedLines: 0, StatNoIdentity: 0, StatNoNotAfter: 0, StatNoLocator: 0, StatReadErrors: 0, StatSkippedFeatureDisabled: 0}
	samples, bad, err := parseText(body, map[string]bool{metricNotAfter: true, metricNotBefore: true, metricReadErrors: true})
	if err != nil {
		return adapter.Result{}, fmt.Errorf("x509-certificate-exporter: %w", err)
	}
	st[StatMalformedLines] = bad
	byKey := map[string]*series{}
	var keys []string
	for _, s := range samples {
		if s.name == metricReadErrors {
			st[StatReadErrors] += int(s.value)
			continue
		}
		k := labelKey(s.labels)
		sr := byKey[k]
		if sr == nil {
			sr = &series{labels: s.labels}
			byKey[k] = sr
			keys = append(keys, k)
		}
		v := s.value
		if s.name == metricNotAfter {
			sr.notAfter = &v
		} else {
			sr.notBefore = &v
		}
	}
	sort.Strings(keys)
	st[StatSeries] = len(keys)
	at := adapter.ObservedAt(a.env.Clock.Now())
	host, cluster := cfg.Setting("host", ""), cfg.Setting("cluster", "")
	next := map[string]string{}
	var out []submit.Observation
	for _, k := range keys {
		o, reason := mapSeries(byKey[k], host, cluster, at)
		if reason != "" {
			st[reason]++
			continue
		}
		id := o.Target.Store + "|" + o.Target.Path + "|" + o.Adapter.Certificate.Issuer + "|" + o.Adapter.Certificate.Serial
		fp := adapter.Fingerprint(o)
		if next[id] == fp {
			continue // the same certificate listed twice
		}
		next[id] = fp
		if cur[id] == fp {
			st[StatUnchanged]++
			continue
		}
		out = append(out, o)
	}
	nc, err := adapter.EncodeCursor(next)
	if err != nil {
		return adapter.Result{}, err
	}
	if !a.env.Features.AdapterEvidenceV2 || !a.env.Features.LocalStoreV1 {
		st[StatSkippedFeatureDisabled] = len(out)
		if a.env.Log != nil {
			a.env.Log.Warn("x509-certificate-exporter observations were not sent: they need "+adapter.EnvAdapterEvidenceV2+" and "+adapter.EnvLocalStoreV1+" (proposed contract 0.10.0); the cursor was not advanced",
				"skipped_feature_disabled", len(out))
		}
		out, nc = nil, since
	}
	if a.env.Log != nil {
		a.env.Log.Info("x509-certificate-exporter sync", "instance", cfg.Name, "observations", len(out), "series", st[StatSeries],
			"unchanged", st[StatUnchanged], "read_errors", st[StatReadErrors])
	}
	return adapter.Result{Observations: out, Cursor: nc, Stats: st}, nil
}

func labelKey(l map[string]string) string {
	ks := make([]string, 0, len(l))
	for k := range l {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k + "\x00" + l[k] + "\x00")
	}
	return b.String()
}

// dn builds an RFC 4514-style name from the exporter's <prefix>_<attr>
// labels, most specific first, as Go's pkix.Name.String does.
func dn(l map[string]string, prefix string) string {
	var parts []string
	for _, attr := range []string{"CN", "OU", "O", "L", "ST", "C"} {
		if v := strings.TrimSpace(l[prefix+"_"+attr]); v != "" {
			parts = append(parts, attr+"="+escapeDN(v))
		}
	}
	return strings.Join(parts, ",")
}

func escapeDN(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `+`, `\+`, `"`, `\"`, `<`, `\<`, `>`, `\>`, `;`, `\;`)
	return r.Replace(v)
}

// serial converts the exporter's decimal serial_number label to lower-case
// hex, as the other adapters report serials.
func serial(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return ""
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 {
		return ""
	}
	return adapter.SerialHex(n)
}

func unixTime(v *float64) *time.Time {
	if v == nil || *v <= 0 || *v > 1e11 {
		return nil
	}
	t := time.Unix(int64(*v), 0).UTC()
	return &t
}

func mapSeries(sr *series, host, cluster string, at time.Time) (submit.Observation, string) {
	l := sr.labels
	issuer, ser := dn(l, "issuer"), serial(l["serial_number"])
	if issuer == "" || ser == "" {
		return submit.Observation{}, StatNoIdentity
	}
	na := unixTime(sr.notAfter)
	if na == nil {
		return submit.Observation{}, StatNoNotAfter
	}
	t := submit.Target{Kind: submit.KindStore, Host: host}
	ns, name := l["secret_namespace"], l["secret_name"]
	fp := l["filepath"]
	switch {
	case ns != "" && name != "" && cluster != "" && !strings.Contains(ns+name, "/"):
		t.Store = adapter.Clip("kubernetes/"+cluster+"/"+ns+"/"+name, 512)
	case strings.HasPrefix(fp, "/") && len(fp) <= 4096:
		t.Store, t.Path = FileStore, fp
	default:
		return submit.Observation{}, StatNoLocator
	}
	return submit.Observation{
		Target:     t,
		Method:     submit.MethodAdapter,
		ObservedAt: at,
		Outcome:    submit.OutcomeCertSeen,
		Adapter: &submit.AdapterEvidence{
			Source: Source,
			Certificate: &submit.CertificateMetadata{
				Serial:     ser,
				Issuer:     adapter.Clip(issuer, 4096),
				Subject:    adapter.Clip(dn(l, "subject"), 4096),
				CommonName: adapter.Clip(l["subject_CN"], 1024),
				NotBefore:  unixTime(sr.notBefore),
				NotAfter:   na,
			},
			// The exporter reports nothing about keys.
			Custody: &submit.Custody{KeyCustody: submit.KeyUnknown},
		},
	}, ""
}
