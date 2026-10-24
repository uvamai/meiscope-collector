package ct

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Domains is a tenant's owned-domain list, normalised.
type Domains []string

// ParseDomains normalises and validates a domain list.
func ParseDomains(in []string) (Domains, error) {
	seen := map[string]bool{}
	var out Domains
	for _, d := range in {
		n := normalizeName(d)
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, "*.") || strings.ContainsAny(n, " /:@?#*") || !strings.Contains(n, ".") || len(n) > 253 {
			return nil, fmt.Errorf("invalid owned domain %q", d)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// Match returns the owned domain that name falls under ("" for none). A
// wildcard name "*.a.example.com" falls under the domains of a.example.com.
func (ds Domains) Match(name string) string {
	n := strings.TrimPrefix(normalizeName(name), "*.")
	best := ""
	for _, d := range ds {
		if (n == d || strings.HasSuffix(n, "."+d)) && len(d) > len(best) {
			best = d
		}
	}
	return best
}

// MatchAny returns the first owned domain any of names falls under.
func (ds Domains) MatchAny(names []string) string {
	for _, n := range names {
		if d := ds.Match(n); d != "" {
			return d
		}
	}
	return ""
}

// normalizeSerial writes a serial as lowercase hex without leading zeros, so
// crt.sh's DER-byte hex and big.Int hex compare equal.
func normalizeSerial(s string) string {
	s = strings.TrimLeft(strings.ToLower(strings.TrimSpace(s)), "0")
	if s == "" {
		return "0"
	}
	return s
}

func normalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// parsedCert is what the poller needs from a (pre)certificate.
type parsedCert struct {
	names   []string
	serial  string // see normalizeSerial
	scts    []submit.SCT
	precert bool
}

// parseCert parses a certificate or precertificate leniently (CT holds
// certificates that crypto/x509 rejects; design review finding 25) and
// returns its DNS names (SAN dNSName and CN), serial and embedded SCTs.
func parseCert(der []byte) (parsedCert, error) {
	c, err := ctx509.ParseCertificate(der)
	if ctx509.IsFatal(err) || c == nil {
		if err == nil {
			err = fmt.Errorf("empty certificate")
		}
		return parsedCert{}, fmt.Errorf("parse certificate: %w", err)
	}
	set := map[string]bool{}
	for _, n := range append([]string{c.Subject.CommonName}, c.DNSNames...) {
		if n = normalizeName(n); n != "" {
			set[n] = true
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	pc := parsedCert{names: names, precert: c.IsPrecertificate()}
	if c.SerialNumber != nil {
		pc.serial = normalizeSerial(c.SerialNumber.Text(16))
	}
	for _, s := range c.SCTList.SCTList {
		var sct ctgo.SignedCertificateTimestamp
		if rest, err := cttls.Unmarshal(s.Val, &sct); err != nil || len(rest) > 0 {
			continue // a malformed SCT is not a reason to drop the certificate
		}
		pc.scts = append(pc.scts, submit.SCT{
			LogID:     append([]byte(nil), sct.LogID.KeyID[:]...),
			Timestamp: msToTime(sct.Timestamp),
		})
	}
	return pc, nil
}

func msToTime(ms uint64) time.Time {
	return time.UnixMilli(int64(ms)).UTC() //nolint:gosec // CT timestamps are milliseconds since the epoch and fit int64
}

// fingerprint is the lowercase hex SHA-256 of a DER certificate: the dedupe
// key (FR-DISC-020).
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Found is a certificate for an owned domain, from one CT source.
type Found struct {
	// Chain is the (pre)certificate as logged, then its issuers, DER.
	Chain       [][]byte
	Fingerprint string
	Serial      string
	Evidence    submit.CTEvidence
}

// newFound builds a Found from a leaf and chain, or returns ok=false when
// the leaf matches no owned domain.
func newFound(domains Domains, leaf []byte, chain [][]byte, ev submit.CTEvidence) (Found, bool, error) {
	pc, err := parseCert(leaf)
	if err != nil {
		return Found{}, false, err
	}
	d := domains.MatchAny(pc.names)
	if d == "" {
		return Found{}, false, nil
	}
	ev.MatchedDomain = d
	ev.DNSNames = pc.names
	if ev.EntryType == "" {
		ev.EntryType = submit.EntryX509
		if pc.precert {
			ev.EntryType = submit.EntryPrecert
		}
	}
	if len(pc.scts) > 0 {
		ev.SCTs = pc.scts
	}
	full := make([][]byte, 0, 1+len(chain))
	full = append(full, leaf)
	full = append(full, chain...)
	if len(full) > 20 { // served_chain maxItems
		full = full[:20]
	}
	return Found{Chain: full, Fingerprint: fingerprint(leaf), Serial: pc.serial, Evidence: ev}, true, nil
}

// Observation turns a Found into an observation with method ct and the log
// entry as evidence.
func (f Found) Observation(observedAt time.Time) submit.Observation {
	ev := f.Evidence
	return submit.Observation{
		Target: submit.Target{
			Kind:        submit.KindCTEntry,
			Host:        ev.MatchedDomain,
			Fingerprint: f.Fingerprint,
		},
		Method:      submit.MethodCT,
		ObservedAt:  observedAt.UTC(),
		Outcome:     submit.OutcomeCertSeen,
		ServedChain: f.Chain,
		CT:          &ev,
	}
}
