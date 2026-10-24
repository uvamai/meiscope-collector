package ct

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

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
	precert bool
}

// parseCert parses a certificate or precertificate leniently (CT holds
// certificates that crypto/x509 rejects; design review finding 25) and
// returns its DNS names (SAN dNSName and CN) and serial.
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

// CT sources, as the poller names them in its statistics and logs.
const (
	SourceCertSpotter = "certspotter"
	SourceRFC6962     = "rfc6962"
	SourceStaticCT    = "static_ct"
	SourceCrtSh       = "crtsh"
)

// Entry types of a log entry.
const (
	EntryX509    = "x509_entry"
	EntryPrecert = "precert_entry"
)

// Evidence is where a certificate was found. Only Source, Endpoint and the
// log fields (LogID, EntryIndex, Timestamp) reach the core; the rest serves
// the poller's own bookkeeping (dedupe, coverage, logs).
type Evidence struct {
	// Source is one of the Source* constants.
	Source string
	// Endpoint is the URL of the log (RFC 6962 base, static-ct monitoring
	// prefix) or search service that was read.
	Endpoint      string
	MatchedDomain string
	DNSNames      []string
	EntryType     string
	// LogID (32 bytes), EntryIndex and Timestamp (the SCT timestamp) are set
	// for entries read from a log; LogID only when the log's key is known.
	LogID      []byte
	EntryIndex *int64
	Timestamp  *time.Time
	// SourceID is the record id at a search service (Cert Spotter issuance
	// id, crt.sh certificate id).
	SourceID string
}

// wireSource maps a poller source to CTEntry.source.
func wireSource(source string) string {
	switch source {
	case SourceCertSpotter:
		return submit.CTSourceCertSpotter
	case SourceCrtSh:
		return submit.CTSourceCrtSh
	}
	return submit.CTSourceLog // SourceRFC6962, SourceStaticCT
}

// endpointTarget is the ct_log target of a log or service URL: its host and
// port (the default port of the scheme when the URL names none).
func endpointTarget(endpoint string) submit.Target {
	t := submit.Target{Kind: submit.KindCTLog}
	u, err := url.Parse(endpoint)
	if err != nil {
		return t
	}
	t.Host = u.Hostname()
	switch p, err := strconv.Atoi(u.Port()); {
	case err == nil:
		t.Port = p
	case u.Scheme == "https":
		t.Port = 443
	case u.Scheme == "http":
		t.Port = 80
	}
	return t
}

// Found is a certificate for an owned domain, from one CT source.
type Found struct {
	// Chain is the (pre)certificate as logged, then its issuers, DER.
	Chain       [][]byte
	Fingerprint string
	Serial      string
	Evidence    Evidence
}

// newFound builds a Found from a leaf and chain, or returns ok=false when
// the leaf matches no owned domain.
func newFound(domains Domains, leaf []byte, chain [][]byte, ev Evidence) (Found, bool, error) {
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
		ev.EntryType = EntryX509
		if pc.precert {
			ev.EntryType = EntryPrecert
		}
	}
	full := make([][]byte, 0, 1+len(chain))
	full = append(full, leaf)
	full = append(full, chain...)
	if len(full) > 20 { // served_chain maxItems
		full = full[:20]
	}
	return Found{Chain: full, Fingerprint: fingerprint(leaf), Serial: pc.serial, Evidence: ev}, true, nil
}

// Observation turns a Found into an observation with method ct: the target
// is the log or service that was read (kind ct_log), served_chain has the
// logged (pre)certificate first, and ct_entry says where it was found.
func (f Found) Observation(observedAt time.Time) submit.Observation {
	ev := f.Evidence
	entry := &submit.CTEntry{Source: wireSource(ev.Source), EntryIndex: ev.EntryIndex, Timestamp: ev.Timestamp}
	if len(ev.LogID) == sha256.Size {
		entry.LogID = ev.LogID
	}
	return submit.Observation{
		Target:      endpointTarget(ev.Endpoint),
		Method:      submit.MethodCT,
		ObservedAt:  observedAt.UTC(),
		Outcome:     submit.OutcomeCertSeen,
		ServedChain: f.Chain,
		CTEntry:     entry,
	}
}
