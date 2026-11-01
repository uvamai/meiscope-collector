// Package scope verifies the scan scopes the core sends to the collector.
//
// A scope says what may be probed (hosts, CIDRs, ports), how (the
// ScanPolicy: rates, windows, deny-list, canary) and who authorised it. The
// core signs it with its Ed25519 job-signing key; the collector refuses any
// scope that is unsigned, signed by another key, expired, not yet valid, or
// missing its authorisation record (security-architecture.md §5,
// design-review finding 6). Nothing in a scope is trusted before Verify.
package scope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Verification errors.
var (
	ErrUnsigned     = errors.New("scope: no signature")
	ErrBadSignature = errors.New("scope: signature does not verify with the core's key")
	ErrExpired      = errors.New("scope: expired")
	ErrNotYetValid  = errors.New("scope: not yet valid")
	ErrInvalid      = errors.New("scope: invalid")
	ErrUnknownKey   = errors.New("scope: signed with a key that is not pinned")
)

// Signed is a scope as it travels: the exact payload bytes the core signed,
// and the signature over them. Verifying the bytes received (not a
// re-encoding) means no JSON canonicalisation is needed on either side.
type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
	KeyID     string          `json:"key_id,omitempty"`
}

// Scope is what the core authorised.
type Scope struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// Version increases every time the core changes the scope; the
	// collector refuses an older or replayed version (Tracker).
	Version       int64         `json:"version"`
	Hosts         []string      `json:"hosts"`
	CIDRs         []string      `json:"cidrs"`
	Ports         []int         `json:"ports"`
	Policy        ScanPolicy    `json:"scan_policy"`
	Authorisation Authorisation `json:"authorisation"`
	NotBefore     time.Time     `json:"not_before"`
	NotAfter      time.Time     `json:"not_after"`
	// RescanIntervalSeconds is how often the whole scope is scanned again;
	// 0 means DefaultRescanInterval.
	RescanIntervalSeconds int `json:"rescan_interval_seconds,omitempty"`
	// NamesByIP lists, per address inside CIDRs, the host names known for it
	// (from the scope, CT and the CMDB). Each name is probed as its own SNI.
	NamesByIP map[string][]string `json:"names_by_ip,omitempty"`
}

// Authorisation records who allowed the scan (printed on every report).
type Authorisation struct {
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	Document string    `json:"document"`
}

// ScanPolicy is the scope's rate and safety settings.
type ScanPolicy struct {
	// Deny lists hosts (exact names or DNS suffixes) and CIDRs never probed,
	// even when Hosts or CIDRs include them.
	Deny []string `json:"deny"`
	// RatePer24 is new connections per second to any one /24 (IPv4) or /64
	// (IPv6).
	RatePer24 float64 `json:"rate_per_24"`
	// Burst is the token-bucket burst per /24; at least 1.
	Burst int `json:"burst"`
	// ConnectTimeoutSeconds bounds each connection attempt.
	ConnectTimeoutSeconds int `json:"connect_timeout_seconds"`
	// Windows are the UTC times scanning may run; empty means any time.
	Windows []Window `json:"windows"`
	// CanaryPercent of targets run first on a new scope (default 1); the rest
	// wait until the canary finishes cleanly.
	CanaryPercent float64 `json:"canary_percent"`
	// DryRun lists the targets without connecting to any of them.
	DryRun bool `json:"dry_run"`
}

// Window is a daily UTC time range [Start, End), "HH:MM". End before Start
// wraps past midnight.
type Window struct {
	Days  []time.Weekday `json:"days"` // empty means every day
	Start string         `json:"start"`
	End   string         `json:"end"`
}

// Limits the collector enforces whatever a scope asks for.
const (
	MaxRatePer24          = 10.0
	MaxBurst              = 10
	MaxConnectTimeout     = 15
	DefaultConnectTimeout = 5
	DefaultCanaryPercent  = 1.0
	MaxTargets            = 1 << 20
	MinRescanInterval     = 60
	MaxRescanInterval     = 7 * 24 * 3600
	DefaultRescanInterval = 24 * 3600
	MaxNamesPerIP         = 64
	MaxActiveKeys         = 2
)

// Verify checks sig against the core's public key and validity at now, then
// decodes and validates the scope. Only a scope returned by Verify may be run.
func Verify(s Signed, coreKey ed25519.PublicKey, now time.Time) (*Scope, error) {
	if len(s.Signature) == 0 || len(s.Payload) == 0 {
		return nil, ErrUnsigned
	}
	if len(coreKey) != ed25519.PublicKeySize || !ed25519.Verify(coreKey, s.Payload, s.Signature) {
		return nil, ErrBadSignature
	}
	var sc Scope
	dec := json.NewDecoder(bytes.NewReader(s.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if now.Before(sc.NotBefore) {
		return nil, ErrNotYetValid
	}
	if !now.Before(sc.NotAfter) {
		return nil, ErrExpired
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	return &sc, nil
}

func (sc *Scope) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
	}
	if sc.ID == "" || sc.TenantID == "" {
		return bad("id and tenant_id are required")
	}
	if sc.Version < 1 {
		return bad("version must be at least 1")
	}
	switch {
	case sc.RescanIntervalSeconds == 0:
		sc.RescanIntervalSeconds = DefaultRescanInterval
	case sc.RescanIntervalSeconds < MinRescanInterval || sc.RescanIntervalSeconds > MaxRescanInterval:
		return bad("rescan_interval_seconds must be %d..%d", MinRescanInterval, MaxRescanInterval)
	}
	if strings.TrimSpace(sc.Authorisation.By) == "" || sc.Authorisation.At.IsZero() || strings.TrimSpace(sc.Authorisation.Document) == "" {
		return bad("authorisation (by, at, document) is required")
	}
	if len(sc.Hosts) == 0 && len(sc.CIDRs) == 0 {
		return bad("no hosts or cidrs")
	}
	if len(sc.Ports) == 0 {
		return bad("no ports")
	}
	for _, p := range sc.Ports {
		if p < 1 || p > 65535 {
			return bad("port %d out of range", p)
		}
	}
	var prefixes []netip.Prefix
	for _, c := range sc.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return bad("cidr %q: %v", c, err)
		}
		prefixes = append(prefixes, p)
	}
	domains := scopeDomains(sc.Hosts)
	for ip, names := range sc.NamesByIP {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return bad("names_by_ip key %q is not an IP address", ip)
		}
		if !containsAddr(prefixes, a) {
			return bad("names_by_ip address %s is outside the scope's cidrs", a)
		}
		if len(names) == 0 || len(names) > MaxNamesPerIP {
			return bad("names_by_ip %s: 1..%d names", a, MaxNamesPerIP)
		}
		for _, n := range names {
			if !validName(n) {
				return bad("names_by_ip %s: invalid name %q (wildcards and IP literals are refused)", a, n)
			}
			if len(domains) > 0 && !underDomains(strings.ToLower(n), domains) {
				return bad("names_by_ip %s: %q is outside the scope's domains", a, n)
			}
		}
	}
	p := &sc.Policy
	if p.RatePer24 <= 0 || p.RatePer24 > MaxRatePer24 {
		return bad("rate_per_24 must be in (0, %v]", MaxRatePer24)
	}
	if p.Burst < 1 || p.Burst > MaxBurst {
		return bad("burst must be 1..%d", MaxBurst)
	}
	switch {
	case p.ConnectTimeoutSeconds == 0:
		p.ConnectTimeoutSeconds = DefaultConnectTimeout
	case p.ConnectTimeoutSeconds < 1 || p.ConnectTimeoutSeconds > MaxConnectTimeout:
		return bad("connect_timeout_seconds must be 1..%d", MaxConnectTimeout)
	}
	if p.CanaryPercent == 0 {
		p.CanaryPercent = DefaultCanaryPercent
	}
	if p.CanaryPercent < 0 || p.CanaryPercent > 100 {
		return bad("canary_percent must be 0..100")
	}
	for _, w := range p.Windows {
		if _, err := parseHHMM(w.Start); err != nil {
			return bad("window start %q", w.Start)
		}
		if _, err := parseHHMM(w.End); err != nil {
			return bad("window end %q", w.End)
		}
	}
	return nil
}

// InWindow reports whether t falls in one of the windows (true when there
// are none).
func (p ScanPolicy) InWindow(t time.Time) bool {
	if len(p.Windows) == 0 {
		return true
	}
	t = t.UTC()
	mins := t.Hour()*60 + t.Minute()
	for _, w := range p.Windows {
		start, _ := parseHHMM(w.Start)
		end, _ := parseHHMM(w.End)
		day := t.Weekday()
		inRange := false
		switch {
		case start < end:
			inRange = mins >= start && mins < end
		case start > end: // wraps midnight: the part after midnight belongs to the previous day
			if mins >= start {
				inRange = true
			} else if mins < end {
				inRange = true
				day = (day + 6) % 7
			}
		}
		if inRange && (len(w.Days) == 0 || containsDay(w.Days, day)) {
			return true
		}
	}
	return false
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// scopeDomains returns the scope's host names (lower case); IP literals in
// Hosts are addresses, not domains, and are left out.
func scopeDomains(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if _, err := netip.ParseAddr(h); err != nil && h != "" {
			out = append(out, h)
		}
	}
	return out
}

// underDomains reports whether n equals one of domains or is below one.
func underDomains(n string, domains []string) bool {
	for _, d := range domains {
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
}

// validName accepts a DNS name: labels of letters, digits, '-' and '_',
// 1..63 bytes each, 253 bytes in all. Wildcards and IP literals are refused,
// so SNI expansion can only ever name a host, never redirect the probe.
func validName(n string) bool {
	if n == "" || len(n) > 253 || strings.HasSuffix(n, ".") {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, r := range l {
			if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
	}
	return true
}

func containsDay(ds []time.Weekday, d time.Weekday) bool {
	for _, x := range ds {
		if x == d {
			return true
		}
	}
	return false
}

func parseHHMM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("time %q: %w", s, err)
	}
	return t.Hour()*60 + t.Minute(), nil
}
