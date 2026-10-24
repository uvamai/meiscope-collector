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
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id"`
	Hosts         []string      `json:"hosts"`
	CIDRs         []string      `json:"cidrs"`
	Ports         []int         `json:"ports"`
	Policy        ScanPolicy    `json:"scan_policy"`
	Authorisation Authorisation `json:"authorisation"`
	NotBefore     time.Time     `json:"not_before"`
	NotAfter      time.Time     `json:"not_after"`
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
	bad := func(format string, a ...any) error { return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...) }
	if sc.ID == "" || sc.TenantID == "" {
		return bad("id and tenant_id are required")
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
	for _, c := range sc.CIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			return bad("cidr %q: %v", c, err)
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
