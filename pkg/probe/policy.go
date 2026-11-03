package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Probe budget limits (per process, over a rolling minute).
const (
	DefaultProbesPerMinute = 30
	MaxProbesPerMinute     = 120
	budgetWindow           = time.Minute
)

// Policy errors. Both are refusals made before any packet is sent.
var (
	ErrBudgetExhausted = errors.New("probe budget exhausted")
	ErrNotAllowed      = errors.New("target refused: outside the allow list")
)

// Budget caps how many probes the process may start per rolling minute. It
// bounds what a prompt-injected agent can do with the probe tool even when
// every individual call is allowed.
type Budget struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	start []time.Time // start times inside the window, oldest first
}

// NewBudget returns a budget of perMinute probes; 1..MaxProbesPerMinute.
func NewBudget(perMinute int, now func() time.Time) (*Budget, error) {
	if perMinute < 1 || perMinute > MaxProbesPerMinute {
		return nil, fmt.Errorf("probes per minute must be between 1 and %d, got %d", MaxProbesPerMinute, perMinute)
	}
	if now == nil {
		now = time.Now
	}
	return &Budget{max: perMinute, now: now}, nil
}

// Take reserves one probe, or fails without reserving when the window is full.
func (b *Budget) Take() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	cut := 0
	for cut < len(b.start) && now.Sub(b.start[cut]) >= budgetWindow {
		cut++
	}
	b.start = b.start[cut:]
	if len(b.start) >= b.max {
		wait := budgetWindow - now.Sub(b.start[0])
		return fmt.Errorf("%w: %d probes per minute allowed; next probe possible in %d s",
			ErrBudgetExhausted, b.max, int(wait.Seconds())+1)
	}
	b.start = append(b.start, now)
	return nil
}

// Allow is an optional allow list of DNS suffixes and CIDRs (meiscope-mcp:
// MEISCOPE_MCP_ALLOW; the collector: the signed scope).
//
//   - A host name is allowed before resolution only if it equals a suffix or
//     ends with "." + suffix. An IP literal is allowed only if a CIDR (or a
//     bare IP entry) contains it.
//   - At dial time, when the list contains any CIDR, the address being dialled
//     must be inside one, whatever name was given; with a suffix-only list the
//     dial must go to the address that was vetted for the name.
//   - The link-local and cloud metadata block applies before and regardless of
//     this list.
type Allow struct {
	suffixes []string
	prefixes []netip.Prefix
}

// ParseAllow parses a comma-separated list. An empty string means no list.
func ParseAllow(s string) (*Allow, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil //nolint:nilnil // nil list means "no allow list configured"
	}
	a := &Allow{}
	for _, raw := range strings.Split(s, ",") {
		e := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case e == "":
			continue
		case strings.Contains(e, "/"):
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("allow list entry %q: %w", raw, err)
			}
			a.prefixes = append(a.prefixes, p.Masked())
		default:
			if ip, err := netip.ParseAddr(e); err == nil {
				a.prefixes = append(a.prefixes, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
				continue
			}
			e = strings.TrimPrefix(strings.TrimSuffix(e, "."), ".")
			if e == "" || strings.ContainsAny(e, "*/ \t") {
				return nil, fmt.Errorf("allow list entry %q: give a DNS suffix such as example.internal or a CIDR", raw)
			}
			a.suffixes = append(a.suffixes, e)
		}
	}
	if len(a.suffixes) == 0 && len(a.prefixes) == 0 {
		return nil, errors.New("allow list is set but has no entries")
	}
	return a, nil
}

// String lists the entries for diagnostics.
func (a *Allow) String() string {
	parts := append([]string(nil), a.suffixes...)
	for _, p := range a.prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// allowsHost is the check before resolution. host is already normalised.
func (a *Allow) allowsHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return a.inPrefixes(ip)
	}
	for _, s := range a.suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// allowsDial is the check at connect time.
func (a *Allow) allowsDial(dialled, vetted netip.Addr) bool {
	if len(a.prefixes) > 0 {
		return a.inPrefixes(dialled)
	}
	return dialled == vetted
}

func (a *Allow) inPrefixes(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// NewAllow builds an allow list from DNS suffixes and prefixes (for example
// a signed scan scope's hosts and CIDRs), with the rules of ParseAllow.
func NewAllow(suffixes []string, prefixes []netip.Prefix) (*Allow, error) {
	a := &Allow{}
	for _, s := range suffixes {
		e := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(s), "."), "."))
		if e == "" || strings.ContainsAny(e, "*/ \t,") {
			return nil, fmt.Errorf("allow list entry %q: give a DNS suffix such as example.internal", s)
		}
		a.suffixes = append(a.suffixes, e)
	}
	for _, p := range prefixes {
		if !p.IsValid() {
			return nil, errors.New("allow list entry: invalid prefix")
		}
		bits := p.Bits()
		if p.Addr().Is4In6() { // ::ffff:a.b.c.d/n covers a.b.c.d/(n-96)
			bits = max(bits-96, 0)
		}
		a.prefixes = append(a.prefixes, netip.PrefixFrom(p.Addr().Unmap(), bits).Masked())
	}
	if len(a.suffixes) == 0 && len(a.prefixes) == 0 {
		return nil, errors.New("allow list has no entries")
	}
	return a, nil
}
