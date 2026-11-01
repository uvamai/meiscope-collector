package probe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBudgetRollingWindow(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	b, err := NewBudget(3, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := b.Take(); err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		clk.advance(10 * time.Second)
	}
	err = b.Take()
	if !errors.Is(err, ErrBudgetExhausted) || !strings.Contains(err.Error(), "next probe possible in 31 s") {
		t.Fatalf("4th take: %v", err)
	}
	clk.advance(30 * time.Second) // the first probe is now exactly a minute old
	if err := b.Take(); err != nil {
		t.Fatalf("after the window rolled: %v", err)
	}
	if err := b.Take(); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("window full again: %v", err)
	}
	for _, n := range []int{0, -1, MaxProbesPerMinute + 1} {
		if _, err := NewBudget(n, nil); err == nil {
			t.Errorf("NewBudget(%d) accepted", n)
		}
	}
	if _, err := NewBudget(MaxProbesPerMinute, nil); err != nil {
		t.Errorf("hard maximum refused: %v", err)
	}
}

// TestProbeBudgetRefusesWithoutDialling: the 31st probe in a minute fails
// before any connection is attempted.
func TestProbeBudgetRefusesWithoutDialling(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), nil)
	clk := &fakeClock{t: now}
	budget, err := NewBudget(DefaultProbesPerMinute, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	pr := New(Options{Roots: p.roots, Now: clk.now, Budget: budget})
	target := Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test"}
	for i := 0; i < DefaultProbesPerMinute; i++ {
		if _, err := pr.Probe(context.Background(), target); err != nil {
			t.Fatalf("probe %d: %v", i+1, err)
		}
	}
	before := srv.conns.Load()
	if _, err := pr.Probe(context.Background(), target); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("probe 31: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if after := srv.conns.Load(); after != before {
		t.Fatalf("refused probe still connected (%d -> %d connections)", before, after)
	}
	if int(before) != DefaultProbesPerMinute {
		t.Fatalf("server saw %d connections, want %d", before, DefaultProbesPerMinute)
	}
}

func TestParseAllow(t *testing.T) {
	a, err := ParseAllow(" Example.Internal. , .corp.example,10.0.0.0/8, 192.168.1.7 ,2001:db8::/32,")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.String(); got != "example.internal,corp.example,10.0.0.0/8,192.168.1.7/32,2001:db8::/32" {
		t.Fatalf("parsed %q", got)
	}
	if a, err := ParseAllow("  "); a != nil || err != nil {
		t.Fatalf("empty list: %v %v", a, err)
	}
	for _, bad := range []string{"*.example.com", "10.0.0.0/33", ",,", "a b.example"} {
		if _, err := ParseAllow(bad); err == nil {
			t.Errorf("ParseAllow(%q) accepted", bad)
		}
	}
}

func TestAllowHostMatching(t *testing.T) {
	a, err := ParseAllow("example.internal,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"example.internal":                true,
		"app.example.internal":            true,
		"a.b.example.internal":            true,
		"evil-example.internal":           false, // not on a label boundary
		"example.internal.attacker.test":  false, // suffix appended to another domain
		"attacker.test":                   false,
		"10.1.2.3":                        true,
		"11.1.2.3":                        false,
		"::ffff:10.1.2.3":                 true, // IPv4-mapped form of an allowed address
		"internal":                        false,
		"xexample.internal":               false,
		"example.internal.":               false, // normalised away before matching; raw form never matches
		"sub.example.internal.evil.local": false,
	} {
		if got := a.allowsHost(host); got != want {
			t.Errorf("allowsHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// countingResolver answers with a different list on each call, the way a
// DNS-rebinding attacker would.
type countingResolver struct {
	answers [][]netip.Addr
	calls   atomic.Int32
}

func (r *countingResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	i := int(r.calls.Add(1)) - 1
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	return r.answers[i], nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestAllowListOnProbe(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), nil)
	port := srv.port()
	probe := func(t *testing.T, allow string, res Resolver, host string) error {
		t.Helper()
		a, err := ParseAllow(allow)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(Options{Roots: p.roots, Now: func() time.Time { return now }, Resolver: res, Allow: a}).
			Probe(context.Background(), Target{Host: host, Port: port, SNI: "www.example.test", Timeout: 2 * time.Second})
		return err
	}
	loopback := &countingResolver{answers: [][]netip.Addr{addrs("127.0.0.1")}}

	t.Run("hit by suffix", func(t *testing.T) {
		if err := probe(t, "example.internal", loopback, "app.example.internal"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("hit by CIDR", func(t *testing.T) {
		if err := probe(t, "127.0.0.0/8", nil, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("miss is refused before resolution", func(t *testing.T) {
		r := &countingResolver{answers: [][]netip.Addr{addrs("127.0.0.1")}}
		err := probe(t, "example.internal", r, "other.test")
		if !errors.Is(err, ErrNotAllowed) || r.calls.Load() != 0 {
			t.Fatalf("err %v, resolver calls %d (want refusal and 0 calls)", err, r.calls.Load())
		}
	})
	t.Run("IP literal outside the CIDRs", func(t *testing.T) {
		if err := probe(t, "10.0.0.0/8", nil, "127.0.0.1"); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("allowed name resolving outside the CIDRs", func(t *testing.T) {
		r := &countingResolver{answers: [][]netip.Addr{addrs("127.0.0.1")}}
		if err := probe(t, "example.internal,10.0.0.0/8", r, "app.example.internal"); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("DNS rebinding: resolved once, dial pinned to the vetted address", func(t *testing.T) {
		// First answer is allowed; later answers would point elsewhere.
		r := &countingResolver{answers: [][]netip.Addr{addrs("127.0.0.1"), addrs("192.0.2.66"), addrs("169.254.169.254")}}
		before := srv.conns.Load()
		if err := probe(t, "example.internal,127.0.0.0/8", r, "rebind.example.internal"); err != nil {
			t.Fatal(err)
		}
		if r.calls.Load() != 1 {
			t.Fatalf("resolver called %d times; a second lookup could be rebound", r.calls.Load())
		}
		if srv.conns.Load() != before+1 {
			t.Fatal("the vetted loopback address was not the one dialled")
		}
	})
	t.Run("DNS rebinding: one allowed and one metadata answer", func(t *testing.T) {
		r := &countingResolver{answers: [][]netip.Addr{addrs("127.0.0.1", "169.254.169.254")}}
		if err := probe(t, "example.internal,0.0.0.0/0", r, "mixed.example.internal"); !errors.Is(err, ErrForbiddenTarget) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("metadata block wins over the allow list", func(t *testing.T) {
		if err := probe(t, "169.254.0.0/16", nil, "169.254.169.254"); !errors.Is(err, ErrForbiddenTarget) {
			t.Fatalf("by address: %v", err)
		}
		if err := probe(t, "metadata.google.internal,google.internal", nil, "metadata.google.internal"); !errors.Is(err, ErrForbiddenTarget) {
			t.Fatalf("by name: %v", err)
		}
		r := &countingResolver{answers: [][]netip.Addr{addrs("169.254.169.254")}}
		if err := probe(t, "example.internal", r, "imds.example.internal"); !errors.Is(err, ErrForbiddenTarget) {
			t.Fatalf("allowed name resolving to metadata: %v", err)
		}
	})
	t.Run("allow-list refusals do not spend the budget", func(t *testing.T) {
		b, err := NewBudget(1, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		a, _ := ParseAllow("example.internal")
		pr := New(Options{Roots: p.roots, Now: func() time.Time { return now }, Resolver: loopback, Budget: b, Allow: a})
		for i := 0; i < 3; i++ {
			if _, err := pr.Probe(context.Background(), Target{Host: "elsewhere.test", Port: port}); !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("err %v", err)
			}
		}
		if _, err := pr.Probe(context.Background(), Target{Host: "app.example.internal", Port: port, SNI: "www.example.test"}); err != nil {
			t.Fatalf("budget was spent by refusals: %v", err)
		}
	})
}

func TestAllowsDialSuffixOnlyPinsVettedAddress(t *testing.T) {
	a, err := ParseAllow("example.internal")
	if err != nil {
		t.Fatal(err)
	}
	v := netip.MustParseAddr("192.0.2.10")
	if !a.allowsDial(v, v) || a.allowsDial(netip.MustParseAddr("192.0.2.11"), v) {
		t.Fatal("suffix-only list must allow exactly the vetted address")
	}
}
