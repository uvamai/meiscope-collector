package runner

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// startClock is a fake clock for pacing tests (S-25). Now stays at t0, so
// every reservation's start is t0 plus the wait the pacer asked for, and
// Sleep records that start. Like clock.System, a sleep that would outlast
// the context's real deadline fails with the context's error instead of
// returning early, so a pacing wait inside a probe timeout is caught.
type startClock struct {
	t0     time.Time
	mu     sync.Mutex
	starts []time.Time
}

func (c *startClock) Now() time.Time { return c.t0 }

func (c *startClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && d > time.Until(dl) {
		return context.DeadlineExceeded
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts = append(c.starts, c.t0.Add(max(d, 0)))
	return nil
}

func (c *startClock) sortedStarts() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := slices.Clone(c.starts)
	slices.SortFunc(s, func(a, b time.Time) int { return a.Compare(b) })
	return s
}

// The CAT-01 failure (S-25): 20 endpoints in one /24 at the default policy
// (1 start per second, burst 1, 5 s timeout) with 16 workers. Pacing must
// not run inside the connect timeout: every target is attempted, none is
// "not run", and the connection starts are at least 1 s apart.
func TestPacingOutsideConnectTimeoutOneNetwork(t *testing.T) {
	p := newPKI(t)
	var targets []scope.Target
	for range 20 {
		srv := tlsServer(t, p)
		targets = append(targets, scope.Target{Host: "127.0.0.1", Port: srv.port(), Protocol: scope.ProtocolTLS})
	}
	sc := testScope(targets...)
	sc.Policy.RatePer24, sc.Policy.Burst, sc.Policy.ConnectTimeoutSeconds = 1, 1, 5

	clk := &startClock{t0: time.Date(2026, 11, 14, 5, 18, 10, 0, time.UTC)}
	var s sink
	rep, err := New(Options{Roots: p.roots, Clock: clk, Workers: 16}).Run(context.Background(), sc, s.emit)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Planned != 20 || rep.Attempts != 20 || rep.NotRun != 0 || rep.Outcomes[submit.OutcomeCertSeen] != 20 {
		t.Fatalf("report %+v, want 20 planned, 20 attempted (cert_seen), 0 not run", rep)
	}
	starts := clk.sortedStarts()
	if len(starts) != 20 {
		t.Fatalf("%d paced starts, want 20", len(starts))
	}
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < time.Second {
			t.Fatalf("starts %d and %d are %v apart, want >= 1s", i-1, i, gap)
		}
	}
}

// A wait that ends without a connection gives its slot back, so the next
// target in the network is not delayed by a start that never happened.
func TestPacerReleasesCancelledReservation(t *testing.T) {
	clk := &startClock{t0: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	pc := newPacer(clk, scope.ScanPolicy{RatePer24: 1, Burst: 1}, func() bool { return false })
	a := netip.MustParseAddr("10.10.10.11")

	if err := pc.wait(context.Background(), a); err != nil { // starts at t0
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pc.wait(cancelled, a); !errors.Is(err, context.Canceled) { // would start at t0+1s
		t.Fatalf("cancelled wait: %v", err)
	}
	if err := pc.wait(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	starts := clk.sortedStarts()
	want := []time.Time{clk.t0, clk.t0.Add(time.Second)}
	if !slices.Equal(starts, want) {
		t.Fatalf("starts %v, want %v (the cancelled slot reused)", starts, want)
	}
}

// When the run itself ends during a pacing wait, the waiting targets are
// not run: they are never reported as a network timeout and so never feed
// the pacer's back-off.
func TestPacingCancelIsNotRunNotTimeout(t *testing.T) {
	p := newPKI(t)
	var targets []scope.Target
	for range 6 {
		srv := tlsServer(t, p)
		targets = append(targets, scope.Target{Host: "127.0.0.1", Port: srv.port(), Protocol: scope.ProtocolTLS})
	}
	sc := testScope(targets...)
	sc.Policy.RatePer24, sc.Policy.Burst, sc.Policy.ConnectTimeoutSeconds = 1, 1, 5

	// The run has 3 s left: starts at 0, 1 and 2 s fit; 3, 4 and 5 s do not.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clk := &startClock{t0: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	var s sink
	rep, _ := New(Options{Roots: p.roots, Clock: clk, Workers: 6}).Run(ctx, sc, s.emit)
	if rep.Outcomes[submit.OutcomeTimeout] != 0 {
		t.Fatalf("pacing cancel reported as timeout: %+v", rep)
	}
	if rep.Attempts+rep.NotRun != 6 || rep.NotRun == 0 {
		t.Fatalf("report %+v, want every planned attempt either run or not run, some not run", rep)
	}
	for _, o := range s.obs {
		if o.Outcome == submit.OutcomeTimeout {
			t.Fatalf("timeout observation %+v", o)
		}
	}
}

// Releasing a booking that is no longer the latest gives nothing back: a
// new start must never share a slot with one already booked.
func TestPacerReleaseNeverOverbooks(t *testing.T) {
	clk := &startClock{t0: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	pc := newPacer(clk, scope.ScanPolicy{RatePer24: 1, Burst: 1}, func() bool { return false })
	a := netip.MustParseAddr("10.10.10.11")

	pc.reserve(a)         // starts at t0
	_, b := pc.reserve(a) // t0+1s, cancelled below
	w, _ := pc.reserve(a) // t0+2s, still booked
	pc.release(a, b)
	next, _ := pc.reserve(a)
	if w != 2*time.Second || next != 3*time.Second {
		t.Fatalf("waits %v then %v, want 2s then 3s (no shared slot)", w, next)
	}
}
