package runner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/scope"
)

// Pacing errors: the attempt was not made.
var (
	ErrPaused       = errors.New("runner: paused")
	ErrOutsideScope = errors.New("runner: address is on the scope's deny list")
	ErrOutsideTime  = errors.New("runner: outside the scope's scan window")
)

// maxBackoffShift caps the back-off at 32 times the base interval.
const maxBackoffShift = 5

// pacer spaces connection starts per /24 (IPv4) or /64 (IPv6): a token
// bucket of RatePer24 per second with Burst, slowed by back-off while a
// network keeps timing out. It is the probe's Pace hook, so it runs after
// every probe policy check and immediately before each dial.
type pacer struct {
	clk    clock.Clock
	policy scope.ScanPolicy
	deny   deny
	paused func() bool

	mu   sync.Mutex
	nets map[netip.Prefix]*netState
}

type netState struct {
	tat      time.Time // GCRA theoretical arrival time
	failures int       // consecutive timeouts in this network
}

func newPacer(clk clock.Clock, policy scope.ScanPolicy, paused func() bool) *pacer {
	return &pacer{clk: clk, policy: policy, deny: parseDeny(policy.Deny), paused: paused, nets: map[netip.Prefix]*netState{}}
}

// NetworkOf is the rate-limit key of a: its /24 or /64.
func NetworkOf(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// wait blocks until a connection to a may start, or refuses it.
func (p *pacer) wait(ctx context.Context, a netip.Addr) error {
	if p.deny.addr(a) {
		return ErrOutsideScope // a listed name resolved into a denied network
	}
	if err := p.check(); err != nil {
		return err
	}
	d, booked := p.reserve(a)
	if err := p.clk.Sleep(ctx, d); err != nil {
		p.release(a, booked)
		return err
	}
	if err := p.check(); err != nil { // a pause or the window may have closed while waiting
		p.release(a, booked)
		return err
	}
	return nil
}

func (p *pacer) check() error {
	if p.paused() {
		return ErrPaused
	}
	if !p.policy.InWindow(p.clk.Now()) {
		return ErrOutsideTime
	}
	return nil
}

// reserve books the next start in a's network and returns how long to wait
// for it (GCRA: at most Burst starts at once, then one per interval), and
// the booking, for release.
func (p *pacer) reserve(a netip.Addr) (time.Duration, booking) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := NetworkOf(a)
	st := p.nets[k]
	if st == nil {
		st = &netState{}
		p.nets[k] = st
	}
	iv := time.Duration(float64(time.Second) / p.policy.RatePer24)
	iv <<= min(st.failures, maxBackoffShift)
	now := p.clk.Now()
	if st.tat.Before(now) {
		st.tat = now
	}
	st.tat = st.tat.Add(iv)
	wait := st.tat.Sub(now) - time.Duration(p.policy.Burst)*iv
	return max(wait, 0), booking{tat: st.tat, iv: iv}
}

// booking is one reservation: the arrival time it set and its interval.
type booking struct {
	tat time.Time
	iv  time.Duration
}

// release gives back a reservation whose connection never started (the
// wait was cancelled, or a pause or the window closed meanwhile), so the
// next target in the network does not wait for an unused slot (S-25). Only
// the latest booking is given back: rewinding past a later booking would
// let two starts share a slot and exceed the rate.
func (p *pacer) release(a netip.Addr, b booking) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.nets[NetworkOf(a)]; st != nil && st.tat.Equal(b.tat) {
		st.tat = st.tat.Add(-b.iv)
	}
}

// record feeds an attempt's outcome back: timeouts back off the network,
// anything else that answered resets it.
func (p *pacer) record(a netip.Addr, timedOut bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.nets[NetworkOf(a)]
	if st == nil {
		return
	}
	if timedOut {
		st.failures++
	} else {
		st.failures = 0
	}
}
