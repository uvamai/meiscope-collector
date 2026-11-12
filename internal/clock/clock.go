// Package clock abstracts time so that rate limits and back-off can be tested
// with a fake clock (engineering-standards.md section 2: inject a clock).
package clock

import (
	"context"
	"sync"
	"time"
)

// Clock tells the time and waits.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx ends, whichever is first; it returns
	// ctx.Err() when ctx ended first.
	Sleep(ctx context.Context, d time.Duration) error
}

// System is the real clock.
type System struct{}

// Now returns the current time.
func (System) Now() time.Time { return time.Now() }

// Sleep waits for d or until ctx ends.
func (System) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Fake is a clock for tests: Sleep returns at once, advances the time by d
// and records d.
type Fake struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

// NewFake returns a fake clock set to start.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Sleep advances the fake time by d and records d (only when d > 0).
func (f *Fake) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	f.sleeps = append(f.sleeps, d)
	return nil
}

// Advance moves the fake time forward without recording a sleep.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Sleeps returns a copy of the recorded sleeps.
func (f *Fake) Sleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.sleeps...)
}

// Manual is a clock for tests of long-running loops: Sleep blocks until
// Advance moves the time to or past the end of the sleep, or until ctx ends.
// WaitSleepers lets a test wait until its goroutines are all asleep before
// it advances the time, so no real sleeping is needed.
type Manual struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*waiter
	changed chan struct{} // closed and replaced whenever waiters changes
}

type waiter struct {
	until time.Time
	ch    chan struct{}
}

// NewManual returns a manual clock set to start.
func NewManual(start time.Time) *Manual {
	return &Manual{now: start, changed: make(chan struct{})}
}

// Now returns the manual time.
func (m *Manual) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

// notify wakes WaitSleepers; m.mu must be held.
func (m *Manual) notify() {
	close(m.changed)
	m.changed = make(chan struct{})
}

// Sleep blocks until the time reaches now+d or ctx ends.
func (m *Manual) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	m.mu.Lock()
	w := &waiter{until: m.now.Add(d), ch: make(chan struct{})}
	m.waiters = append(m.waiters, w)
	m.notify()
	m.mu.Unlock()
	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		m.mu.Lock()
		for i, x := range m.waiters {
			if x == w {
				m.waiters = append(m.waiters[:i], m.waiters[i+1:]...)
				m.notify()
				break
			}
		}
		m.mu.Unlock()
		return ctx.Err()
	}
}

// Advance moves the time forward by d and wakes every sleep that has ended.
func (m *Manual) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
	kept := m.waiters[:0]
	for _, w := range m.waiters {
		if m.now.Before(w.until) {
			kept = append(kept, w)
			continue
		}
		close(w.ch)
	}
	if len(kept) != len(m.waiters) {
		m.waiters = kept
		m.notify()
	}
}

// Sleepers returns how many goroutines are sleeping.
func (m *Manual) Sleepers() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.waiters)
}

// WaitSleepers blocks until at least n goroutines are sleeping, or ctx ends.
func (m *Manual) WaitSleepers(ctx context.Context, n int) error {
	for {
		m.mu.Lock()
		if len(m.waiters) >= n {
			m.mu.Unlock()
			return nil
		}
		ch := m.changed
		m.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
