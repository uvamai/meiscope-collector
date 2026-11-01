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
