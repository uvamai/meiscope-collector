package clock

import (
	"context"
	"testing"
	"time"
)

func TestFake(t *testing.T) {
	start := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	f := NewFake(start)
	_ = f.Sleep(context.Background(), 0)
	_ = f.Sleep(context.Background(), 5*time.Second)
	f.Advance(time.Second)
	if !f.Now().Equal(start.Add(6*time.Second)) || len(f.Sleeps()) != 1 {
		t.Fatalf("now %v sleeps %v", f.Now(), f.Sleeps())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.Sleep(ctx, time.Second) == nil || (System{}).Sleep(ctx, time.Hour) == nil {
		t.Fatal("Sleep must return the context error")
	}
}

func TestManual(t *testing.T) {
	start := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	m := NewManual(start)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	woke := make(chan time.Time, 1)
	go func() {
		if err := m.Sleep(ctx, time.Minute); err == nil {
			woke <- m.Now()
		}
	}()
	if err := m.WaitSleepers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	m.Advance(59 * time.Second)
	if m.Sleepers() != 1 {
		t.Fatal("woke before its time")
	}
	m.Advance(time.Second)
	select {
	case at := <-woke:
		if !at.Equal(start.Add(time.Minute)) {
			t.Fatalf("woke at %v", at)
		}
	case <-ctx.Done():
		t.Fatal("did not wake")
	}

	// A cancelled sleep returns the context error and stops counting.
	sctx, scancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- m.Sleep(sctx, time.Hour) }()
	if err := m.WaitSleepers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	scancel()
	if err := <-done; err == nil || m.Sleepers() != 0 {
		t.Fatalf("err %v, sleepers %d", err, m.Sleepers())
	}
	if m.Sleep(ctx, 0) != nil {
		t.Fatal("a zero sleep returns at once")
	}
}
