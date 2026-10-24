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
