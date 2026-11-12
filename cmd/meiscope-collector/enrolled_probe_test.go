package main

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/runner"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// fakeRuns replaces the runner: every run reports its start and then holds
// until its context is cancelled, so a test sees exactly which scope
// versions run and which are stopped. It makes no connection.
type fakeRuns struct {
	started   chan string // "id@version"
	cancelled chan string
}

func newFakeRuns() *fakeRuns {
	return &fakeRuns{started: make(chan string, 16), cancelled: make(chan string, 16)}
}

func (f *fakeRuns) run(ctx context.Context, sc *scope.Scope, _ func(submit.Observation)) (runner.Report, error) {
	key := sc.ID + "@" + strconv.FormatInt(sc.Version, 10)
	f.started <- key
	<-ctx.Done()
	f.cancelled <- key
	return runner.Report{}, ctx.Err()
}

func expect(t *testing.T, ch chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", want)
	}
}

func expectNone(t *testing.T, ch chan string) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected %s", got)
	default:
	}
}

// settle waits until no run is in progress.
func settle(t *testing.T, s *probeSchedule) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.status().Running > 0 {
		if time.Now().After(deadline) {
			t.Fatal("runs still in progress")
		}
		runtime.Gosched()
	}
}

func TestEnrolledScheduleRunsExactlyTheHeldScopes(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 0)
	rt := f.runtime(t, platform.Config{})
	runs := newFakeRuns()
	rt.sched.runFn = runs.run
	ctx := context.Background()
	now := clk.Now()
	refresh := func(payloads ...[]byte) {
		t.Helper()
		f.core.SetScopes(payloads...)
		if err := rt.scopes.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing held, nothing runs.
	rt.sched.tick(ctx)
	expectNone(t, runs.started)

	// Two scopes from the core: both run.
	refresh(corePayload(t, "scope-a", 1, now), corePayload(t, "scope-b", 1, now))
	rt.sched.tick(ctx)
	got := map[string]bool{}
	for range 2 {
		got[<-runs.started] = true
	}
	if !got["scope-a@1"] || !got["scope-b@1"] {
		t.Fatalf("started %v", got)
	}
	if st := rt.status().Probing; st.State != "active" || st.Scopes != 2 || st.Running != 2 {
		t.Fatalf("probing status %+v", st)
	}

	// The core stops listing scope-b: its run is cancelled at the next tick
	// and it is not started again.
	refresh(corePayload(t, "scope-a", 1, now))
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-b@1")
	expectNone(t, runs.started)

	// A new version of scope-a replaces the run in progress.
	refresh(corePayload(t, "scope-a", 2, now))
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-a@1")
	settle(t, rt.sched)
	rt.sched.tick(ctx)
	expect(t, runs.started, "scope-a@2")

	// Paused: the runner is paused, so nothing new starts.
	rt.sched.run.Pause()
	if st := rt.sched.status(); st.State != "paused" {
		t.Fatalf("state %s", st.State)
	}
	rt.sched.run.Resume()

	// The collector certificate expires: the run in progress stops at once,
	// and nothing runs again, whatever the core lists.
	rt.expire()
	expect(t, runs.cancelled, "scope-a@2")
	settle(t, rt.sched)
	rt.sched.tick(ctx)
	expectNone(t, runs.started)
	if len(rt.scopes.Signed()) != 0 {
		t.Fatal("the set still lists scopes after expiry")
	}
	if st := rt.status().Probing; st.State != "stopped" || st.Running != 0 {
		t.Fatalf("probing status after expiry %+v", st)
	}
}

func TestEnrolledScheduleExpiredScopeIsNotRun(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 0)
	rt := f.runtime(t, platform.Config{})
	runs := newFakeRuns()
	rt.sched.runFn = runs.run
	ctx := context.Background()
	now := clk.Now()

	f.core.SetScopes(corePayload(t, "scope-a", 1, now))
	if err := rt.scopes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	rt.sched.tick(ctx)
	expect(t, runs.started, "scope-a@1")

	// Past the scope's not_after (90 days): the run is cancelled and the
	// scope is not started again.
	clk.Advance(91 * 24 * time.Hour)
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-a@1")
	settle(t, rt.sched)
	rt.sched.tick(ctx)
	expectNone(t, runs.started)
}
