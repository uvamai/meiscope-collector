package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/runner"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// fakeRuns replaces the runner: every run reports its start and then holds
// until its context ends, so a test sees exactly which scope versions run
// and which are stopped. It makes no connection.
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

// running is the number of runs the schedule has started and not yet
// finished. start is synchronous inside tick, so right after a tick it
// counts every run that tick started.
func running(s *probeSchedule) int { return s.status().Running }

// settle waits until no run is in progress.
func settle(t *testing.T, s *probeSchedule) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for running(s) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("runs still in progress")
		}
		runtime.Gosched()
	}
}

// tickUntil ticks until the run want has started. A replacement may start in
// the same tick that cancelled its predecessor (the cancelled run can finish
// between prune and start), or only at a later tick: both are correct, so the
// test does not assume either.
func tickUntil(ctx context.Context, t *testing.T, s *probeSchedule, ch chan string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case got := <-ch:
			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
			return
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", want)
		}
		s.tick(ctx)
	}
}

func wantRunning(t *testing.T, s *probeSchedule, n int) {
	t.Helper()
	if got := running(s); got != n {
		t.Fatalf("%d runs in progress, want %d", got, n)
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
	wantRunning(t, rt.sched, 0)

	// A scope from the core runs.
	refresh(corePayload(t, "scope-a", 1, now))
	rt.sched.tick(ctx)
	expect(t, runs.started, "scope-a@1")
	wantRunning(t, rt.sched, 1)

	// A second scope waits: one scope runs at a time.
	refresh(corePayload(t, "scope-a", 1, now), corePayload(t, "scope-b", 1, now))
	rt.sched.tick(ctx)
	wantRunning(t, rt.sched, 1)
	if st := rt.status().Probing; st.State != "active" || st.Scopes != 2 || st.Running != 1 {
		t.Fatalf("probing status %+v", st)
	}

	// The core stops listing scope-a: its run is cancelled, then scope-b runs.
	refresh(corePayload(t, "scope-b", 1, now))
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-a@1")
	tickUntil(ctx, t, rt.sched, runs.started, "scope-b@1")
	wantRunning(t, rt.sched, 1)

	// A new version of scope-b replaces the run in progress.
	refresh(corePayload(t, "scope-b", 2, now))
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-b@1")
	tickUntil(ctx, t, rt.sched, runs.started, "scope-b@2")
	wantRunning(t, rt.sched, 1)

	// Paused: nothing starts until resume.
	refresh()
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-b@2")
	settle(t, rt.sched)
	rt.sched.run.Pause()
	refresh(corePayload(t, "scope-c", 1, now))
	rt.sched.tick(ctx)
	wantRunning(t, rt.sched, 0)
	if st := rt.sched.status(); st.State != "paused" {
		t.Fatalf("state %s", st.State)
	}
	rt.sched.run.Resume()
	rt.sched.tick(ctx)
	expect(t, runs.started, "scope-c@1")

	// The collector certificate ends: even before the renewer notices (no
	// expire()), the run is cancelled and nothing starts.
	clk.Advance(rt.store.NotAfter().Sub(clk.Now()) + time.Minute)
	rt.sched.tick(ctx)
	expect(t, runs.cancelled, "scope-c@1")
	settle(t, rt.sched)
	rt.sched.tick(ctx)
	wantRunning(t, rt.sched, 0)

	// Once the renewer records the expiry, the schedule is stopped for good.
	rt.expire()
	rt.sched.tick(ctx)
	wantRunning(t, rt.sched, 0)
	if st := rt.status().Probing; st.State != "stopped" {
		t.Fatalf("probing status after expiry %+v", st)
	}
}

func TestEnrolledScheduleExpiredScopeIsNotRun(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 365*24*time.Hour)
	rt := f.runtime(t, platform.Config{})
	runs := newFakeRuns()
	rt.sched.runFn = runs.run
	ctx := context.Background()

	f.core.SetScopes(corePayload(t, "scope-a", 1, clk.Now()))
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
	wantRunning(t, rt.sched, 0)
}

// keyPair is a scope-signing key for the schedule tests.
type keyPair struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKeyPair(t *testing.T, id string) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{id: id, pub: pub, priv: priv}
}

func (k keyPair) sign(payload []byte) scope.Signed {
	return scope.Signed{Payload: payload, Signature: ed25519.Sign(k.priv, payload), KeyID: k.id}
}

func TestScheduleVerifiesEveryTickWithTheCurrentKeys(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	now := clk.Now()
	keyA, keyB, keyC := newKeyPair(t, "key-a"), newKeyPair(t, "key-b"), newKeyPair(t, "key-c")

	var mu sync.Mutex
	var list []scope.Signed
	pinned := []keyPair{keyA}
	setList := func(l ...scope.Signed) { mu.Lock(); list = l; mu.Unlock() }
	setPinned := func(p ...keyPair) { mu.Lock(); pinned = p; mu.Unlock() }
	source := func() ([]scope.Signed, error) { mu.Lock(); defer mu.Unlock(); return list, nil }
	keys := func() (scope.Keyring, error) {
		mu.Lock()
		defer mu.Unlock()
		m := map[string]ed25519.PublicKey{}
		for _, k := range pinned {
			m[k.id] = k.pub
		}
		return scope.NewKeyring(m)
	}
	tr, err := scope.LoadTracker("")
	if err != nil {
		t.Fatal(err)
	}
	s := newSchedule(source, keys, tr, quietLog())
	s.clk = clk
	runs := newFakeRuns()
	s.runFn = runs.run
	s.submit = func(context.Context, []submit.Observation) error { return nil }
	ctx := context.Background()

	// Signed with the pinned key: runs.
	setList(keyA.sign(corePayload(t, "scope-1", 1, now)))
	s.tick(ctx)
	expect(t, runs.started, "scope-1@1")

	// The keys rotate (key-a removed, key-b pinned): the key-a scope is
	// refused at the next tick and its run cancelled.
	setPinned(keyB)
	s.tick(ctx)
	expect(t, runs.cancelled, "scope-1@1")
	settle(t, s)
	s.tick(ctx)
	wantRunning(t, s, 0)

	// A scope signed with the new key runs.
	setList(keyB.sign(corePayload(t, "scope-2", 1, now)))
	s.tick(ctx)
	expect(t, runs.started, "scope-2@1")

	// A key that is not pinned is never planned.
	setList(keyB.sign(corePayload(t, "scope-2", 1, now)), keyC.sign(corePayload(t, "scope-3", 1, now)))
	s.tick(ctx)
	if st := s.status(); st.Scopes != 1 {
		t.Fatalf("%d scopes live, want 1 (the unpinned one refused)", st.Scopes)
	}

	// Version 2, then a rollback to version 1: the rollback is refused and
	// the run of version 2 stops (it is no longer listed).
	setList(keyB.sign(corePayload(t, "scope-2", 2, now)))
	s.tick(ctx)
	expect(t, runs.cancelled, "scope-2@1")
	tickUntil(ctx, t, s, runs.started, "scope-2@2")
	wantRunning(t, s, 1)
	setList(keyB.sign(corePayload(t, "scope-2", 1, now)))
	s.tick(ctx)
	expect(t, runs.cancelled, "scope-2@2")
	settle(t, s)
	s.tick(ctx)
	wantRunning(t, s, 0)

	// The keys cannot be read: fail closed, nothing is live.
	setList(keyB.sign(corePayload(t, "scope-4", 1, now)))
	s.tick(ctx)
	expect(t, runs.started, "scope-4@1")
	s.keys = func() (scope.Keyring, error) { return nil, context.DeadlineExceeded }
	s.tick(ctx)
	expect(t, runs.cancelled, "scope-4@1")
}
