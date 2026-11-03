package runner

import (
	"context"
	"net/netip"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// failResolver fails the test if the probe ever tries to resolve a name: a
// job that fails closed must never reach the network.
type failResolver struct{ t *testing.T }

func (r failResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.t.Helper()
	r.t.Fatal("resolver called: a fail-closed job must not dial")
	return nil, nil
}

func TestAllowForRejectsBadHostAndPinsGoodTargets(t *testing.T) {
	if _, err := allowFor(Job{Target: scope.Target{Host: "bad host", Port: 443}}); err == nil {
		t.Fatal("allowFor accepted an invalid host; it must return an error so the caller can fail closed")
	}
	if a, err := allowFor(Job{Target: scope.Target{Host: "www.example.test", Port: 443}}); err != nil || a == nil {
		t.Fatalf("allowFor name target: a=%v err=%v; want a non-nil allow list, no error", a, err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	if a, err := allowFor(Job{Target: scope.Target{Host: "192.0.2.1", Port: 443}, IP: ip}); err != nil || a == nil {
		t.Fatalf("allowFor IP target: a=%v err=%v; want a non-nil allow list, no error", a, err)
	}
}

// TestRunJobFailsClosedOnAllowError proves the runner never probes with a nil
// allow list: when allowFor errors, the job is skipped, every SNI is counted
// as not run, nothing is emitted, and the resolver is never called.
func TestRunJobFailsClosedOnAllowError(t *testing.T) {
	r := New(Options{Resolver: failResolver{t}})
	pc := newPacer(r.o.Clock, scope.ScanPolicy{RatePer24: 1, Burst: 1}, func() bool { return false })
	sc := &scope.Scope{ID: "s1", Policy: scope.ScanPolicy{RatePer24: 1, Burst: 1}}

	j := Job{Target: scope.Target{Host: "bad host", Port: 443}, SNIs: []string{"bad host", "other"}}

	emitted := 0
	notRun := 0
	r.runJob(context.Background(), sc, pc, j,
		func(submit.Observation) { emitted++ },
		func(n int) { notRun += n },
	)

	if emitted != 0 {
		t.Fatalf("fail-closed job emitted %d observations; want 0", emitted)
	}
	if notRun != len(j.SNIs) {
		t.Fatalf("fail-closed job counted notRun=%d; want %d (every SNI)", notRun, len(j.SNIs))
	}
}
