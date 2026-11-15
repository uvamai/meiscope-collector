package runner

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/pkg/probe"
)

// DefaultWorkers is how many targets are probed at once.
const DefaultWorkers = 16

// Options configure a Runner.
type Options struct {
	Clock    clock.Clock    // default clock.System
	Resolver probe.Resolver // default net.DefaultResolver
	Roots    *x509.CertPool // default the system roots
	Logger   *slog.Logger   // default slog.Default()
	Workers  int            // default DefaultWorkers
}

// Runner probes the targets of verified scopes. Pause stops every scope's
// attempts at once: no new connection starts and open ones are cancelled.
type Runner struct {
	o      Options
	paused atomic.Bool

	mu      sync.Mutex
	cancels map[int]context.CancelFunc
	nextID  int
	canary  map[string]int64 // scope ID -> version whose canary passed
}

// New returns a Runner.
func New(o Options) *Runner {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Workers < 1 {
		o.Workers = DefaultWorkers
	}
	return &Runner{o: o, cancels: map[int]context.CancelFunc{}, canary: map[string]int64{}}
}

// Pause stops all scanning until Resume: it cancels every run in progress
// (open connections close at once) and refuses new attempts.
func (r *Runner) Pause() {
	r.paused.Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.cancels {
		c()
	}
}

// Resume allows scanning again; the schedule starts the next run.
func (r *Runner) Resume() { r.paused.Store(false) }

// Paused reports whether the runner is paused.
func (r *Runner) Paused() bool { return r.paused.Load() }

// Report summarises one run of a scope.
type Report struct {
	Planned  int
	Denied   int
	Attempts int            // connections made
	Outcomes map[string]int // by contract outcome
	// NotRun counts planned attempts that did not run (pause, window,
	// shutdown or a failed canary); they produce no observation.
	NotRun int
	DryRun bool
}

// Run probes every target of sc once and passes each attempt's observation
// to emit (called from one goroutine at a time). In dry-run mode it plans
// and logs the targets and connects to nothing.
func (r *Runner) Run(ctx context.Context, sc *scope.Scope, emit func(submit.Observation)) (Report, error) {
	jobs, denied := Plan(sc)
	rep := Report{Planned: len(jobs), Denied: len(denied), Outcomes: map[string]int{}, DryRun: sc.Policy.DryRun}
	for _, t := range denied {
		r.o.Logger.InfoContext(ctx, "target on the deny list, not probed", "scope", sc.ID, "host", t.Host, "port", t.Port)
	}
	if sc.Policy.DryRun {
		for _, j := range jobs {
			r.o.Logger.InfoContext(ctx, "dry run: would probe", "scope", sc.ID, "host", j.Target.Host, "port", j.Target.Port, "snis", len(j.SNIs))
		}
		return rep, nil
	}
	if r.paused.Load() {
		rep.NotRun = attempts(jobs)
		return rep, ErrPaused
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	id := r.register(cancel)
	defer r.unregister(id)

	pc := newPacer(r.o.Clock, sc.Policy, r.paused.Load)
	var mu sync.Mutex
	out := func(o submit.Observation) {
		mu.Lock()
		defer mu.Unlock()
		rep.Attempts++
		rep.Outcomes[o.Outcome]++
		emit(o)
	}
	notRun := func(n int) {
		mu.Lock()
		defer mu.Unlock()
		rep.NotRun += n
	}

	rest := jobs
	if !r.canaryPassed(sc) {
		n := int(math.Ceil(float64(len(jobs)) * sc.Policy.CanaryPercent / 100))
		n = min(max(n, 1), len(jobs))
		r.runJobs(ctx, sc, pc, jobs[:n], out, notRun)
		if ctx.Err() != nil || r.paused.Load() {
			notRun(attempts(jobs[n:]))
			return rep, r.stopReason(ctx)
		}
		r.markCanary(sc)
		rest = jobs[n:]
	}
	r.runJobs(ctx, sc, pc, rest, out, notRun)
	if ctx.Err() != nil || r.paused.Load() {
		return rep, r.stopReason(ctx)
	}
	return rep, nil
}

func (r *Runner) stopReason(ctx context.Context) error {
	if r.paused.Load() {
		return ErrPaused
	}
	return ctx.Err()
}

func (r *Runner) runJobs(ctx context.Context, sc *scope.Scope, pc *pacer, jobs []Job, out func(submit.Observation), notRun func(int)) {
	ch := make(chan Job)
	var wg sync.WaitGroup
	for range min(r.o.Workers, max(len(jobs), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				r.runJob(ctx, sc, pc, j, out, notRun)
			}
		}()
	}
	for i, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
			notRun(attempts(jobs[i:]))
			close(ch)
			wg.Wait()
			return
		}
	}
	close(ch)
	wg.Wait()
}

// runJob makes one attempt per SNI on the job's target, in order. When the
// port is closed or silent (refused, timeout), the remaining names on the
// same target are reported with that outcome without connecting again: the
// port's state is the same for every name.
func (r *Runner) runJob(ctx context.Context, sc *scope.Scope, pc *pacer, j Job, out func(submit.Observation), notRun func(int)) {
	allow, err := allowFor(j)
	if err != nil || allow == nil {
		// Fail closed: a job whose allow list the runner cannot build is
		// never probed. A nil Allow means "no list" to probe.New, so the
		// probe would run unrestricted; refuse the whole job instead and
		// count every SNI as not run.
		r.o.Logger.WarnContext(ctx, "target not probed: allow list rejected", "scope", sc.ID, "host", j.Target.Host, "port", j.Target.Port, "error", err)
		notRun(len(j.SNIs))
		return
	}
	for i, sni := range j.SNIs {
		if ctx.Err() != nil {
			notRun(len(j.SNIs) - i)
			return
		}
		var dialled netip.Addr
		p := probe.New(probe.Options{
			Resolver: r.o.Resolver,
			Roots:    r.o.Roots,
			Now:      r.o.Clock.Now,
			Logger:   r.o.Logger,
			Allow:    allow,
			Pace: func(ctx context.Context, a netip.Addr) error {
				// Only a wait that ended in a dial is fed back to the
				// pacer: a cancelled wait is not a network timeout (S-25).
				if err := pc.wait(ctx, a); err != nil {
					return err
				}
				dialled = a
				return nil
			},
		})
		at := r.o.Clock.Now().UTC()
		res, err := p.Probe(ctx, probe.Target{
			Host:     j.Target.Host,
			Port:     j.Target.Port,
			SNI:      sni,
			StartTLS: Mode(j.Target.Protocol),
			Timeout:  time.Duration(sc.Policy.ConnectTimeoutSeconds) * time.Second,
		})
		outcome := probe.Outcome(err)
		if outcome == "" {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, ErrPaused) || errors.Is(err, ErrOutsideTime) {
				notRun(len(j.SNIs) - i)
				return
			}
			r.o.Logger.WarnContext(ctx, "target not probed", "scope", sc.ID, "host", j.Target.Host, "port", j.Target.Port, "error", err)
			notRun(1)
			continue
		}
		if dialled.IsValid() {
			pc.record(dialled, outcome == probe.OutcomeTimeout)
		}
		o := observation(j, sni, at, outcome, res)
		out(o)
		if outcome == probe.OutcomeRefused || outcome == probe.OutcomeTimeout {
			for _, other := range j.SNIs[i+1:] {
				out(observation(j, other, at, outcome, nil))
			}
			return
		}
	}
}

// allowFor pins the probe to the job's own target: an IP target may only
// dial that address; a name target only that name, dialled at the address
// vetted for it. The scope verifier has already refused anything NewAllow
// would reject, but allowFor still returns the error so the caller can fail
// closed rather than hand probe.New a nil (unrestricted) allow list.
func allowFor(j Job) (*probe.Allow, error) {
	if j.IP.IsValid() {
		return probe.NewAllow(nil, []netip.Prefix{netip.PrefixFrom(j.IP, j.IP.BitLen())})
	}
	return probe.NewAllow([]string{j.Target.Host}, nil)
}

func attempts(jobs []Job) int {
	n := 0
	for _, j := range jobs {
		n += len(j.SNIs)
	}
	return n
}

func (r *Runner) register(c context.CancelFunc) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	r.cancels[r.nextID] = c
	return r.nextID
}

func (r *Runner) unregister(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cancels, id)
}

func (r *Runner) canaryPassed(sc *scope.Scope) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.canary[sc.ID] == sc.Version
}

func (r *Runner) markCanary(sc *scope.Scope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canary[sc.ID] = sc.Version
}
