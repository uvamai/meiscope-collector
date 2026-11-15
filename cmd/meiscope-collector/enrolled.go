package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/ct"
	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/scopesync"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Settings of an enrolled collector's run (docs/install.md).
const (
	envScopeRefresh = "MEISCOPE_SCOPE_REFRESH"
	envCTInterval   = "MEISCOPE_CT_INTERVAL"

	defaultCTInterval = time.Hour
	minCTInterval     = 15 * time.Minute
	maxCTInterval     = 24 * time.Hour

	// Files kept next to the identity unless their variables say otherwise.
	scopeVersionsFile = "scope-versions.json" // MEISCOPE_SCOPE_STATE_FILE
	ctStateFile       = "ct-state.json"       // MEISCOPE_CT_STATE_FILE
)

// durationSetting reads a duration variable bounded to [lo, hi]; with
// allowOff, "off" or "0" turns the feature off (0).
func durationSetting(getenv func(string) string, name string, def, lo, hi time.Duration, allowOff bool) (time.Duration, error) {
	v := strings.TrimSpace(getenv(name))
	if v == "" {
		return def, nil
	}
	if allowOff && (v == "off" || v == "0") {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("%s: must be between %s and %s, got %s", name, lo, hi, v)
	}
	return d, nil
}

// sameURL compares two core URLs, ignoring a trailing slash.
func sameURL(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

// enrolledDeps are the injectable parts of an enrolled run (tests replace them).
type enrolledDeps struct {
	clk clock.Clock
	// base is the transport to the core before the identity is layered on
	// it; nil builds it from the egress settings (proxy, MEISCOPE_NO_PROXY).
	base  *http.Transport
	ct    ctDeps // its clk is replaced by clk
	creds func(getenv func(string) string) credential.Source
}

func defaultEnrolledDeps() enrolledDeps {
	return enrolledDeps{clk: clock.System{}, ct: defaultCTDeps(), creds: defaultCredentialSource}
}

// enrolledRuntime is a collector enrolled with "meiscope-collector enrol":
// every call to the core goes over mTLS with its identity, from one process
// that renews the certificate, refreshes the signed scopes and polls
// Certificate Transparency for the owned domains.
type enrolledRuntime struct {
	store   *identity.Store
	sub     *submit.Client
	scopes  *scopesync.Set
	sched   *probeSchedule // probes the scopes in scopes; stopped on expiry
	renewer *enrol.Renewer
	refresh time.Duration
	ctEvery time.Duration
	ctPoll  func(context.Context) error // nil when CT polling is off
	clk     clock.Clock
	log     *slog.Logger

	mu      sync.Mutex
	expired bool
	ctLast  time.Time
	ctErr   string
}

// newEnrolledRuntime loads the identity in the state directory and checks
// the configuration against it.
func newEnrolledRuntime(getenv func(string) string, cfg platform.Config, log *slog.Logger, deps enrolledDeps) (*enrolledRuntime, error) {
	dir := stateDir(getenv)
	if getenv(envScopeFile) != "" {
		return nil, fmt.Errorf("%s is set, but this collector is enrolled (identity in %s) and takes its scopes from the core: unset %s and %s",
			envScopeFile, dir, envScopeFile, envScopeKeys)
	}
	store, err := identity.Load(dir)
	if err != nil {
		return nil, err
	}
	if cfg.CoreURL != "" && !sameURL(cfg.CoreURL, store.CoreURL()) {
		return nil, fmt.Errorf("MEISCOPE_CORE_URL is %s, but this collector enrolled with the core at %s: unset MEISCOPE_CORE_URL, or enrol again against the new core",
			cfg.CoreURL, store.CoreURL())
	}
	refresh, err := durationSetting(getenv, envScopeRefresh, scopesync.DefaultRefresh, scopesync.MinRefresh, scopesync.MaxRefresh, false)
	if err != nil {
		return nil, err
	}
	ctEvery, err := durationSetting(getenv, envCTInterval, defaultCTInterval, minCTInterval, maxCTInterval, true)
	if err != nil {
		return nil, err
	}
	base := deps.base
	if base == nil {
		if base, err = egress.Transport(egress.LoadConfig(getenv), deps.creds(getenv), egress.Options{}); err != nil {
			return nil, err
		}
	}
	// One mTLS client for every call to the core: it presents the current
	// certificate and trusts only the CA bundle pinned at enrolment.
	hc := egress.Client(store.Transport(base), time.Minute)
	sub, err := submit.New(store.CoreURL(), hc, submit.WithClock(deps.clk), submit.WithUserAgent(userAgent()), submit.WithLogger(log))
	if err != nil {
		return nil, err
	}
	ecl, err := enrol.New(store.CoreURL(), hc, userAgent())
	if err != nil {
		return nil, err
	}
	trackerPath := getenv(envScopeState)
	if trackerPath == "" {
		trackerPath = filepath.Join(dir, scopeVersionsFile)
	}
	tr, err := scope.LoadTracker(trackerPath)
	if err != nil {
		return nil, err
	}
	keys := func() (scope.Keyring, error) { return scopesync.KeyringFrom(store.ScopeKeys()) }
	if _, err := keys(); err != nil {
		return nil, fmt.Errorf("pinned scope-signing keys in %s: %w", dir, err)
	}
	rt := &enrolledRuntime{
		store: store, sub: sub, refresh: refresh, ctEvery: ctEvery, clk: deps.clk, log: log,
		scopes:  scopesync.New(sub.Scopes, keys, tr, deps.clk, log),
		renewer: &enrol.Renewer{Store: store, Client: ecl, Clock: deps.clk, Log: log},
	}
	// The probe schedule runs exactly the scopes the set holds now and
	// verifies each again against the pinned keys, read on every tick (a
	// renewal may rotate them). Nothing runs once the collector certificate
	// has ended, even before the renewer notices, and no run outlives it.
	// The schedule keeps its own in-memory version record; the set's record
	// on disk already refuses rollbacks.
	schedTracker, err := scope.LoadTracker("")
	if err != nil {
		return nil, err
	}
	rt.sched = newSchedule(func() ([]scope.Signed, error) { return rt.scopes.Signed(), nil }, keys, schedTracker, log)
	rt.sched.deadline = store.NotAfter
	rt.sched.clk = deps.clk
	rt.sched.submit = submitTo(sub, log)
	if ctEvery > 0 {
		ctCfg, err := ct.LoadConfig(getenv)
		if err != nil {
			return nil, err
		}
		if ctCfg.StateFile == "" {
			ctCfg.StateFile = filepath.Join(dir, ctStateFile)
		}
		if len(ctCfg.Domains) > 0 {
			log.Warn("MEISCOPE_CT_DOMAINS is ignored: the owned domains come from the core")
		}
		ctd := deps.ct
		ctd.clk = deps.clk
		poller, st, err := ctSetup(ctCfg, ctd, getenv, log)
		if err != nil {
			return nil, err
		}
		rt.ctPoll = func(ctx context.Context) error {
			return pollOnce(ctx, poller, st, ctCfg.StateFile, sub, "", io.Discard, log)
		}
	}
	return rt, nil
}

// run calls the core until ctx ends or the certificate expires: renewal,
// scope refresh and CT polling, each in its own goroutine. It returns when
// all of them have stopped. After an expiry nothing calls the core again.
func (rt *enrolledRuntime) run(ctx context.Context) {
	ctInterval := "off"
	if rt.ctPoll != nil {
		ctInterval = rt.ctEvery.String()
	}
	rt.log.InfoContext(ctx, "enrolled collector running", "collector_id", rt.store.CollectorID(), "core_url", rt.store.CoreURL(),
		"certificate_not_after", rt.store.NotAfter(), "renew_at", rt.store.RenewAt(),
		"scope_refresh", rt.refresh.String(), "ct_interval", ctInterval)
	if !rt.clk.Now().Before(rt.store.NotAfter()) {
		_, _ = rt.renewer.Step(ctx) // logs and records the expiry; calls nothing
		rt.expire()
		return
	}
	coreCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := rt.renewer.Run(coreCtx); errors.Is(err, enrol.ErrExpired) {
			rt.expire()
			stop()
		}
	})
	wg.Go(func() { rt.scopes.Run(coreCtx, rt.refresh) })
	if rt.ctPoll != nil {
		wg.Go(func() { ctLoop(coreCtx, rt.clk, rt.ctEvery, rt.pollCT, rt.log) })
	}
	wg.Wait()
}

// expire stops everything that would call the core with a dead certificate.
func (rt *enrolledRuntime) expire() {
	rt.mu.Lock()
	rt.expired = true
	rt.mu.Unlock()
	rt.scopes.Stop("the collector certificate expired")
	rt.sched.stopAll("the collector certificate expired")
}

func (rt *enrolledRuntime) isExpired() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.expired
}

// pollCT runs one CT poll and records its outcome for the status output.
func (rt *enrolledRuntime) pollCT(ctx context.Context) error {
	err := rt.ctPoll(ctx)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ctLast, rt.ctErr = rt.clk.Now(), ""
	if err != nil {
		rt.ctErr = err.Error()
	}
	return err
}

// idle is called every idle interval by serve.
func (rt *enrolledRuntime) idle() {
	if rt.isExpired() {
		rt.log.Error("the collector certificate has expired: the collector no longer calls the core", "action", enrol.ErrExpired.Error())
	}
}

// enrolledStatus is the GET /status answer: enrolment state, never secrets.
type enrolledStatus struct {
	Enrolled    bool             `json:"enrolled"`
	CollectorID string           `json:"collector_id"`
	CoreURL     string           `json:"core_url"`
	Certificate certificateState `json:"certificate"`
	Scopes      scopesync.Status `json:"scopes"`
	Probing     scheduleStatus   `json:"probing"`
	CT          ctPollState      `json:"ct"`
}

type certificateState struct {
	State     string              `json:"state"` // valid, renewal_failing or expired
	NotBefore time.Time           `json:"not_before"`
	NotAfter  time.Time           `json:"not_after"`
	RenewAt   time.Time           `json:"renew_at"`
	Renewal   enrol.RenewalStatus `json:"renewal"`
}

type ctPollState struct {
	Enabled   bool      `json:"enabled"`
	Interval  string    `json:"interval,omitempty"`
	LastPoll  time.Time `json:"last_poll,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

func (rt *enrolledRuntime) status() enrolledStatus {
	rs := rt.renewer.Status()
	state := "valid"
	switch {
	case rt.isExpired() || rs.Expired || !rt.clk.Now().Before(rt.store.NotAfter()):
		state = "expired"
	case rs.Failures > 0:
		state = "renewal_failing"
	}
	st := enrolledStatus{
		Enrolled: true, CollectorID: rt.store.CollectorID(), CoreURL: rt.store.CoreURL(),
		Certificate: certificateState{
			State: state, NotBefore: rt.store.NotBefore(), NotAfter: rt.store.NotAfter(), RenewAt: rt.store.RenewAt(), Renewal: rs,
		},
		Scopes:  rt.scopes.Status(),
		Probing: rt.sched.status(),
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st.CT = ctPollState{Enabled: rt.ctPoll != nil, LastPoll: rt.ctLast, LastError: rt.ctErr}
	if rt.ctPoll != nil {
		st.CT.Interval = rt.ctEvery.String()
	}
	return st
}

// handler adds GET /status to the local health listener.
func (rt *enrolledRuntime) handler(health http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", health)
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rt.status())
	})
	return mux
}
