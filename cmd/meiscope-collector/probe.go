package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/runner"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Probe settings (development enrolment path, until D1b's GET /scopes):
// MEISCOPE_SCOPE_FILE is a signed scope, or {"scopes":[...]} as the core
// serves them; MEISCOPE_SCOPE_KEYS is the pinned scope-signing keys, in the
// shape of the enrolment response ([{"key_id","public_key"}], base64 keys);
// MEISCOPE_SCOPE_STATE_FILE remembers accepted scope versions.
const (
	envScopeFile  = "MEISCOPE_SCOPE_FILE"
	envScopeKeys  = "MEISCOPE_SCOPE_KEYS"
	envScopeState = "MEISCOPE_SCOPE_STATE_FILE"
)

// scheduleTick is how often the schedule reloads the scope file and starts
// the runs that are due.
const scheduleTick = 5 * time.Second

// pinnedKey is one entry of MEISCOPE_SCOPE_KEYS.
type pinnedKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func loadKeyring(path string) (scope.Keyring, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envScopeKeys, err)
	}
	var keys []pinnedKey
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("%s: %w", envScopeKeys, err)
	}
	m := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%s: key %q: %w", envScopeKeys, k.KeyID, err)
		}
		m[k.KeyID] = raw
	}
	ring, err := scope.NewKeyring(m)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envScopeKeys, err)
	}
	return ring, nil
}

// readScopes reads a single signed scope or a {"scopes": [...]} list.
func readScopes(path string) ([]scope.Signed, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envScopeFile, err)
	}
	var list struct {
		Scopes []scope.Signed `json:"scopes"`
	}
	if err := json.Unmarshal(b, &list); err == nil && list.Scopes != nil {
		return list.Scopes, nil
	}
	var one scope.Signed
	if err := json.Unmarshal(b, &one); err != nil {
		return nil, fmt.Errorf("%s: %w", envScopeFile, err)
	}
	return []scope.Signed{one}, nil
}

// probeSchedule rescans every verified scope on its own interval.
type probeSchedule struct {
	path    string
	ring    scope.Keyring
	tracker *scope.Tracker
	run     *runner.Runner
	clk     clock.Clock
	log     *slog.Logger
	submit  func(context.Context, []submit.Observation) error

	mu      sync.Mutex
	next    map[string]time.Time // scope ID -> next run
	running map[string]bool
	wg      sync.WaitGroup
}

// tick verifies the scope file and starts every run that is due. A scope
// that fails verification is never run; the others still are.
func (s *probeSchedule) tick(ctx context.Context) {
	signed, err := readScopes(s.path)
	if err != nil {
		s.log.ErrorContext(ctx, "scopes not loaded", "error", err)
		return
	}
	now := s.clk.Now()
	for _, sg := range signed {
		sc, err := scope.VerifyKeyring(sg, s.ring, now)
		if err == nil {
			err = s.tracker.Accept(sc, sg.Payload)
		}
		if err != nil {
			s.log.ErrorContext(ctx, "scope refused", "key_id", sg.KeyID, "error", err)
			continue
		}
		if s.run.Paused() || !s.due(sc.ID, now) {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.done(sc.ID)
			s.runScope(ctx, sc, now)
		}()
	}
}

func (s *probeSchedule) due(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[id] || now.Before(s.next[id]) {
		return false
	}
	s.running[id] = true
	return true
}

func (s *probeSchedule) done(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, id)
}

func (s *probeSchedule) runScope(ctx context.Context, sc *scope.Scope, started time.Time) {
	var obs []submit.Observation
	rep, err := s.run.Run(ctx, sc, func(o submit.Observation) { obs = append(obs, o) })
	s.mu.Lock()
	if errors.Is(err, runner.ErrPaused) {
		delete(s.next, sc.ID) // run again as soon as the runner resumes
	} else {
		s.next[sc.ID] = started.Add(time.Duration(sc.RescanIntervalSeconds) * time.Second)
	}
	s.mu.Unlock()
	s.log.InfoContext(ctx, "scope run finished", "scope", sc.ID, "version", sc.Version,
		"planned", rep.Planned, "denied", rep.Denied, "attempts", rep.Attempts, "not_run", rep.NotRun,
		"outcomes", rep.Outcomes, "dry_run", rep.DryRun, "error", err)
	if len(obs) > 0 {
		if serr := s.submit(ctx, obs); serr != nil {
			s.log.ErrorContext(ctx, "observations not submitted", "scope", sc.ID, "count", len(obs), "error", serr)
		}
	}
}

// loop ticks until ctx ends, then waits for the runs in progress.
func (s *probeSchedule) loop(ctx context.Context) {
	defer s.wg.Wait()
	t := time.NewTicker(scheduleTick)
	defer t.Stop()
	for {
		s.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// controlHandler adds POST /pause and POST /resume to the local health
// listener (127.0.0.1 by default). Pause cancels open probe connections at
// once and refuses new ones until resume.
func controlHandler(health http.Handler, r *runner.Runner, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", health)
	mux.HandleFunc("POST /pause", func(w http.ResponseWriter, req *http.Request) {
		r.Pause()
		log.WarnContext(req.Context(), "probing paused")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /resume", func(w http.ResponseWriter, req *http.Request) {
		r.Resume()
		log.InfoContext(req.Context(), "probing resumed")
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// newProbeSchedule builds the schedule from the environment, or returns nil
// when MEISCOPE_SCOPE_FILE is unset (the collector then only serves health).
func newProbeSchedule(getenv func(string) string, sub *submit.Client, stdout io.Writer, log *slog.Logger) (*probeSchedule, error) {
	path := getenv(envScopeFile)
	if path == "" {
		return nil, nil //nolint:nilnil // no scope configured: nothing to schedule
	}
	keys := getenv(envScopeKeys)
	if keys == "" {
		return nil, fmt.Errorf("%s is set but %s is not: scopes are verified against pinned keys", envScopeFile, envScopeKeys)
	}
	ring, err := loadKeyring(keys)
	if err != nil {
		return nil, err
	}
	tr, err := scope.LoadTracker(getenv(envScopeState))
	if err != nil {
		return nil, err
	}
	if getenv(envScopeState) == "" {
		log.Warn(envScopeState + " is not set: accepted scope versions are not kept across restarts")
	}
	s := &probeSchedule{
		path: path, ring: ring, tracker: tr, clk: clock.System{}, log: log,
		run:  runner.New(runner.Options{Logger: log}),
		next: map[string]time.Time{}, running: map[string]bool{},
	}
	if sub != nil {
		s.submit = func(ctx context.Context, obs []submit.Observation) error {
			res, err := sub.Submit(ctx, obs)
			if err == nil {
				log.InfoContext(ctx, "observations submitted", "accepted", res.Accepted, "duplicates", res.Duplicates, "rejected", len(res.Rejected))
			}
			return err
		}
	} else {
		log.Warn("MEISCOPE_CORE_URL is not set: observations are written to standard output, not submitted")
		var mu sync.Mutex
		s.submit = func(_ context.Context, obs []submit.Observation) error {
			mu.Lock()
			defer mu.Unlock()
			return json.NewEncoder(stdout).Encode(submit.ObservationBatch{Observations: obs})
		}
	}
	return s, nil
}
