// Package scopesync keeps an enrolled collector's set of scan scopes in step
// with the core: it fetches the signed scopes (GET /collector/v1/scopes),
// verifies each with the scope-signing keys pinned at enrolment, refuses a
// version lower than the last accepted for its id (scope.Tracker), keeps the
// last good set when a fetch fails, and drops the scopes the core no longer
// lists or that have expired.
//
// It decides which scopes may run; it never connects to a target.
package scopesync

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/scope"
)

// Refresh interval bounds (MEISCOPE_SCOPE_REFRESH).
const (
	DefaultRefresh = 5 * time.Minute
	MinRefresh     = time.Minute
	MaxRefresh     = time.Hour
)

// FailureBackoff is the wait after a failed fetch: it starts at 30 seconds,
// doubles, and never exceeds the refresh interval.
var FailureBackoff = retry.Policy{Base: 30 * time.Second}

// Fetcher returns the signed scopes the core lists, unverified.
type Fetcher func(ctx context.Context) ([]scope.Signed, error)

// KeyringFrom converts the pinned scope-signing keys of an identity into a
// keyring.
func KeyringFrom(keys []identity.ScopeSigningKey) (scope.Keyring, error) {
	m := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("scope-signing key %q: %w", k.KeyID, err)
		}
		m[k.KeyID] = raw
	}
	return scope.NewKeyring(m)
}

// Set is the current set of verified scopes.
type Set struct {
	fetch   Fetcher
	keys    func() (scope.Keyring, error)
	tracker *scope.Tracker
	clk     clock.Clock
	log     *slog.Logger

	mu        sync.Mutex
	held      map[string]entry // scope id -> last accepted version
	lastFetch time.Time        // last successful fetch
	lastTry   time.Time
	lastErr   string
	refused   int // entries refused by the last successful fetch
	failures  int // consecutive failed fetches
	stopped   string
}

type entry struct {
	signed scope.Signed
	sc     *scope.Scope
}

// New returns an empty set. keys is called on every refresh, so keys
// renewed with the certificate take effect at once.
func New(fetch Fetcher, keys func() (scope.Keyring, error), tracker *scope.Tracker, clk clock.Clock, log *slog.Logger) *Set {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Set{fetch: fetch, keys: keys, tracker: tracker, clk: clk, log: log, held: map[string]entry{}}
}

// Refresh fetches the core's list once and replaces the set with the
// scopes that verify. When the fetch fails, the set is kept as it was (its
// expired scopes still drop out, see Signed) and the error is returned.
// A listed scope that fails verification, or whose version is lower than
// the last accepted for its id, is refused and logged; it does not stay in
// the set under its older version, because the core no longer lists that.
func (s *Set) Refresh(ctx context.Context) error {
	if s.Stopped() != "" {
		return fmt.Errorf("scope refresh stopped: %s", s.Stopped())
	}
	list, err := s.fetch(ctx)
	now := s.clk.Now()
	if err == nil {
		var ring scope.Keyring
		if ring, err = s.keys(); err == nil {
			s.replace(ctx, list, ring, now)
			return nil
		}
		err = fmt.Errorf("pinned scope-signing keys: %w", err)
	}
	s.mu.Lock()
	s.lastTry, s.lastErr = now, err.Error()
	s.failures++
	n := len(s.held)
	s.mu.Unlock()
	if ctx.Err() == nil {
		s.log.ErrorContext(ctx, "scopes not fetched; keeping the last good set", "held", n, "error", err)
	}
	return err
}

func (s *Set) replace(ctx context.Context, list []scope.Signed, ring scope.Keyring, now time.Time) {
	next := map[string]entry{}
	refused := 0
	for _, sg := range list {
		sc, err := scope.VerifyKeyring(sg, ring, now)
		if err == nil {
			if _, dup := next[sc.ID]; dup {
				err = fmt.Errorf("%w: scope %s is listed twice", scope.ErrInvalid, sc.ID)
			}
		}
		if err == nil {
			err = s.tracker.Accept(sc, sg.Payload)
		}
		if err != nil {
			refused++
			attrs := []any{"key_id", sg.KeyID, "error", err}
			if sc != nil {
				attrs = append(attrs, "scope", sc.ID, "version", sc.Version)
			}
			s.log.ErrorContext(ctx, "scope refused", attrs...)
			continue
		}
		next[sc.ID] = entry{signed: sg, sc: sc}
	}
	s.mu.Lock()
	prev := s.held
	s.held, s.lastFetch, s.lastTry, s.lastErr, s.refused, s.failures = next, now, now, "", refused, 0
	s.mu.Unlock()
	for id, e := range next {
		if p, ok := prev[id]; !ok {
			s.log.InfoContext(ctx, "scope accepted", "scope", id, "version", e.sc.Version, "targets", len(e.sc.Targets), "not_after", e.sc.NotAfter)
		} else if p.sc.Version != e.sc.Version {
			s.log.InfoContext(ctx, "scope updated", "scope", id, "version", e.sc.Version, "previous", p.sc.Version, "targets", len(e.sc.Targets))
		}
	}
	for id := range prev {
		if _, ok := next[id]; !ok {
			s.log.InfoContext(ctx, "scope dropped: the core no longer lists a valid version of it", "scope", id)
		}
	}
}

// live returns the held entries valid at now, sorted by scope id.
func (s *Set) live(now time.Time) []entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped != "" {
		return nil
	}
	out := make([]entry, 0, len(s.held))
	for _, e := range s.held {
		if !now.Before(e.sc.NotBefore) && now.Before(e.sc.NotAfter) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b entry) int { return cmp.Compare(a.sc.ID, b.sc.ID) })
	return out
}

// Signed returns the verified scopes, as the core signed them, that are
// valid now: what a schedule may run. It is empty once the set is stopped.
func (s *Set) Signed() []scope.Signed {
	live := s.live(s.clk.Now())
	out := make([]scope.Signed, len(live))
	for i, e := range live {
		out[i] = e.signed
	}
	return out
}

// Scopes returns the decoded scopes of Signed.
func (s *Set) Scopes() []*scope.Scope {
	live := s.live(s.clk.Now())
	out := make([]*scope.Scope, len(live))
	for i, e := range live {
		out[i] = e.sc
	}
	return out
}

// Stop empties the set for good and ends Run: nothing may run, for the
// reason given (for example an expired collector certificate).
func (s *Set) Stop(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = reason
	s.held = map[string]entry{}
}

// Stopped returns the reason the set was stopped, or "".
func (s *Set) Stopped() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// Status is what the collector's status output shows of the set.
type Status struct {
	Count     int       `json:"count"`
	IDs       []string  `json:"ids"`
	LastFetch time.Time `json:"last_fetch,omitzero"`
	LastTry   time.Time `json:"last_attempt,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	Refused   int       `json:"refused_in_last_fetch"`
	Stopped   string    `json:"stopped,omitempty"`
}

// Status reports the set.
func (s *Set) Status() Status {
	sc := s.Scopes()
	ids := make([]string, len(sc))
	for i, x := range sc {
		ids[i] = x.ID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		Count: len(ids), IDs: ids, LastFetch: s.lastFetch, LastTry: s.lastTry,
		LastError: s.lastErr, Refused: s.refused, Stopped: s.stopped,
	}
}

// Wait returns how long to wait before the next refresh: every after a
// good fetch, FailureBackoff (capped at every) after a failed one.
func (s *Set) Wait(every time.Duration) time.Duration {
	s.mu.Lock()
	f := s.failures
	s.mu.Unlock()
	if f == 0 {
		return every
	}
	p := FailureBackoff
	p.Max = every
	return p.Delay(f - 1)
}

// Run refreshes the set every interval until ctx ends or the set is
// stopped.
func (s *Set) Run(ctx context.Context, every time.Duration) {
	for s.Stopped() == "" {
		_ = s.Refresh(ctx) // logged by Refresh
		if s.clk.Sleep(ctx, s.Wait(every)) != nil {
			return
		}
	}
}
