package adapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
)

// DefaultMaxPages bounds Paginate when the caller passes 0.
const DefaultMaxPages = 10000

// ErrTooManyPages is returned when a listing does not end within the cap.
var ErrTooManyPages = errors.New("pagination did not end within the page cap")

// Page is one page of a paginated listing.
type Page[T any] struct {
	Items []T
	// Next is the token of the next page; "" ends the listing.
	Next string
}

// Paginate calls fetch with "" and then with each Next token until a page
// has no Next, returning all items in order. A token that repeats is an
// error (a server that loops would otherwise never end).
func Paginate[T any](ctx context.Context, maxPages int, fetch func(ctx context.Context, token string) (Page[T], error)) ([]T, error) {
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}
	var all []T
	seen := map[string]bool{}
	token := ""
	for i := 0; i < maxPages; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := fetch(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", i, err)
		}
		all = append(all, p.Items...)
		if p.Next == "" {
			return all, nil
		}
		if seen[p.Next] {
			return nil, fmt.Errorf("page %d: next token repeats", i)
		}
		seen[p.Next] = true
		token = p.Next
	}
	return nil, ErrTooManyPages
}

// Limiter spaces calls at least Interval apart on a clock, so an adapter
// stays inside the rate an API owner allows.
type Limiter struct {
	Clock    clock.Clock
	Interval time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewLimiter allows perSecond calls per second (0 or less: unlimited).
func NewLimiter(clk clock.Clock, perSecond float64) *Limiter {
	l := &Limiter{Clock: clk}
	if perSecond > 0 {
		l.Interval = time.Duration(float64(time.Second) / perSecond)
	}
	return l
}

// Wait blocks until the next call is allowed.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.Interval <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Clock.Now()
	if !l.last.IsZero() {
		if d := l.last.Add(l.Interval).Sub(now); d > 0 {
			if err := l.Clock.Sleep(ctx, d); err != nil {
				return err
			}
			now = l.Clock.Now()
		}
	}
	l.last = now
	return nil
}

// secretPatterns match credential and key material that must never appear
// in logs, observations or fixtures.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\bbasic\s+[a-z0-9+/=]{8,}`),
	regexp.MustCompile(`(?i)"?(api[_-]?token|api[_-]?key|password|passwd|secret|client_secret|access_token|refresh_token)"?\s*[:=]\s*"?[^\s",}]{6,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
}

// LooksSecret reports whether s contains something shaped like credential
// or private-key material.
func LooksSecret(s string) bool {
	for _, p := range secretPatterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// FindSecrets returns the patterns that match b (for the fixture leak test).
func FindSecrets(b []byte) []string {
	var out []string
	for _, p := range secretPatterns {
		if p.Match(b) {
			out = append(out, p.String())
		}
	}
	return out
}

// Redact replaces credential-shaped substrings with [redacted], and each of
// the given known values too.
func Redact(s string, known ...string) string {
	for _, k := range known {
		if len(k) >= 4 {
			s = strings.ReplaceAll(s, k, "[redacted]")
		}
	}
	for _, p := range secretPatterns {
		s = p.ReplaceAllString(s, "[redacted]")
	}
	return s
}
