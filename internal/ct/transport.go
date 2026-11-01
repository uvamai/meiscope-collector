package ct

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// Politeness is the rate limit and back-off for one public service.
type Politeness struct {
	// MinInterval is the least time between the starts of two requests.
	MinInterval time.Duration
	// Retry is the back-off on 429, 5xx and network errors.
	Retry retry.Policy
}

// Defaults per service. They are deliberately conservative: CT data is
// public and shared, and none of these services is ours.
var (
	// CertSpotterPoliteness: the free tier allows a handful of requests per
	// hour; a long Retry-After ends the attempt and crt.sh is tried instead.
	CertSpotterPoliteness = Politeness{
		MinInterval: time.Second,
		Retry:       retry.Policy{Attempts: 3, Base: 5 * time.Second, Max: time.Minute, MaxRetryAfter: 2 * time.Minute},
	}
	// CrtShPoliteness: crt.sh has no SLA and is run as a public service; at
	// most one request per 10 s, long back-off.
	CrtShPoliteness = Politeness{
		MinInterval: 10 * time.Second,
		Retry:       retry.Policy{Attempts: 4, Base: 30 * time.Second, Max: 5 * time.Minute, MaxRetryAfter: 10 * time.Minute},
	}
	// LogPoliteness applies per CT log.
	LogPoliteness = Politeness{
		MinInterval: 250 * time.Millisecond,
		Retry:       retry.Policy{Attempts: 5, Base: time.Second, Max: 2 * time.Minute, MaxRetryAfter: 5 * time.Minute},
	}
)

// transport is an http.RoundTripper that spaces requests by MinInterval and
// retries idempotent requests on 429, 5xx and network errors with
// exponential back-off, honouring Retry-After.
type transport struct {
	base      http.RoundTripper
	clk       clock.Clock
	p         Politeness
	userAgent string

	mu   sync.Mutex
	next time.Time
}

// newHTTPClient returns a client for one service.
func newHTTPClient(base http.RoundTripper, clk clock.Clock, p Politeness, userAgent string) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Transport: &transport{base: base, clk: clk, p: p, userAgent: userAgent},
		Timeout:   0, // per-request deadlines come from the context
	}
}

// wait blocks until this request may start.
func (t *transport) wait(ctx context.Context) error {
	t.mu.Lock()
	now := t.clk.Now()
	start := now
	if t.next.After(now) {
		start = t.next
	}
	t.next = start.Add(t.p.MinInterval)
	t.mu.Unlock()
	return t.clk.Sleep(ctx, start.Sub(now))
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("ct transport: refusing %s; CT sources are read-only", req.Method)
	}
	ctx := req.Context()
	for attempt := 0; ; attempt++ {
		if err := t.wait(ctx); err != nil {
			return nil, err
		}
		r := req.Clone(ctx)
		if t.userAgent != "" && r.Header.Get("User-Agent") == "" {
			r.Header.Set("User-Agent", t.userAgent)
		}
		resp, err := t.base.RoundTrip(r)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
		default:
			return resp, nil
		}
		if attempt >= t.p.Retry.Attempts {
			return resp, err
		}
		wait, ok := t.p.Retry.Wait(attempt, hdr, t.clk.Now())
		if !ok {
			// The server asked for a longer pause than we are willing to
			// hold a poll for: hand the 429/503 to the caller.
			return resp, err
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
		}
		// Push the next request start past the back-off as well, so that
		// concurrent callers on this service also pause.
		t.mu.Lock()
		if until := t.clk.Now().Add(wait); until.After(t.next) {
			t.next = until
		}
		t.mu.Unlock()
		if err := t.clk.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// StatusError is a non-success HTTP answer from a CT source.
type StatusError struct {
	URL        string
	StatusCode int
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("GET %s: HTTP %d (retry after %s)", e.URL, e.StatusCode, e.RetryAfter)
	}
	return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.StatusCode)
}

// getBytes fetches url with hc and returns the body of a 200 answer, read up
// to limit bytes.
func getBytes(ctx context.Context, hc *http.Client, clk clock.Clock, url string, hdr http.Header, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", redactURL(url), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		ra, _ := retry.ParseRetryAfter(resp.Header, clk.Now())
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, &StatusError{URL: redactURL(url), StatusCode: resp.StatusCode, RetryAfter: ra}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", redactURL(url), err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", redactURL(url), limit)
	}
	return b, nil
}

// redactURL drops the query string, which may name customer domains, from
// error messages and logs.
func redactURL(u string) string {
	for i := 0; i < len(u); i++ {
		if u[i] == '?' {
			return u[:i] + "?…"
		}
	}
	return u
}

// IsStatus reports whether err is a StatusError with the given code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.StatusCode == code
}
