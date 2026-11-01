// Package submit is the collector's client of the core's collector API
// (ADR-0005): POST /collector/v1/observations with gzip-compressed JSON
// batches of at most 1000 observations, and GET /collector/v1/owned-domains,
// both retried with back-off.
package submit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// Endpoints below the core base URL.
const (
	ObservationsPath  = "/collector/v1/observations"
	OwnedDomainsPath  = "/collector/v1/owned-domains"
	maxResponseBytes  = 16 << 20
	maxDiscardedBytes = 1 << 20
)

// MaxWireBytes is the core's limit on the compressed body (10 MiB); batches
// are split before they reach it.
const MaxWireBytes = 10 << 20

// DefaultRetry is the back-off for submissions.
var DefaultRetry = retry.Policy{Attempts: 5, Base: time.Second, Max: time.Minute, MaxRetryAfter: 5 * time.Minute}

// Client submits observation batches.
type Client struct {
	base      *url.URL
	hc        *http.Client
	clk       clock.Clock
	policy    retry.Policy
	batch     int
	maxWire   int
	userAgent string
	log       *slog.Logger

	mu      sync.Mutex
	unknown map[string]bool // rejection codes already logged as unknown
}

// Option configures a Client.
type Option func(*Client)

// WithClock sets the clock (tests).
func WithClock(c clock.Clock) Option { return func(cl *Client) { cl.clk = c } }

// WithRetry sets the back-off policy.
func WithRetry(p retry.Policy) Option { return func(cl *Client) { cl.policy = p } }

// WithBatchSize sets the batch size (1..MaxBatch).
func WithBatchSize(n int) Option {
	return func(cl *Client) {
		if n >= 1 && n <= MaxBatch {
			cl.batch = n
		}
	}
}

// WithLogger sets the logger; each rejection code the collector does not
// know is logged on it once.
func WithLogger(l *slog.Logger) Option { return func(cl *Client) { cl.log = l } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(cl *Client) { cl.userAgent = ua } }

// New returns a client for the core at base (an absolute URL). hc carries the
// collector's mTLS identity once enrolment exists (WP0.3).
func New(base string, hc *http.Client, opts ...Option) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("core URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("core URL must be absolute, got %q", base)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	c := &Client{base: u, hc: hc, clk: clock.System{}, policy: DefaultRetry, batch: MaxBatch, maxWire: MaxWireBytes,
		log: slog.New(slog.DiscardHandler), unknown: map[string]bool{}}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Result sums the core's answers over all batches. Rejection indices refer
// to the slice given to Submit.
type Result struct {
	Batches    int
	Accepted   int
	Duplicates int
	Rejected   []Rejection
	// Reasons counts the rejections by Rejection.Reason.
	Reasons map[string]int
}

// PermanentError is a 4xx answer that retrying cannot fix.
type PermanentError struct {
	Status  int
	Problem Problem
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("core refused the request: HTTP %d %s %s", e.Status, e.Problem.Title, e.Problem.Detail)
}

// Submit sends obs in batches. It stops at the first batch that fails and
// returns the result so far with the error; batches are idempotent at the
// core, so the caller retries the whole slice next cycle.
func (c *Client) Submit(ctx context.Context, obs []Observation) (Result, error) {
	var res Result
	for start := 0; start < len(obs); start += c.batch {
		end := min(start+c.batch, len(obs))
		if err := c.sendSplit(ctx, obs[start:end], start, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// sendSplit sends one batch, halving it while the compressed body exceeds
// the wire limit.
func (c *Client) sendSplit(ctx context.Context, obs []Observation, offset int, res *Result) error {
	body, err := encode(obs)
	if err != nil {
		return err
	}
	if len(body) > c.maxWire {
		if len(obs) == 1 {
			return fmt.Errorf("observation %d alone exceeds %d bytes compressed", offset, c.maxWire)
		}
		half := len(obs) / 2
		if err := c.sendSplit(ctx, obs[:half], offset, res); err != nil {
			return err
		}
		return c.sendSplit(ctx, obs[half:], offset+half, res)
	}
	br, err := c.post(ctx, body)
	if err != nil {
		return err
	}
	res.Batches++
	res.Accepted += br.Accepted
	res.Duplicates += br.Duplicates
	for _, r := range br.Rejected {
		r.Index += offset
		r.Reason = RejectionReason(r.Code)
		if !r.Known() {
			c.logUnknown(r)
		}
		if res.Reasons == nil {
			res.Reasons = map[string]int{}
		}
		res.Reasons[r.Reason]++
		res.Rejected = append(res.Rejected, r)
	}
	return nil
}

// logUnknown logs a rejection code this collector does not know, once per
// code. The observation is still counted as rejected (it is not resent).
func (c *Client) logUnknown(r Rejection) {
	c.mu.Lock()
	seen := c.unknown[r.Code]
	c.unknown[r.Code] = true
	c.mu.Unlock()
	if !seen {
		c.log.Warn("the core rejected an observation with a code this collector does not know; it is counted as rejected and not resent",
			"code", r.Code, "reason", r.Reason, "message", r.Message)
	}
}

func encode(obs []Observation) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(ObservationBatch{Observations: obs}); err != nil {
		return nil, fmt.Errorf("encode batch: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("gzip batch: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *Client) post(ctx context.Context, body []byte) (ObservationBatchResult, error) {
	var out ObservationBatchResult
	err := c.do(ctx, http.MethodPost, ObservationsPath, body, http.StatusAccepted, &out)
	if err != nil {
		return ObservationBatchResult{}, fmt.Errorf("submit observations: %w", err)
	}
	return out, nil
}

// OwnedDomains returns the tenant's owned domains (GET
// /collector/v1/owned-domains), the domains the CT poller queries.
func (c *Client) OwnedDomains(ctx context.Context) ([]string, error) {
	var out OwnedDomainList
	if err := c.do(ctx, http.MethodGet, OwnedDomainsPath, nil, http.StatusOK, &out); err != nil {
		return nil, fmt.Errorf("owned domains: %w", err)
	}
	return out.Domains, nil
}

// do sends one request, retrying network errors, 429 and 5xx with back-off,
// and decodes a want-status JSON answer into out. Any other status is a
// PermanentError.
func (c *Client) do(ctx context.Context, method, path string, body []byte, want int, out any) error {
	endpoint := c.base.JoinPath(path).String()
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", "gzip")
		}
		req.Header.Set("Accept", "application/json")
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		resp, err := c.hc.Do(req)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
		case resp.StatusCode == want:
			derr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out)
			_ = resp.Body.Close()
			if derr != nil {
				return fmt.Errorf("decode answer: %w", derr)
			}
			return nil
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardedBytes))
			_ = resp.Body.Close()
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		default:
			p := readProblem(resp)
			return &PermanentError{Status: resp.StatusCode, Problem: p}
		}
		if attempt >= c.policy.Attempts {
			return fmt.Errorf("giving up after %d attempts: %w", attempt+1, err)
		}
		wait, ok := c.policy.Wait(attempt, hdr, c.clk.Now())
		if !ok {
			return fmt.Errorf("core asked to retry after %s: %w", wait, err)
		}
		if err := c.clk.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func readProblem(resp *http.Response) Problem {
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var p Problem
	if err := json.Unmarshal(b, &p); err != nil || p.Title == "" {
		p = Problem{Title: http.StatusText(resp.StatusCode), Status: resp.StatusCode, Detail: strings.TrimSpace(string(b))}
	}
	return p
}

// IsPermanent reports whether err is a PermanentError.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}
