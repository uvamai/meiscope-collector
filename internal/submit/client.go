// Package submit sends observations to the core: POST
// /collector/v1/observations with gzip-compressed JSON batches of at most
// 1000 observations, retried with back-off (ADR-0005).
package submit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// ObservationsPath is the endpoint below the core base URL.
const ObservationsPath = "/collector/v1/observations"

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
	c := &Client{base: u, hc: hc, clk: clock.System{}, policy: DefaultRetry, batch: MaxBatch, maxWire: MaxWireBytes}
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
}

// PermanentError is a 4xx answer that retrying cannot fix.
type PermanentError struct {
	Status  int
	Problem Problem
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("core refused the batch: HTTP %d %s %s", e.Status, e.Problem.Title, e.Problem.Detail)
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
		res.Rejected = append(res.Rejected, r)
	}
	return nil
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
	endpoint := c.base.JoinPath(ObservationsPath).String()
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return ObservationBatchResult{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Accept", "application/json")
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		resp, err := c.hc.Do(req)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ObservationBatchResult{}, ctx.Err()
			}
		case resp.StatusCode == http.StatusAccepted:
			var out ObservationBatchResult
			derr := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out)
			_ = resp.Body.Close()
			if derr != nil {
				return ObservationBatchResult{}, fmt.Errorf("decode batch result: %w", derr)
			}
			return out, nil
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		default:
			p := readProblem(resp)
			return ObservationBatchResult{}, &PermanentError{Status: resp.StatusCode, Problem: p}
		}
		if attempt >= c.policy.Attempts {
			return ObservationBatchResult{}, fmt.Errorf("submit observations: giving up after %d attempts: %w", attempt+1, err)
		}
		wait, ok := c.policy.Wait(attempt, hdr, c.clk.Now())
		if !ok {
			return ObservationBatchResult{}, fmt.Errorf("submit observations: core asked to retry after %s: %w", wait, err)
		}
		if err := c.clk.Sleep(ctx, wait); err != nil {
			return ObservationBatchResult{}, err
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
