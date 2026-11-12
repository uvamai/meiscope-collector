package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// StatusError is a non-retryable HTTP answer of the system an adapter reads.
// It names the path and status only, never a credential.
type StatusError struct {
	Path   string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.Path, e.Status) }

// IsStatus reports whether err is a StatusError with one of the statuses.
func IsStatus(err error, statuses ...int) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	for _, s := range statuses {
		if se.Status == s {
			return true
		}
	}
	return false
}

// NoRedirect is an http.Client CheckRedirect that refuses every redirect:
// the 3xx answer is returned as is (Getter reports it as a StatusError), so
// a bearer credential never follows a redirect to another host or scheme.
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ErrBodyTooLarge is returned when a response is larger than the limit.
var ErrBodyTooLarge = errors.New("response body exceeds the adapter's size limit")

// Getter performs read-only GET requests for an adapter: rate limited,
// retried on 429 and 5xx with Retry-After honoured, with an optional bearer
// credential that never appears in an error. It never follows a redirect,
// whatever the client's own CheckRedirect says.
type Getter struct {
	HTTP    *http.Client
	Env     Env
	Limiter *Limiter
	Policy  retry.Policy
	// Bearer is sent as "Authorization: Bearer"; empty sends none.
	Bearer credential.Secret
	// MaxBody bounds a response body (0: 64 MiB).
	MaxBody int64
}

// DefaultRetry is the retry policy of Getter when Policy is zero.
var DefaultRetry = retry.Policy{Attempts: 3, Base: time.Second, Max: 30 * time.Second, MaxRetryAfter: 2 * time.Minute}

// Get fetches u with the Accept header and returns the body.
func (g *Getter) Get(ctx context.Context, u *url.URL, accept string) ([]byte, error) {
	pol := g.Policy
	if pol.Attempts == 0 && pol.Base == 0 {
		pol = DefaultRetry
	}
	limit := g.MaxBody
	if limit <= 0 {
		limit = 64 << 20
	}
	hc := &http.Client{Timeout: time.Minute}
	if g.HTTP != nil {
		c := *g.HTTP
		hc = &c
	}
	hc.CheckRedirect = NoRedirect
	path := u.Path
	for attempt := 0; ; attempt++ {
		if err := g.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if !g.Bearer.Empty() {
			req.Header.Set("Authorization", "Bearer "+g.Bearer.Reveal())
		}
		resp, err := hc.Do(req)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			err = fmt.Errorf("GET %s: %s", path, Redact(err.Error(), g.Bearer.Reveal()))
		case resp.StatusCode == http.StatusOK:
			b, rerr := readBody(resp, limit)
			_ = resp.Body.Close()
			if rerr != nil {
				return nil, fmt.Errorf("GET %s: read: %s", path, Redact(rerr.Error(), g.Bearer.Reveal()))
			}
			if int64(len(b)) > limit {
				return nil, fmt.Errorf("GET %s: %w (%d bytes)", path, ErrBodyTooLarge, limit)
			}
			return b, nil
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			err = &StatusError{Path: path, Status: resp.StatusCode}
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			return nil, &StatusError{Path: path, Status: resp.StatusCode}
		}
		if attempt >= pol.Attempts {
			return nil, fmt.Errorf("giving up after %d attempts: %w", attempt+1, err)
		}
		wait, ok := pol.Wait(attempt, hdr, g.Env.Clock.Now())
		if !ok {
			return nil, err
		}
		if err := g.Env.Clock.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// readBody reads at most limit+1 bytes. With a declared Content-Length
// within the limit the body is read into one buffer of that size, so no
// intermediate copies of it are left behind for the garbage collector
// (callers that zero the result zero the only copy).
func readBody(resp *http.Response, limit int64) ([]byte, error) {
	if n := resp.ContentLength; n > 0 && n <= limit {
		b := make([]byte, n)
		_, err := io.ReadFull(resp.Body, b)
		return b, err
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit+1))
}
