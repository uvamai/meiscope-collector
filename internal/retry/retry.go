// Package retry holds the collector's back-off policy for outbound HTTP:
// exponential back-off on 429 and 5xx, and Retry-After honoured.
package retry

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Policy is an exponential back-off policy.
type Policy struct {
	// Attempts is the maximum number of retries after the first try.
	Attempts int
	// Base is the delay before the first retry; it doubles on each retry.
	Base time.Duration
	// Max caps the exponential delay.
	Max time.Duration
	// MaxRetryAfter is the longest Retry-After the caller will wait for; a
	// longer one ends the retries (the caller reports the failure and tries
	// again next cycle). Zero means Max.
	MaxRetryAfter time.Duration
}

// Delay returns the exponential delay before retry n (0 for the first retry).
func (p Policy) Delay(n int) time.Duration {
	d := p.Base
	for i := 0; i < n; i++ {
		d *= 2
		if p.Max > 0 && d >= p.Max {
			return p.Max
		}
	}
	if p.Max > 0 && d > p.Max {
		return p.Max
	}
	return d
}

// Wait returns how long to wait before retry n given the response headers
// (nil when the attempt failed without a response), and false when the
// caller should stop retrying because the server asked for a longer wait
// than MaxRetryAfter.
func (p Policy) Wait(n int, h http.Header, now time.Time) (time.Duration, bool) {
	if ra, ok := ParseRetryAfter(h, now); ok {
		limit := p.MaxRetryAfter
		if limit == 0 {
			limit = p.Max
		}
		if ra > limit {
			return ra, false
		}
		// Never retry sooner than our own back-off schedule would.
		return max(ra, p.Delay(n)), true
	}
	return p.Delay(n), true
}

// Retryable reports whether an HTTP status is worth retrying: 429 and 5xx
// except 501 (not implemented) and 505 (version not supported).
func Retryable(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status != http.StatusNotImplemented && status != http.StatusHTTPVersionNotSupported
}

// ParseRetryAfter parses a Retry-After header (delay-seconds or HTTP-date; RFC
// 9110 section 10.2.3). It also accepts dates written with "UTC" instead of
// "GMT", which some CT logs send.
func ParseRetryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	if h == nil {
		return 0, false
	}
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	t, err := http.ParseTime(v)
	if err != nil {
		t, err = time.Parse(time.RFC1123, v)
		if err != nil {
			return 0, false
		}
	}
	if d := t.Sub(now); d > 0 {
		return d, true
	}
	return 0, true
}
