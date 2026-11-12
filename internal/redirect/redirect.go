// Package redirect makes the collector's HTTP clients refuse redirects.
//
// The collector talks only to URLs the operator configured (the core, a CT
// service, an adapter's API). A redirect would send the request again, with
// its body and, for a same-host redirect, its Authorization header, to a
// place nobody configured. So no client follows one: CheckRedirect hands the
// 3xx answer back to the caller (http.ErrUseLastResponse), and the caller
// turns it into an error with Check.
package redirect

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrRefused is wrapped by every error Check returns.
var ErrRefused = errors.New("redirects are not followed")

// Refuse is an http.Client CheckRedirect that never follows a redirect: the
// client returns the 3xx answer itself, unread.
func Refuse(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Client returns a shallow copy of hc that refuses redirects, or nil when
// hc is nil. The caller's client is not changed.
func Client(hc *http.Client) *http.Client {
	if hc == nil {
		return nil
	}
	c := *hc
	c.CheckRedirect = Refuse
	return &c
}

// Is reports whether resp is a redirect answer (3xx other than 304 Not
// Modified).
func Is(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.StatusCode != http.StatusNotModified
}

// Check returns an error wrapping ErrRefused when resp is a redirect, and
// nil otherwise. The message names the status and the target's scheme and
// host only: a Location query may carry tokens or customer names.
func Check(resp *http.Response) error {
	if !Is(resp) {
		return nil
	}
	target := "an unknown location"
	if loc, err := resp.Location(); err == nil && loc.Host != "" {
		target = loc.Scheme + "://" + loc.Host
	}
	return fmt.Errorf("HTTP %d redirect to %s not followed: %w; check the configured URL", resp.StatusCode, target, ErrRefused)
}
