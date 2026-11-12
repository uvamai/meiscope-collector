// Package azure holds read-only adapters for Microsoft cloud services
// (WP1.2, FR-DISC-024..026, FR-DISC-030): Azure Key Vault certificates and
// certificate-bearing secrets, App Gateway listener certificates, App
// Service bound certificates, Entra ID application credentials and the
// Defender Vulnerability Management certificate inventory.
//
// The adapters call the documented REST APIs with plain net/http. They only
// read; they never scan networks or connect to anything but the Microsoft
// endpoints named here. Access tokens come from client credentials (the
// client secret resolved just in time through credential.Source) or from a
// managed identity; a token lives in memory for one sync only, is never
// logged, never written to disk and never sent to a host other than the API
// it was issued for.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// API hosts and token scopes (Azure public cloud).
const (
	armHost   = "management.azure.com"
	graphHost = "graph.microsoft.com"
	// vaultSuffix is the DNS suffix of Key Vault data-plane hosts.
	vaultSuffix = ".vault.azure.net"

	scopeARM   = "https://management.azure.com/.default"
	scopeGraph = "https://graph.microsoft.com/.default"
	scopeVault = "https://vault.azure.net/.default"

	maxBody = 64 << 20
)

// ErrAuth marks a sync that failed because the identity could not get a
// token or lacks a permission. It is not retried.
var ErrAuth = errors.New("azure: authentication or authorisation failed")

var apiRetry = retry.Policy{Attempts: 4, Base: time.Second, Max: 30 * time.Second, MaxRetryAfter: 5 * time.Minute}

// Statistic keys common to the Azure adapters.
const (
	StatThrottled              = "throttled"
	StatSkippedFeatureDisabled = "skipped_feature_disabled"
	StatUnchanged              = "unchanged"
)

// statusError is a non-retryable HTTP answer. It names the method, the URL
// path and the status, never a query string, header or body.
type statusError struct {
	method, path string
	status       int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("azure: %s %s: HTTP %d", e.method, e.path, e.status)
}

func (e *statusError) Unwrap() error {
	if e.status == http.StatusUnauthorized || e.status == http.StatusForbidden {
		return ErrAuth
	}
	return nil
}

// allowedHost reports whether a token for scope may be sent to host. It
// stops a nextLink or deltaLink from steering a token anywhere else.
func allowedHost(scope, host string) bool {
	host = strings.ToLower(host)
	switch scope {
	case scopeARM:
		return host == armHost
	case scopeGraph:
		return host == graphHost
	case scopeVault:
		name, ok := strings.CutSuffix(host, vaultSuffix)
		return ok && vaultName.MatchString(name)
	}
	return false
}

// client performs authenticated, rate-limited, retried API calls.
type client struct {
	hc    *http.Client
	ts    *tokenSource
	lim   *adapter.Limiter
	env   adapter.Env
	stats map[string]int
}

func checkURL(raw, scope string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("azure: invalid API URL")
	}
	if u.Scheme != "https" || u.User != nil || !allowedHost(scope, u.Hostname()) || (u.Port() != "" && u.Port() != "443") {
		return nil, fmt.Errorf("azure: refusing to send a token to %s://%s (not the API host of its scope)", u.Scheme, u.Host)
	}
	return u, nil
}

// get decodes the JSON answer of a GET into out.
func (c *client) get(ctx context.Context, raw, scope string, out any) error {
	return c.do(ctx, http.MethodGet, raw, scope, nil, out)
}

// do performs one call with retries: 429 and 5xx are retried honouring
// Retry-After; a 401 refreshes the token once; other answers are final.
func (c *client) do(ctx context.Context, method, raw, scope string, body []byte, out any) error {
	u, err := checkURL(raw, scope)
	if err != nil {
		return err
	}
	clk := c.env.Clock
	refreshed := false
	for attempt := 0; ; attempt++ {
		if err := c.lim.Wait(ctx); err != nil {
			return err
		}
		tok, err := c.ts.token(ctx, scope)
		if err != nil {
			return err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+tok.Reveal())
		resp, err := c.hc.Do(req)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("azure: %s %s: %s", method, u.Path, adapter.Redact(err.Error(), tok.Reveal()))
		case resp.StatusCode == http.StatusOK:
			derr := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
			_ = resp.Body.Close()
			if derr != nil {
				return fmt.Errorf("azure: %s %s: decode: %w", method, u.Path, derr)
			}
			return nil
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			drain(resp)
			refreshed = true
			c.ts.forget(scope)
			continue
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			if resp.StatusCode == http.StatusTooManyRequests {
				c.stats[StatThrottled]++
			}
			drain(resp)
			err = &statusError{method: method, path: u.Path, status: resp.StatusCode}
		default:
			drain(resp)
			return &statusError{method: method, path: u.Path, status: resp.StatusCode}
		}
		if attempt >= apiRetry.Attempts {
			return fmt.Errorf("giving up after %d attempts: %w", attempt+1, err)
		}
		wait, ok := apiRetry.Wait(attempt, hdr, clk.Now())
		if !ok {
			return fmt.Errorf("server asked to wait %s, longer than allowed: %w", wait, err)
		}
		if err := clk.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// listPage is the paging envelope of ARM, Key Vault and Graph lists.
type listPage[T any] struct {
	Value      []T    `json:"value"`
	NextLink   string `json:"nextLink"`
	ODataNext  string `json:"@odata.nextLink"`
	ODataDelta string `json:"@odata.deltaLink"`
}

// listAll follows nextLink (or @odata.nextLink) from first and returns the
// items and the @odata.deltaLink of the last page, if any. Every link is
// checked against the scope's API host before a token goes with it.
func listAll[T any](ctx context.Context, c *client, first, scope string) ([]T, string, error) {
	var delta string
	items, err := adapter.Paginate(ctx, 0, func(ctx context.Context, token string) (adapter.Page[T], error) {
		u := first
		if token != "" {
			u = token
		}
		var p listPage[T]
		if err := c.get(ctx, u, scope, &p); err != nil {
			return adapter.Page[T]{}, err
		}
		next := p.NextLink
		if next == "" {
			next = p.ODataNext
		}
		if p.ODataDelta != "" {
			delta = p.ODataDelta
		}
		return adapter.Page[T]{Items: p.Value, Next: next}, nil
	})
	return items, delta, err
}
