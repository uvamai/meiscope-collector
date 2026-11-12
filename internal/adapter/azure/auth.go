package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// Authentication modes (setting "auth").
const (
	AuthClientCredentials = "client_credentials"
	AuthManagedIdentity   = "managed_identity"
)

// CredClientSecret is the credential purpose of the client secret.
const CredClientSecret = "client_secret"

const (
	loginURL = "https://login.microsoftonline.com"
	// imdsURL is the documented managed-identity token endpoint of the
	// Azure Instance Metadata Service. It is reached directly, never
	// through a proxy.
	imdsURL = "http://169.254.169.254/metadata/identity/oauth2/token"
)

var (
	guidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	vaultName     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)
)

// validateAuth checks the authentication settings without contacting
// anything.
func validateAuth(cfg adapter.Config) error {
	switch cfg.Setting("auth", AuthClientCredentials) {
	case AuthClientCredentials:
		if !tenantPattern.MatchString(cfg.Setting("tenant_id", "")) {
			return errors.New("tenant_id is required (a tenant GUID or domain) for client_credentials")
		}
		if !guidPattern.MatchString(cfg.Setting("client_id", "")) {
			return errors.New("client_id (application GUID) is required for client_credentials")
		}
		if _, ok := cfg.Credentials[CredClientSecret]; !ok {
			return fmt.Errorf("credentials.%s must name the credential reference of the client secret", CredClientSecret)
		}
	case AuthManagedIdentity:
		if id := cfg.Setting("client_id", ""); id != "" && !guidPattern.MatchString(id) {
			return errors.New("client_id of a user-assigned managed identity must be a GUID")
		}
	default:
		return fmt.Errorf("auth must be %s or %s", AuthClientCredentials, AuthManagedIdentity)
	}
	if v := cfg.Setting("rate_per_second", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err != nil || f <= 0 || f > 100 {
			return errors.New("rate_per_second must be a number in (0, 100]")
		}
	}
	return nil
}

type cachedToken struct {
	v   credential.Secret
	exp time.Time
}

// tokenSource obtains and caches access tokens per scope for one sync.
type tokenSource struct {
	cfg  adapter.Config
	env  adapter.Env
	hc   *http.Client
	imds *http.Client

	mu    sync.Mutex
	cache map[string]cachedToken
}

func newTokenSource(cfg adapter.Config, env adapter.Env, hc *http.Client) *tokenSource {
	return &tokenSource{cfg: cfg, env: env, hc: hc, imds: directClient(hc), cache: map[string]cachedToken{}}
}

// directClient is hc without a proxy, for the link-local metadata service.
func directClient(hc *http.Client) *http.Client {
	c := *hc
	switch t := hc.Transport.(type) {
	case *http.Transport:
		tt := t.Clone()
		tt.Proxy = nil
		c.Transport = tt
	case nil:
		tt := http.DefaultTransport.(*http.Transport).Clone()
		tt.Proxy = nil
		c.Transport = tt
	default:
		// A test transport: use it as it is.
	}
	return &c
}

func (ts *tokenSource) forget(scope string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.cache, scope)
}

// token returns a token for scope, from the cache while it has more than
// five minutes left.
func (ts *tokenSource) token(ctx context.Context, scope string) (credential.Secret, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := ts.env.Clock.Now()
	if t, ok := ts.cache[scope]; ok && now.Add(5*time.Minute).Before(t.exp) {
		return t.v, nil
	}
	var (
		t   cachedToken
		err error
	)
	if ts.cfg.Setting("auth", AuthClientCredentials) == AuthManagedIdentity {
		t, err = ts.managedIdentity(ctx, scope, now)
	} else {
		t, err = ts.clientCredentials(ctx, scope, now)
	}
	if err != nil {
		return credential.Secret{}, err
	}
	ts.cache[scope] = t
	return t.v, nil
}

// tokenAnswer is the token endpoints' answer. expires_in is a number from
// Entra ID and a string from IMDS.
type tokenAnswer struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	Error       string          `json:"error"`
}

func (a tokenAnswer) lifetime() time.Duration {
	s := strings.Trim(string(a.ExpiresIn), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(n) * time.Second
}

// errorCode keeps only a short OAuth error code from an answer (for example
// "invalid_client"); descriptions are not repeated.
var errorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (ts *tokenSource) clientCredentials(ctx context.Context, scope string, now time.Time) (cachedToken, error) {
	sec, err := ts.cfg.Credential(ctx, ts.env.Creds, CredClientSecret)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: %w", ErrAuth, err)
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ts.cfg.Setting("client_id", "")},
		"client_secret": {sec.Reveal()},
		"scope":         {scope},
	}
	u := loginURL + "/" + url.PathEscape(ts.cfg.Setting("tenant_id", "")) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return ts.exchange(ts.hc, req, now, sec.Reveal())
}

func (ts *tokenSource) managedIdentity(ctx context.Context, scope string, now time.Time) (cachedToken, error) {
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {strings.TrimSuffix(scope, "/.default")}}
	if id := ts.cfg.Setting("client_id", ""); id != "" {
		q.Set("client_id", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsURL+"?"+q.Encode(), nil)
	if err != nil {
		return cachedToken{}, err
	}
	req.Header.Set("Metadata", "true")
	return ts.exchange(ts.imds, req, now)
}

func (ts *tokenSource) exchange(hc *http.Client, req *http.Request, now time.Time, known ...string) (cachedToken, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: token request to %s: %s", ErrAuth, req.URL.Host, adapter.Redact(err.Error(), known...))
	}
	defer func() { _ = resp.Body.Close() }()
	if rerr := redirect.Check(resp); rerr != nil {
		return cachedToken{}, fmt.Errorf("%w: token request to %s: %w", ErrAuth, req.URL.Host, rerr)
	}
	var a tokenAnswer
	derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&a)
	if resp.StatusCode != http.StatusOK || derr != nil || a.AccessToken == "" {
		code := "none"
		if errorCode.MatchString(a.Error) {
			code = a.Error
		}
		return cachedToken{}, fmt.Errorf("%w: token request to %s: HTTP %d (error %s)", ErrAuth, req.URL.Host, resp.StatusCode, code)
	}
	return cachedToken{v: credential.NewSecret(a.AccessToken), exp: now.Add(a.lifetime())}, nil
}
