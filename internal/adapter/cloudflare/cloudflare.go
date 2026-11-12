// Package cloudflare is the read-only Cloudflare adapter (FR-DISC-030):
// per zone, the edge certificate packs (Cloudflare-managed) and custom
// (uploaded) certificates with their hostnames, and the zone's Origin CA
// certificates. It reads the Cloudflare API v4 with an API token resolved
// just in time from credential.Source, uses GET requests only, and never
// connects to anything but the API host.
//
// Its observations use the proposed cloud_resource target
// (api/proposed/collector-0.10.0-proposed.yaml) and are sent only when
// MEISCOPE_FEATURE_CLOUD_RESOURCE_V1 is on.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Registry name, evidence source and provider of the adapter.
const (
	Name     = "cloudflare"
	Source   = "cloudflare"
	Provider = "cloudflare"
)

// DefaultBaseURL is the Cloudflare API v4.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// CredAPIToken is the credential purpose of the API token.
const CredAPIToken = "api_token" //nolint:gosec // a purpose name, not a credential

// ErrAuth marks an answer that says the token was refused or lacks a
// permission (HTTP 401 or 403). It is not retried.
var ErrAuth = errors.New("the Cloudflare API refused the token or the permission (needs Zone:Read and SSL and Certificates:Read)")

var (
	zoneIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	cfRetry       = retry.Policy{Attempts: 5, Base: time.Second, Max: 30 * time.Second, MaxRetryAfter: 5 * time.Minute}
)

const (
	perPage = 50
	maxBody = 64 << 20
)

// managedPackTypes are certificate pack types Cloudflare issues and renews.
var managedPackTypes = map[string]bool{"universal": true, "advanced": true, "total_tls": true}

func init() {
	adapter.Register(Name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env} })
}

// Adapter is the Cloudflare adapter.
type Adapter struct {
	env adapter.Env
}

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    Name,
		Source:  Source,
		Summary: "Cloudflare edge certificate packs, custom certificates and Origin CA certificates (read-only API)",
		Settings: []string{
			"zones (comma-separated zone IDs; default every zone the token can read)",
			"origin_ca (true|false, default true)",
			"rate_per_second (default 4), refresh_hours (default 24, 0 = only changes), max_pages (default 10000)",
		},
		Credentials: []string{"api_token (Zone:Read, SSL and Certificates:Read)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	for _, z := range splitList(cfg.Setting("zones", "")) {
		if !zoneIDPattern.MatchString(z) {
			return fmt.Errorf("cloudflare: %q is not a zone ID (32 lower-case hex characters)", z)
		}
	}
	if _, ok := cfg.Credentials[CredAPIToken]; !ok {
		return errors.New("cloudflare: credentials.api_token (a credential reference) is required")
	}
	if v := cfg.Setting("origin_ca", ""); v != "" {
		if _, err := strconv.ParseBool(v); err != nil {
			return errors.New("cloudflare: origin_ca must be true or false")
		}
	}
	if v := cfg.Setting("rate_per_second", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err != nil || f <= 0 || f > 20 {
			return errors.New("cloudflare: rate_per_second must be a number in (0, 20]")
		}
	}
	if err := intIn(cfg, "refresh_hours", 0, 24*365); err != nil {
		return err
	}
	return intIn(cfg, "max_pages", 1, adapter.DefaultMaxPages)
}

type envelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfCert struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	Issuer    string   `json:"issuer"`
	Status    string   `json:"status"`
	Serial    string   `json:"serial_number"`
	ExpiresOn cfTime   `json:"expires_on"`
}

// cfTime accepts the timestamp forms the API uses (RFC 3339, and the
// "2006-01-02 15:04:05.999999 -0700 MST" form of some endpoints); an
// unparseable or empty value is the zero time rather than an error.
type cfTime struct{ time.Time }

func (t *cfTime) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999Z07:00"} {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v
			return nil
		}
	}
	return nil
}

type certPack struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Hosts                []string `json:"hosts"`
	Status               string   `json:"status"`
	CertificateAuthority string   `json:"certificate_authority"`
	PrimaryCertificate   string   `json:"primary_certificate"`
	Certificates         []cfCert `json:"certificates"`
}

type originCert struct {
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"`
	Hostnames   []string `json:"hostnames"`
	ExpiresOn   string   `json:"expires_on"`
	RequestType string   `json:"request_type"`
}

type client struct {
	base  *url.URL
	hc    *http.Client
	token credential.Secret
	clk   clock.Clock
	lim   *adapter.Limiter
	pages int
}

// APIError is a non-successful Cloudflare answer: path and status only.
type APIError struct {
	Path   string
	Status int
}

// Error names the path and status.
func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare: GET %s: HTTP %d", e.Path, e.Status)
}

// Unwrap makes errors.Is(err, ErrAuth) true for 401 and 403.
func (e *APIError) Unwrap() error {
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return ErrAuth
	}
	return nil
}

// get performs one authenticated GET with rate limiting and retries.
func (c *client) get(ctx context.Context, path string, q url.Values) (envelope, error) {
	u := c.base.JoinPath(path)
	u.RawQuery = q.Encode()
	for attempt := 0; ; attempt++ {
		if err := c.lim.Wait(ctx); err != nil {
			return envelope{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return envelope{}, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.token.Reveal())
		resp, err := c.hc.Do(req)
		var (
			hdr     http.Header
			lastErr error
		)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return envelope{}, ctx.Err()
			}
			lastErr = fmt.Errorf("cloudflare: GET %s: %s", path, adapter.Redact(err.Error(), c.token.Reveal()))
		case resp.StatusCode == http.StatusOK:
			var env envelope
			derr := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&env)
			_ = resp.Body.Close()
			if derr != nil {
				return envelope{}, fmt.Errorf("cloudflare: GET %s: decode: %w", path, derr)
			}
			if !env.Success {
				return envelope{}, fmt.Errorf("cloudflare: GET %s: success false", path)
			}
			return env, nil
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			lastErr = &APIError{Path: path, Status: resp.StatusCode}
		default:
			_ = resp.Body.Close()
			return envelope{}, &APIError{Path: path, Status: resp.StatusCode}
		}
		if attempt >= cfRetry.Attempts {
			return envelope{}, fmt.Errorf("giving up after %d attempts: %w", attempt+1, lastErr)
		}
		wait, ok := cfRetry.Wait(attempt, hdr, c.clk.Now())
		if !ok {
			return envelope{}, lastErr
		}
		if err := c.clk.Sleep(ctx, wait); err != nil {
			return envelope{}, err
		}
	}
}

// list pages through a list endpoint (page / per_page / result_info).
func list[T any](ctx context.Context, c *client, path string, q url.Values) ([]T, error) {
	return adapter.Paginate(ctx, c.pages, func(ctx context.Context, token string) (adapter.Page[T], error) {
		page := 1
		if token != "" {
			page, _ = strconv.Atoi(token)
		}
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("page", strconv.Itoa(page))
		qq.Set("per_page", strconv.Itoa(perPage))
		env, err := c.get(ctx, path, qq)
		if err != nil {
			return adapter.Page[T]{}, err
		}
		var items []T
		if err := json.Unmarshal(env.Result, &items); err != nil {
			return adapter.Page[T]{}, fmt.Errorf("cloudflare: GET %s: decode result: %w", path, err)
		}
		p := adapter.Page[T]{Items: items}
		if env.ResultInfo != nil && env.ResultInfo.TotalPages > page {
			p.Next = strconv.Itoa(page + 1)
		}
		return p, nil
	})
}

// Sync reads every zone and returns the resources that changed since the
// cursor (all of them every refresh_hours).
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	token, err := cfg.Credential(ctx, a.env.Creds, CredAPIToken)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("cloudflare: %w", err)
	}
	clk := a.env.Clock
	if clk == nil {
		clk = clock.System{}
	}
	hc := a.env.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	rate := 4.0
	if v, err := strconv.ParseFloat(cfg.Setting("rate_per_second", ""), 64); err == nil && v > 0 {
		rate = v
	}
	base, _ := url.Parse(DefaultBaseURL)
	c := &client{base: base, hc: hc, token: token, clk: clk, lim: adapter.NewLimiter(clk, rate), pages: intSetting(cfg, "max_pages", 0)}
	now := clk.Now().UTC()
	originCA := cfg.Setting("origin_ca", "true") != "false"

	zones, err := a.zones(ctx, c, cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	host := base.Hostname()
	var obs []submit.Observation
	for _, z := range zones {
		packs, err := list[certPack](ctx, c, "zones/"+z.ID+"/ssl/certificate_packs", url.Values{"status": {"all"}})
		if err != nil {
			return adapter.Result{}, err
		}
		for _, p := range packs {
			obs = append(obs, packObservation(host, z, p, now))
		}
		customs, err := list[cfCert](ctx, c, "zones/"+z.ID+"/custom_certificates", nil)
		if err != nil {
			return adapter.Result{}, err
		}
		for _, cc := range customs {
			obs = append(obs, customObservation(host, z, cc, now))
		}
		if originCA {
			origins, err := list[originCert](ctx, c, "certificates", url.Values{"zone_id": {z.ID}})
			if err != nil {
				return adapter.Result{}, err
			}
			for _, oc := range origins {
				o, err := originObservation(host, z, oc, now)
				if err != nil {
					return adapter.Result{}, err
				}
				obs = append(obs, o)
			}
		}
	}
	st := map[string]int{cloud.StatObserved: len(obs)}
	out, next, err := cloud.Filter(since, obs, now, time.Duration(intSetting(cfg, "refresh_hours", 24))*time.Hour, st)
	if err != nil {
		return adapter.Result{}, err
	}
	return cloud.Finish(a.env, Name, cfg, out, st, since, next), nil
}

func (a *Adapter) zones(ctx context.Context, c *client, cfg adapter.Config) ([]zone, error) {
	if ids := splitList(cfg.Setting("zones", "")); len(ids) > 0 {
		out := make([]zone, 0, len(ids))
		for _, id := range ids {
			out = append(out, zone{ID: id})
		}
		return out, nil
	}
	return list[zone](ctx, c, "zones", nil)
}

// Resource types of the observed resources.
const (
	TypeCertificatePack   = "Cloudflare::CertificatePack"
	TypeCustomCertificate = "Cloudflare::CustomCertificate"
	TypeOriginCA          = "Cloudflare::OriginCACertificate"
)

// target locates a zone's certificate: resource_id is "<zone ID>/<ID>".
func target(host, resourceType, id string, z zone) submit.Target {
	return submit.Target{
		Kind: submit.KindCloudResource, Host: host,
		Provider: Provider, ResourceID: z.ID + "/" + id, ResourceType: resourceType,
	}
}

// edgeBindings are the host names Cloudflare's edge serves a certificate
// for, as configured on the zone (resource_id is the zone ID).
func edgeBindings(hosts []string, z zone) []submit.Binding {
	var out []submit.Binding
	for _, h := range cloud.Hostnames(hosts) {
		if len(out) == cloud.MaxBindings {
			break
		}
		out = append(out, submit.Binding{Hostname: h, ResourceID: z.ID})
	}
	return out
}

// packObservation maps an edge certificate pack. The API returns
// certificate metadata, not the certificate, so the outcome is reached.
// Cloudflare issues and renews universal, advanced and total TLS packs.
func packObservation(host string, z zone, p certPack, now time.Time) submit.Observation {
	ev := &submit.AdapterEvidence{
		Source:      Source,
		RenewalMode: submit.RenewalUnknown,
		Bindings:    edgeBindings(p.Hosts, z),
	}
	if managedPackTypes[p.Type] {
		ev.RenewalMode = submit.RenewalExternalAutomated
	}
	cc := &submit.CloudCertificate{ID: p.ID, Type: p.Type, Status: clip(p.Status, 64), Issuer: p.CertificateAuthority, Hostnames: cloud.Hostnames(p.Hosts)}
	for _, c := range p.Certificates {
		if c.ID == p.PrimaryCertificate || (p.PrimaryCertificate == "" && cc.NotAfter == nil) {
			if c.Issuer != "" {
				cc.Issuer = c.Issuer
			}
			cc.Serial, cc.NotAfter = clip(c.Serial, 128), cloud.TimePtr(c.ExpiresOn.Time)
		}
	}
	ev.CloudCertificate = cc
	return submit.Observation{Target: target(host, TypeCertificatePack, p.ID, z), Method: submit.MethodAdapter, ObservedAt: now, Outcome: submit.OutcomeReached, Adapter: ev}
}

// customObservation maps an uploaded custom certificate: the customer
// uploads and replaces it, so renewal is manual.
func customObservation(host string, z zone, c cfCert, now time.Time) submit.Observation {
	return submit.Observation{
		Target: target(host, TypeCustomCertificate, c.ID, z), Method: submit.MethodAdapter, ObservedAt: now, Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:      Source,
			RenewalMode: submit.RenewalManual,
			Bindings:    edgeBindings(c.Hosts, z),
			CloudCertificate: &submit.CloudCertificate{
				ID: c.ID, Type: "custom", Status: clip(c.Status, 64), Issuer: c.Issuer, Serial: clip(c.Serial, 128),
				NotAfter: cloud.TimePtr(c.ExpiresOn.Time), Hostnames: cloud.Hostnames(c.Hosts),
			},
		},
	}
}

// originObservation maps an Origin CA certificate. The API returns the
// public certificate (never a key), so the outcome is cert_seen. It is
// installed on the customer's origin, not served by the edge: no bindings.
func originObservation(host string, z zone, oc originCert, now time.Time) (submit.Observation, error) {
	o := submit.Observation{
		Target: target(host, TypeOriginCA, oc.ID, z), Method: submit.MethodAdapter, ObservedAt: now, Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:           Source,
			RenewalMode:      submit.RenewalManual,
			CloudCertificate: &submit.CloudCertificate{ID: oc.ID, Type: oc.RequestType, Hostnames: cloud.Hostnames(oc.Hostnames)},
		},
	}
	chain, err := cloud.ParsePEMChain(oc.Certificate)
	if err != nil {
		return submit.Observation{}, fmt.Errorf("cloudflare: origin certificate %s: %w", oc.ID, err)
	}
	if len(chain) > 0 {
		m, err := cloud.Metadata(chain[0])
		if err != nil {
			return submit.Observation{}, err
		}
		o.Outcome, o.ServedChain, o.Adapter.Certificate = submit.OutcomeCertSeen, chain, m
		o.Adapter.CloudCertificate.NotAfter = m.NotAfter
	}
	return o, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func intSetting(cfg adapter.Config, name string, def int) int {
	n, err := strconv.Atoi(cfg.Setting(name, ""))
	if err != nil {
		return def
	}
	return n
}

func intIn(cfg adapter.Config, name string, lo, hi int) error {
	v := cfg.Setting(name, "")
	if v == "" {
		return nil
	}
	if n, err := strconv.Atoi(v); err != nil || n < lo || n > hi {
		return fmt.Errorf("cloudflare: %s must be an integer in [%d, %d]", name, lo, hi)
	}
	return nil
}
