package cloudflare_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloudflare"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

const (
	// testValue is a synthetic, low-entropy stand-in for the API token.
	testValue = "synthetic-cf-cccccccccccccccccccccccccccc"
	zoneA     = "0123456789abcdef0123456789abcdef"
	zoneB     = "fedcba9876543210fedcba9876543210"
	packA     = "3822ff90-ea29-44df-9e55-21300bb9419b"
	packB     = "a77f8bd7-3b47-46b4-a6f1-75cf98109948"
	customA   = "2458ce5a-0c35-4c7f-82c7-8e9487d3ff60"
	originA   = "328578533902268680212849205732770752308931942346"
)

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

func newEnv(rt http.RoundTripper) (adapter.Env, *clock.Fake, *bytes.Buffer) {
	var logs bytes.Buffer
	clk := clock.NewFake(t0)
	return adapter.Env{
		HTTP:     &http.Client{Transport: rt},
		Creds:    mapSource{"cf_ref": testValue},
		Clock:    clk,
		Log:      slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Features: adapter.Features{CloudResourceV1: true},
	}, clk, &logs
}

func config(settings map[string]string) adapter.Config {
	s := map[string]string{"rate_per_second": "20"}
	for k, v := range settings {
		s[k] = v
	}
	return adapter.Config{Name: "cf-prod", Adapter: cloudflare.Name, Settings: s, Credentials: map[string]string{"api_token": "cf_ref"}}
}

func load(t *testing.T, scenario string) *fixture.Transport {
	t.Helper()
	tr, err := fixture.Load(fixture.Dir("cloudflare", scenario))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func newAdapter(env adapter.Env) adapter.Adapter {
	f, ok := adapter.Lookup(cloudflare.Name)
	if !ok {
		panic("cloudflare not registered")
	}
	return f(env)
}

func syncOK(t *testing.T, a adapter.Adapter, cfg adapter.Config, since adapter.Cursor) adapter.Result {
	t.Helper()
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), cfg, since)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFullSync(t *testing.T) {
	tr := load(t, "synthetic-full")
	env, _, logs := newEnv(tr)
	res := syncOK(t, newAdapter(env), config(nil), "")
	if len(res.Observations) != 4 {
		t.Fatalf("%d observations, want 4", len(res.Observations))
	}
	m := map[string]submit.Observation{}
	for _, o := range res.Observations {
		m[o.Target.ResourceID] = o
		if o.Target.Host != "api.cloudflare.com" || o.Target.Provider != "cloudflare" || o.Target.Kind != submit.KindCloudResource || o.Adapter.Source != "cloudflare" {
			t.Errorf("target %+v", o.Target)
		}
	}
	pa := m[zoneA+"/"+packA]
	if pa.Outcome != submit.OutcomeReached || pa.Target.ResourceType != cloudflare.TypeCertificatePack || pa.Adapter.RenewalMode != submit.RenewalExternalAutomated {
		t.Fatalf("pack A %+v", pa)
	}
	if cc := pa.Adapter.CloudCertificate; cc.Serial != "0a1b2c3d4e5f" || cc.NotAfter == nil || !cc.NotAfter.Equal(time.Date(2026, 12, 30, 0, 0, 0, 0, time.UTC)) ||
		cc.Issuer != "Synthetic Edge CA" || cc.Type != "universal" || cc.Status != "active" || !slices.Equal(cc.Hostnames, []string{"*.example.test", "example.test"}) {
		t.Errorf("pack A certificate %+v", cc)
	}
	if !slices.Equal(pa.Adapter.Bindings, []submit.Binding{{Hostname: "*.example.test", ResourceID: zoneA}, {Hostname: "example.test", ResourceID: zoneA}}) {
		t.Errorf("pack A bindings %+v", pa.Adapter.Bindings)
	}
	if pb := m[zoneB+"/"+packB]; pb.Adapter.RenewalMode != submit.RenewalExternalAutomated || pb.Adapter.CloudCertificate.Status != "pending_validation" || len(pb.Adapter.Bindings) != 2 {
		t.Errorf("pack B %+v", pb.Adapter)
	}
	if c := m[zoneA+"/"+customA]; c.Target.ResourceType != cloudflare.TypeCustomCertificate || c.Adapter.RenewalMode != submit.RenewalManual || c.Adapter.CloudCertificate.NotAfter == nil {
		t.Errorf("custom %+v", c.Adapter)
	}
	o := m[zoneA+"/"+originA]
	if o.Outcome != submit.OutcomeCertSeen || len(o.ServedChain) != 1 || o.Adapter.Certificate.SHA1 != "20060e7eef4b19f3b041e4abe50173b9b57fbd9f" ||
		o.Adapter.RenewalMode != submit.RenewalManual || len(o.Adapter.Bindings) != 0 {
		t.Errorf("origin %+v", o)
	}

	// Pagination: both zone pages were read.
	var paths []string
	for _, r := range tr.Requests() {
		paths = append(paths, r.URL.Path+"?"+r.URL.Query().Get("page"))
		if r.Method != http.MethodGet || r.URL.Host != "api.cloudflare.com" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer "+testValue {
			t.Errorf("request without the token: %s", r.URL)
		}
	}
	if !slices.Contains(paths, "/client/v4/zones?1") || !slices.Contains(paths, "/client/v4/zones?2") {
		t.Errorf("zone pages %v", paths)
	}

	submitAll(t, res.Observations)
	b, _ := json.Marshal(res)
	for name, text := range map[string]string{"result": string(b), "logs": logs.String()} {
		if strings.Contains(text, testValue) || strings.Contains(text, "Bearer") {
			t.Errorf("%s leaks the token", name)
		}
	}
}

func submitAll(t *testing.T, obs []submit.Observation) {
	t.Helper()
	core, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Accepted != len(obs) {
		t.Fatalf("accepted %d of %d: %v", res.Accepted, len(obs), core.Rejected())
	}
}

func TestZonesSetting(t *testing.T) {
	tr := load(t, "synthetic-full")
	env, _, _ := newEnv(tr)
	res := syncOK(t, newAdapter(env), config(map[string]string{"zones": zoneB, "origin_ca": "false"}), "")
	if len(res.Observations) != 1 || res.Observations[0].Target.ResourceID != zoneB+"/"+packB {
		t.Fatalf("%+v", res.Observations)
	}
	for _, r := range tr.Requests() {
		if r.URL.Path == "/client/v4/zones" || r.URL.Path == "/client/v4/certificates" {
			t.Errorf("unexpected request %s", r.URL)
		}
	}
}

func TestDelta(t *testing.T) {
	env, clk, _ := newEnv(load(t, "synthetic-full"))
	a := newAdapter(env)
	first := syncOK(t, a, config(nil), "")
	second := syncOK(t, a, config(nil), first.Cursor)
	if len(second.Observations) != 0 || second.Stats[cloud.StatUnchanged] != 4 {
		t.Fatalf("second sync: %d, %v", len(second.Observations), second.Stats)
	}
	clk.Advance(24 * time.Hour)
	if r := syncOK(t, a, config(nil), second.Cursor); len(r.Observations) != 4 {
		t.Fatalf("refresh: %d", len(r.Observations))
	}
}

func TestFeatureOff(t *testing.T) {
	env, _, logs := newEnv(load(t, "synthetic-full"))
	env.Features = adapter.Features{}
	res := syncOK(t, newAdapter(env), config(nil), "")
	if len(res.Observations) != 0 || res.Cursor != "" || res.Stats[cloud.StatSkippedFeatureDisabled] != 4 {
		t.Fatalf("flag off: %+v", res)
	}
	if !strings.Contains(logs.String(), adapter.EnvCloudResourceV1) {
		t.Error("no warning")
	}
}

type limiter429 struct {
	next  http.RoundTripper
	mu    sync.Mutex
	left  int
	calls int
}

func (l *limiter429) RoundTrip(r *http.Request) (*http.Response, error) {
	l.mu.Lock()
	l.calls++
	if l.left > 0 {
		l.left--
		l.mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": {"2"}, "Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":971,"message":"Please wait and consider throttling your request speed"}]}`)),
			Request:    r,
		}, nil
	}
	l.mu.Unlock()
	return l.next.RoundTrip(r)
}

func TestThrottling(t *testing.T) {
	env, clk, _ := newEnv(&limiter429{next: load(t, "synthetic-full"), left: 2})
	res := syncOK(t, newAdapter(env), config(nil), "")
	if len(res.Observations) != 4 {
		t.Fatalf("%d", len(res.Observations))
	}
	var long []time.Duration
	for _, d := range clk.Sleeps() {
		if d >= time.Second {
			long = append(long, d)
		}
	}
	if !slices.Equal(long, []time.Duration{2 * time.Second, 2 * time.Second}) {
		t.Fatalf("sleeps %v", long)
	}

	always := &limiter429{next: load(t, "synthetic-full"), left: 100}
	env2, _, _ := newEnv(always)
	if _, err := newAdapter(env2).Sync(context.Background(), config(nil), ""); err == nil || errors.Is(err, cloudflare.ErrAuth) {
		t.Fatalf("persistent 429: %v", err)
	}
	if always.calls != 6 {
		t.Fatalf("%d attempts", always.calls)
	}
}

func TestAuthFailure(t *testing.T) {
	tr := load(t, "synthetic-auth-failure")
	env, _, logs := newEnv(tr)
	_, err := newAdapter(env).Sync(context.Background(), config(nil), "")
	if !errors.Is(err, cloudflare.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if len(tr.Requests()) != 1 {
		t.Errorf("retried an authentication failure")
	}
	if strings.Contains(err.Error(), testValue) || strings.Contains(logs.String(), testValue) {
		t.Error("token leaked")
	}
}

func TestValidate(t *testing.T) {
	a := newAdapter(adapter.Env{})
	if err := a.Validate(config(nil)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]adapter.Config{
		"bad zone":    config(map[string]string{"zones": "example.test"}),
		"bad origin":  config(map[string]string{"origin_ca": "maybe"}),
		"bad rate":    config(map[string]string{"rate_per_second": "500"}),
		"no token":    {Name: "x", Adapter: cloudflare.Name},
		"bad refresh": config(map[string]string{"refresh_hours": "-1"}),
	} {
		if err := a.Validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
