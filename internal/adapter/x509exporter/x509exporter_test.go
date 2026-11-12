package x509exporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/x509exporter"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

const scrapeCred = "eeee-ffff-gggg-test-only" //nolint:gosec // synthetic test value

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

// metricsServer serves the recorded metrics file for /metrics.
type metricsServer struct {
	body     []byte
	status   int
	requests []*http.Request
}

func (m *metricsServer) RoundTrip(r *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, r)
	st := m.status
	if st == 0 {
		st = http.StatusOK
	}
	if r.URL.Path != "/metrics" {
		st = http.StatusNotFound
	}
	return &http.Response{StatusCode: st, Header: http.Header{"Content-Type": {"text/plain; version=0.0.4"}}, Body: io.NopCloser(bytes.NewReader(m.body)), Request: r}, nil
}

func newServer(t *testing.T) *metricsServer {
	t.Helper()
	b, err := os.ReadFile(fixture.Dir(x509exporter.Name, "metrics.prom"))
	if err != nil {
		t.Fatal(err)
	}
	return &metricsServer{body: b}
}

func newAdapter(rt http.RoundTripper, f adapter.Features) (adapter.Adapter, *bytes.Buffer) {
	var logs bytes.Buffer
	fac, ok := adapter.Lookup(x509exporter.Name)
	if !ok {
		panic("not registered")
	}
	return fac(adapter.Env{
		HTTP:     &http.Client{Transport: rt},
		Creds:    mapSource{"exporter_token": scrapeCred},
		Clock:    clock.NewFake(t0),
		Log:      slog.New(slog.NewJSONHandler(&logs, nil)),
		Features: f,
	}), &logs
}

var on = adapter.Features{LocalStoreV1: true, AdapterEvidenceV2: true}

func config() adapter.Config {
	return adapter.Config{
		Name: "exporter", Adapter: x509exporter.Name,
		Settings:    map[string]string{"url": "https://exporter.example.test:9793/metrics", "host": "k8s.example.test", "cluster": "prod"},
		Credentials: map[string]string{"bearer_token": "exporter_token"},
	}
}

func run(t *testing.T, a adapter.Adapter, cfg adapter.Config, since adapter.Cursor) adapter.Result {
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

func TestScrape(t *testing.T) {
	srv := newServer(t)
	a, logs := newAdapter(srv, on)
	res := run(t, a, config(), "")
	for k, v := range map[string]int{
		x509exporter.StatSeries: 6, x509exporter.StatMalformedLines: 1, x509exporter.StatNoIdentity: 1,
		x509exporter.StatNoLocator: 1, x509exporter.StatNoNotAfter: 1, x509exporter.StatReadErrors: 2,
		x509exporter.StatSkippedFeatureDisabled: 0, x509exporter.StatUnchanged: 0,
	} {
		if res.Stats[k] != v {
			t.Errorf("stat %s = %d, want %d (%v)", k, res.Stats[k], v, res.Stats)
		}
	}
	if len(res.Observations) != 3 {
		t.Fatalf("%d observations", len(res.Observations))
	}
	got := map[string]submit.Observation{}
	for _, o := range res.Observations {
		got[o.Adapter.Certificate.CommonName] = o
		if o.Method != submit.MethodAdapter || o.Outcome != submit.OutcomeCertSeen || o.Target.Host != "k8s.example.test" ||
			o.Adapter.Source != "x509_certificate_exporter" || o.Adapter.Certificate.SHA1 != "" || o.Adapter.Custody.KeyCustody != submit.KeyUnknown {
			t.Errorf("observation %+v", o)
		}
	}
	www, api, ca := got["www.example.test"], got["api.example.test"], got["Synthetic Test CA"]
	if www.Target.Store != x509exporter.FileStore || www.Target.Path != "/etc/ssl/www/www.crt" || www.Adapter.Certificate.Serial != "2a01" ||
		www.Adapter.Certificate.Issuer != "CN=Synthetic Test CA,O=Synthetic Test" || www.Adapter.Certificate.NotAfter.Format(time.RFC3339) != "2025-11-30T00:00:00Z" ||
		www.Adapter.Certificate.NotBefore == nil {
		t.Errorf("www %+v %+v", www.Target, www.Adapter.Certificate)
	}
	if api.Target.Store != "kubernetes/prod/api/api-tls" || api.Target.Path != "" || api.Adapter.Certificate.Serial != "2a02" {
		t.Errorf("api %+v %+v", api.Target, api.Adapter.Certificate)
	}
	if ca.Adapter.Certificate.Issuer != `CN=Synthetic Test CA,O=Synthetic Test\, Inc` || ca.Adapter.Certificate.Serial != "1001" {
		t.Errorf("ca %+v", ca.Adapter.Certificate)
	}
	if r := srv.requests[0]; r.Header.Get("Authorization") != "Bearer "+scrapeCred || r.Method != http.MethodGet {
		t.Errorf("request %v", r.Header)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b)+logs.String(), scrapeCred) {
		t.Error("credential leaked")
	}

	// The identity by issuer and serial needs the proposal: the 0.9.0
	// contract refuses it, the 0.10.0 proposal accepts it.
	submitTo(t, submittest.Proposed010SpecPath(), res.Observations, true)
	submitTo(t, submittest.VendoredSpecPath(), res.Observations, false)

	// Delta: the same scrape again is unchanged.
	again := run(t, a, config(), res.Cursor)
	if len(again.Observations) != 0 || again.Stats[x509exporter.StatUnchanged] != 3 {
		t.Fatalf("second scrape %d observations, %v", len(again.Observations), again.Stats)
	}
}

func submitTo(t *testing.T, spec string, obs []submit.Observation, accept bool) {
	t.Helper()
	core, err := submittest.NewCoreWithSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), obs)
	if accept && (err != nil || res.Accepted != len(obs)) {
		t.Fatalf("%s: %+v %v %v", spec, res, err, core.Errors())
	}
	if !accept && err == nil {
		t.Fatalf("%s accepted observations without sha1", spec)
	}
}

func TestFeatureOff(t *testing.T) {
	for _, f := range []adapter.Features{{}, {LocalStoreV1: true}, {AdapterEvidenceV2: true}} {
		a, logs := newAdapter(newServer(t), f)
		res := run(t, a, config(), `{}`)
		if len(res.Observations) != 0 || res.Cursor != `{}` || res.Stats[x509exporter.StatSkippedFeatureDisabled] != 3 {
			t.Fatalf("%+v: %v %q %v", f, res.Observations, res.Cursor, res.Stats)
		}
		if !strings.Contains(logs.String(), adapter.EnvAdapterEvidenceV2) {
			t.Error("warning does not name the switch")
		}
	}
}

func TestForbidden(t *testing.T) {
	srv := newServer(t)
	srv.status = http.StatusForbidden
	a, _ := newAdapter(srv, on)
	if _, err := a.Sync(context.Background(), config(), ""); !adapter.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("error %v", err)
	}
}

func TestValidate(t *testing.T) {
	a, _ := newAdapter(nil, on)
	if err := a.Validate(config()); err != nil {
		t.Fatal(err)
	}
	httpCfg := config()
	httpCfg.Settings["url"] = "http://exporter.example.test:9793/metrics"
	if err := a.Validate(httpCfg); err == nil {
		t.Error("http without allow_http accepted")
	}
	httpCfg.Settings["allow_http"] = "true"
	if err := a.Validate(httpCfg); err == nil {
		t.Error("bearer token over http accepted")
	}
	httpCfg.Credentials = nil
	if err := a.Validate(httpCfg); err != nil {
		t.Errorf("http with allow_http refused: %v", err)
	}
	for name, mut := range map[string]func(c adapter.Config){
		"no host":     func(c adapter.Config) { delete(c.Settings, "host") },
		"bad cluster": func(c adapter.Config) { c.Settings["cluster"] = "A/B" },
		"bad url":     func(c adapter.Config) { c.Settings["url"] = "ftp://x" },
	} {
		c := config()
		mut(c)
		if err := a.Validate(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
