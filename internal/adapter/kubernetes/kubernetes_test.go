package kubernetes_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/kubernetes"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

// saCred is a synthetic bearer value; it must never appear in output.
const saCred = "aaaa-bbbb-cccc-dddd-test-only" //nolint:gosec // synthetic test value

// keyMarkers are the synthetic tls.key value of the fixtures, encoded and
// decoded; they must never appear in observations, logs, stats or cursors.
var keyMarkers = []string{"a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5", "keykeykeykeykeykeykeykey"}

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

func newEnv(rt http.RoundTripper, localStore bool) (adapter.Env, *bytes.Buffer) {
	var logs bytes.Buffer
	return adapter.Env{
		HTTP:     &http.Client{Transport: rt},
		Creds:    mapSource{"k8s_token": saCred},
		Clock:    clock.NewFake(t0),
		Log:      slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Features: adapter.Features{LocalStoreV1: localStore},
	}, &logs
}

func newAdapter(env adapter.Env) adapter.Adapter {
	f, ok := adapter.Lookup(kubernetes.Name)
	if !ok {
		panic("kubernetes not registered")
	}
	return f(env)
}

func config(extra map[string]string) adapter.Config {
	s := map[string]string{
		"cluster":     "prod",
		"api_server":  "https://k8s.example.test:6443",
		"ca_file":     "/nonexistent",
		"page_size":   "2",
		"gateway_api": "true",
	}
	for k, v := range extra {
		if v == "" {
			delete(s, k)
		} else {
			s[k] = v
		}
	}
	return adapter.Config{Name: "k8s-prod", Adapter: kubernetes.Name, Settings: s, Credentials: map[string]string{"bearer_token": "k8s_token"}}
}

// caFile writes the synthetic cluster CA (stored base64 so no PEM armour is
// committed) to a temporary file.
func caFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fixture.Dir("kubernetes", "cluster-ca.b64"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := decodeB64(t, strings.TrimSpace(string(b)))
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func load(t *testing.T, dir string) *fixture.Transport {
	t.Helper()
	tr, err := fixture.Load(fixture.Dir("kubernetes", dir))
	if err != nil {
		t.Fatal(err)
	}
	return tr
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

func submitTo(t *testing.T, spec string, obs []submit.Observation) {
	t.Helper()
	core, err := submittest.NewCoreWithSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Accepted != len(obs) || len(res.Rejected) != 0 {
		t.Fatalf("accepted %d of %d, rejected %+v", res.Accepted, len(obs), res.Rejected)
	}
}

func TestReplayCluster(t *testing.T) {
	tr := load(t, "cluster")
	env, logs := newEnv(tr, true)
	cfg := config(map[string]string{"ca_file": caFile(t)})
	res := syncOK(t, newAdapter(env), cfg, "")

	var stores []string
	for _, o := range res.Observations {
		stores = append(stores, o.Target.Store)
		if o.Target.Kind != submit.KindStore || o.Target.Host != "k8s.example.test" || o.Method != submit.MethodAdapter ||
			o.Outcome != submit.OutcomeCertSeen || len(o.ServedChain) != 0 || !o.ObservedAt.Equal(t0) {
			t.Errorf("observation %+v", o)
		}
	}
	want := []string{"kubernetes/prod/api/api-tls", "kubernetes/prod/legacy/legacy-tls", "kubernetes/prod/web/www-tls"}
	if !reflect.DeepEqual(stores, want) {
		t.Fatalf("stores %v, want %v", stores, want)
	}
	for k, v := range map[string]int{
		kubernetes.StatSecrets: 4, kubernetes.StatBadCertificate: 1, kubernetes.StatCertificateWithoutSecret: 1,
		kubernetes.StatUnchanged: 0, kubernetes.StatRemoved: 0, kubernetes.StatSkippedFeatureDisabled: 0,
	} {
		if res.Stats[k] != v {
			t.Errorf("stat %s = %d, want %d (%v)", k, res.Stats[k], v, res.Stats)
		}
	}

	api, legacy, www := res.Observations[0].Adapter, res.Observations[1].Adapter, res.Observations[2].Adapter
	if www.Certificate.SHA1 != "89433b4ac105d42a60364a3ec00366430801cfb8" || www.Certificate.Serial != "2a01" ||
		www.Certificate.CommonName != "www.example.test" || *www.Certificate.SelfSigned || www.Certificate.NotAfter.Format(time.RFC3339) != "2026-11-30T00:00:00Z" {
		t.Errorf("www certificate %+v", www.Certificate)
	}
	if !reflect.DeepEqual(www.Certificate.DNSNames, []string{"www.example.test", "example.test"}) {
		t.Errorf("www dns names %v", www.Certificate.DNSNames)
	}
	if www.Custody.KeyCustody != submit.KeyPresent || api.Custody.KeyCustody != submit.KeyAbsent || legacy.Custody.KeyCustody != submit.KeyPresent {
		t.Errorf("custody www %v api %v legacy %v", www.Custody, api.Custody, legacy.Custody)
	}
	if www.RenewalMode != submit.RenewalExternalAutomated || api.RenewalMode != "" || legacy.RenewalMode != "" {
		t.Errorf("renewal modes %q %q %q", www.RenewalMode, api.RenewalMode, legacy.RenewalMode)
	}
	k := www.Kubernetes
	if k.Cluster != "prod" || k.Namespace != "web" || k.Name != "www-tls" || k.ChainLength != 2 {
		t.Errorf("www kubernetes %+v", k)
	}
	if !reflect.DeepEqual(k.Hostnames, []string{"example.test", "www.example.test"}) {
		t.Errorf("www hostnames %v", k.Hostnames)
	}
	wantRefs := []submit.KubernetesRef{{Kind: "Gateway", Namespace: "api", Name: "edge"}, {Kind: "Ingress", Namespace: "web", Name: "www"}}
	if !reflect.DeepEqual(k.References, wantRefs) {
		t.Errorf("www references %v", k.References)
	}
	cm := k.CertManager
	if cm == nil || cm.Name != "www" || cm.IssuerKind != "ClusterIssuer" || cm.IssuerName != "acme-staging" || cm.IssuerGroup != "cert-manager.io" ||
		cm.Ready == nil || !*cm.Ready || cm.Revision == nil || *cm.Revision != 3 ||
		cm.RenewalTime == nil || cm.RenewalTime.Format(time.RFC3339) != "2026-10-31T00:00:00Z" || len(cm.DNSNames) != 2 {
		t.Errorf("www cert-manager %+v", cm)
	}
	if !reflect.DeepEqual(api.Kubernetes.Hostnames, []string{"api.example.test"}) || api.Kubernetes.CertManager != nil {
		t.Errorf("api kubernetes %+v", api.Kubernetes)
	}
	if !*legacy.Certificate.SelfSigned || legacy.Certificate.KeyStrength != "2048" || legacy.Kubernetes.ChainLength != 1 {
		t.Errorf("legacy %+v %+v", legacy.Certificate, legacy.Kubernetes)
	}

	// Every request is a read with the bearer token; Secrets are listed with
	// the TLS type selector and paged with continue.
	reqs := tr.Requests()
	if len(reqs) != 5 {
		t.Fatalf("%d requests", len(reqs))
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+saCred {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
	}
	if reqs[1].URL.Query().Get("continue") != "c-token-page-2" || reqs[0].URL.Query().Get("fieldSelector") != "type=kubernetes.io/tls" {
		t.Errorf("paging %s, %s", reqs[0].URL, reqs[1].URL)
	}

	assertNoLeak(t, res, logs.Bytes())
	// The current contract (0.9.0) accepts them, the unknown evidence fields
	// ignored; so does the 0.10.0 proposal that defines those fields.
	submitTo(t, submittest.VendoredSpecPath(), res.Observations)
	submitTo(t, submittest.Proposed010SpecPath(), res.Observations)
}

func assertNoLeak(t *testing.T, res adapter.Result, logs []byte) {
	t.Helper()
	b, err := json.Marshal(res.Observations)
	if err != nil {
		t.Fatal(err)
	}
	stats, _ := json.Marshal(res.Stats)
	all := string(b) + string(stats) + string(res.Cursor) + string(logs)
	for _, m := range append(keyMarkers, saCred) {
		if strings.Contains(all, m) {
			t.Errorf("output contains %q", m)
		}
	}
	if strings.Contains(all, "last-applied") || strings.Contains(all, "tls.key") {
		t.Error("output mentions the Secret's data or kubectl's annotation")
	}
	if hits := adapter.FindSecrets([]byte(all)); len(hits) > 0 {
		t.Errorf("secret patterns %v", hits)
	}
}

func TestDelta(t *testing.T) {
	ca := caFile(t)
	env, _ := newEnv(load(t, "cluster"), true)
	first := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": ca}), "")
	env2, _ := newEnv(load(t, "cluster"), true)
	second := syncOK(t, newAdapter(env2), config(map[string]string{"ca_file": ca}), first.Cursor)
	if len(second.Observations) != 0 || second.Stats[kubernetes.StatUnchanged] != 3 {
		t.Fatalf("second run %d observations, stats %v", len(second.Observations), second.Stats)
	}
	// A changed Secret (its fingerprint differs) is sent again, a Secret no
	// longer listed is counted as removed.
	var cur struct {
		Secrets         map[string]string `json:"secrets"`
		ResourceVersion string            `json:"resource_version"`
	}
	if err := json.Unmarshal([]byte(first.Cursor), &cur); err != nil {
		t.Fatal(err)
	}
	if cur.ResourceVersion != "5001" || len(cur.Secrets) != 3 {
		t.Fatalf("cursor %+v", cur)
	}
	cur.Secrets["web/www-tls"] = "stale"
	cur.Secrets["old/gone-tls"] = "x"
	c, _ := json.Marshal(cur)
	env3, _ := newEnv(load(t, "cluster"), true)
	third := syncOK(t, newAdapter(env3), config(map[string]string{"ca_file": ca}), adapter.Cursor(c))
	if len(third.Observations) != 1 || third.Observations[0].Target.Store != "kubernetes/prod/web/www-tls" ||
		third.Stats[kubernetes.StatRemoved] != 1 || third.Stats[kubernetes.StatUnchanged] != 2 {
		t.Fatalf("third run %v %v", third.Observations, third.Stats)
	}
}

func TestFeatureOff(t *testing.T) {
	const since = adapter.Cursor(`{"secrets":{}}`)
	env, logs := newEnv(load(t, "cluster"), false)
	res := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": caFile(t)}), since)
	if len(res.Observations) != 0 || res.Cursor != since || res.Stats[kubernetes.StatSkippedFeatureDisabled] != 3 {
		t.Fatalf("%v %q %v", res.Observations, res.Cursor, res.Stats)
	}
	if !strings.Contains(logs.String(), adapter.EnvLocalStoreV1) {
		t.Error("no warning names the feature switch")
	}
}

func TestRBACMissing(t *testing.T) {
	env, logs := newEnv(load(t, "rbac-missing"), true)
	cfg := config(map[string]string{"ca_file": caFile(t), "namespaces": "web"})
	_, err := newAdapter(env).Sync(context.Background(), cfg, "")
	if !errors.Is(err, kubernetes.ErrRBAC) || !adapter.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), saCred) || strings.Contains(logs.String(), saCred) {
		t.Fatal("token leaked")
	}
}

func TestOptionalResourcesMissing(t *testing.T) {
	env, logs := newEnv(load(t, "optional-missing"), true)
	cfg := config(map[string]string{"ca_file": caFile(t), "namespaces": "web", "gateway_api": ""})
	res := syncOK(t, newAdapter(env), cfg, "")
	if len(res.Observations) != 1 || res.Stats["api_absent_certificates"] != 1 || res.Stats["rbac_missing_ingresses"] != 1 {
		t.Fatalf("%d observations, stats %v", len(res.Observations), res.Stats)
	}
	if o := res.Observations[0].Adapter; o.Kubernetes.CertManager != nil || o.RenewalMode != "" || len(o.Kubernetes.Hostnames) != 0 {
		t.Errorf("evidence %+v", o.Kubernetes)
	}
	if !strings.Contains(logs.String(), "no permission to list ingresses") {
		t.Error("missing RBAC is not logged")
	}
	assertNoLeak(t, res, logs.Bytes())
}

// expiring answers the second Secret page with 410 Gone once, as an API
// server does when a continue token has expired.
type expiring struct {
	next http.RoundTripper
	mu   sync.Mutex
	done bool
}

func (e *expiring) RoundTrip(r *http.Request) (*http.Response, error) {
	e.mu.Lock()
	expire := !e.done && r.URL.Query().Get("continue") != ""
	if expire {
		e.done = true
	}
	e.mu.Unlock()
	if expire {
		return &http.Response{StatusCode: http.StatusGone, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"kind":"Status","code":410,"reason":"Expired"}`)), Request: r}, nil
	}
	return e.next.RoundTrip(r)
}

func TestContinueExpired(t *testing.T) {
	env, _ := newEnv(&expiring{next: load(t, "cluster")}, true)
	res := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": caFile(t)}), "")
	if len(res.Observations) != 3 || res.Stats[kubernetes.StatContinueExpired] != 1 {
		t.Fatalf("%d observations, stats %v", len(res.Observations), res.Stats)
	}
}

func TestInClusterServiceAccount(t *testing.T) {
	dir := t.TempDir()
	ca, err := os.ReadFile(caFile(t)) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600); err != nil { // #nosec G703 -- a test temp file
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(saCred+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := kubernetes.ServiceAccountDir
	kubernetes.ServiceAccountDir = dir
	defer func() { kubernetes.ServiceAccountDir = old }()
	tr := load(t, "cluster")
	env, _ := newEnv(tr, true)
	cfg := config(map[string]string{"ca_file": "", "in_cluster": "true", "api_server": ""})
	cfg.Credentials = nil
	res := syncOK(t, newAdapter(env), cfg, "")
	if len(res.Observations) != 3 || res.Observations[0].Target.Host != "kubernetes.default.svc" {
		t.Fatalf("%v", res.Observations)
	}
	for _, r := range tr.Requests() {
		if r.Header.Get("Authorization") != "Bearer "+saCred || r.URL.Host != "kubernetes.default.svc" {
			t.Fatalf("request %s", r.URL)
		}
	}
}

func TestValidate(t *testing.T) {
	a := newAdapter(adapter.Env{})
	if err := a.Validate(config(nil)); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	bad := map[string]map[string]string{
		"no cluster":          {"cluster": ""},
		"cluster with slash":  {"cluster": "a/b"},
		"http server":         {"api_server": "http://k8s.example.test"},
		"user info":           {"api_server": "https://u@k8s.example.test"},
		"no anchor":           {"ca_file": ""},
		"two anchors":         {"system_roots": "true"},
		"bad namespace":       {"namespaces": "Web"},
		"page size":           {"page_size": "0"},
		"rate":                {"rate_per_second": "-1"},
		"bad bool":            {"gateway_api": "maybe"},
		"context without kc":  {"kube_context": "x"},
		"no server":           {"api_server": ""},
		"in_cluster and file": {"in_cluster": "true"},
	}
	for name, s := range bad {
		if err := a.Validate(config(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noToken := config(nil)
	noToken.Credentials = nil
	if err := a.Validate(noToken); err == nil {
		t.Error("missing bearer_token accepted")
	}
}

func TestDescribe(t *testing.T) {
	d := newAdapter(adapter.Env{}).Describe()
	if d.Name != "kubernetes" || d.Source != "kubernetes" {
		t.Fatalf("%+v", d)
	}
}
