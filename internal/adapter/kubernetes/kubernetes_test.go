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

// v2 is the feature set the default (metadata-only) mode needs: a Secret
// reported without its certificate is proposed in contract 0.10.0.
var v2 = adapter.Features{LocalStoreV1: true, AdapterEvidenceV2: true}

func newEnv(rt http.RoundTripper, f adapter.Features) (adapter.Env, *bytes.Buffer) {
	var logs bytes.Buffer
	return adapter.Env{
		HTTP:     &http.Client{Transport: rt},
		Creds:    mapSource{"k8s_token": saCred},
		Clock:    clock.NewFake(t0),
		Log:      slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Features: f,
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

const acceptMetadata = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"

// The default mode reads no Secret data: Secret metadata (as
// PartialObjectMetadataList), cert-manager Certificates, Ingresses and
// Gateways, and reports each Secret without its certificate (H1).
func TestReplayClusterMetadataOnly(t *testing.T) {
	tr := load(t, "cluster")
	env, logs := newEnv(tr, v2)
	cfg := config(map[string]string{"ca_file": caFile(t)})
	res := syncOK(t, newAdapter(env), cfg, "")

	var stores []string
	for _, o := range res.Observations {
		stores = append(stores, o.Target.Store)
		a := o.Adapter
		if o.Target.Kind != submit.KindStore || o.Target.Host != "k8s.example.test" || o.Method != submit.MethodAdapter ||
			o.Outcome != submit.OutcomeReached || len(o.ServedChain) != 0 || !o.ObservedAt.Equal(t0) ||
			a.Certificate != nil || a.Custody != nil || a.Kubernetes.ChainLength != 0 ||
			!reflect.DeepEqual(a.Findings, []submit.Finding{{Code: submit.FindingSecretNotRead}}) {
			t.Errorf("observation %+v %+v", o, a)
		}
	}
	want := []string{"kubernetes/prod/api/api-tls", "kubernetes/prod/legacy/legacy-tls", "kubernetes/prod/web/broken-tls", "kubernetes/prod/web/www-tls"}
	if !reflect.DeepEqual(stores, want) {
		t.Fatalf("stores %v, want %v", stores, want)
	}
	for k, v := range map[string]int{
		kubernetes.StatSecrets: 4, kubernetes.StatSecretsNotRead: 4, kubernetes.StatSecretsRead: 0,
		kubernetes.StatCertificateWithoutSecret: 1, kubernetes.StatBadCertificate: 0,
		kubernetes.StatUnchanged: 0, kubernetes.StatRemoved: 0, kubernetes.StatSkippedFeatureDisabled: 0,
	} {
		if res.Stats[k] != v {
			t.Errorf("stat %s = %d, want %d (%v)", k, res.Stats[k], v, res.Stats)
		}
	}

	api, legacy, broken, www := res.Observations[0].Adapter, res.Observations[1].Adapter, res.Observations[2].Adapter, res.Observations[3].Adapter
	if www.RenewalMode != submit.RenewalExternalAutomated || api.RenewalMode != "" || legacy.RenewalMode != "" || broken.RenewalMode != "" {
		t.Errorf("renewal modes %q %q %q %q", www.RenewalMode, api.RenewalMode, legacy.RenewalMode, broken.RenewalMode)
	}
	k := www.Kubernetes
	if k.Cluster != "prod" || k.Namespace != "web" || k.Name != "www-tls" {
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
		cm.Ready == nil || !*cm.Ready || cm.Revision == nil || *cm.Revision != 3 || cm.NotAfter == nil ||
		cm.RenewalTime == nil || cm.RenewalTime.Format(time.RFC3339) != "2026-10-31T00:00:00Z" || len(cm.DNSNames) != 2 {
		t.Errorf("www cert-manager %+v", cm)
	}
	if !reflect.DeepEqual(api.Kubernetes.Hostnames, []string{"api.example.test"}) || api.Kubernetes.CertManager != nil {
		t.Errorf("api kubernetes %+v", api.Kubernetes)
	}
	if !reflect.DeepEqual(legacy.Kubernetes.Hostnames, []string{"legacy.example.test"}) || legacy.Kubernetes.CertManager != nil {
		t.Errorf("legacy kubernetes %+v", legacy.Kubernetes)
	}
	if len(broken.Kubernetes.Hostnames) != 0 || len(broken.Kubernetes.References) != 0 {
		t.Errorf("broken kubernetes %+v", broken.Kubernetes)
	}

	// Every request is a read with the bearer token. Secrets are only ever
	// listed, as metadata, with the TLS type selector and paged with
	// continue; no single Secret is fetched.
	reqs := tr.Requests()
	if len(reqs) != 5 {
		t.Fatalf("%d requests", len(reqs))
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+saCred {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		if strings.Contains(r.URL.Path, "/secrets") && (r.URL.Path != "/api/v1/secrets" || r.Header.Get("Accept") != acceptMetadata) {
			t.Errorf("secret request %s Accept %q", r.URL, r.Header.Get("Accept"))
		}
	}
	if reqs[1].URL.Query().Get("continue") != "c-token-page-2" || reqs[0].URL.Query().Get("fieldSelector") != "type=kubernetes.io/tls" {
		t.Errorf("paging %s, %s", reqs[0].URL, reqs[1].URL)
	}

	assertNoLeak(t, res, logs.Bytes())
	// Reported without a certificate, the Secrets need the 0.10.0 proposal;
	// a 0.9.0 core refuses them.
	submitTo(t, submittest.CloudProposedSpecPath(), res.Observations)
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	if r, err := cl.Submit(context.Background(), res.Observations); err == nil && len(r.Rejected) == 0 {
		t.Error("a 0.9.0 core accepted a store observation without a certificate")
	}
}

// read_tls_crt=true with a namespaces allow-list gets each named Secret
// in those namespaces and parses tls.crt only.
func TestReadSecretsOptIn(t *testing.T) {
	tr := load(t, "read-secrets")
	env, logs := newEnv(tr, adapter.Features{LocalStoreV1: true})
	cfg := config(map[string]string{"ca_file": caFile(t), "namespaces": "web,legacy,api", "read_tls_crt": "true", "gateway_api": ""})
	res := syncOK(t, newAdapter(env), cfg, "")

	var stores []string
	for _, o := range res.Observations {
		stores = append(stores, o.Target.Store)
		if o.Outcome != submit.OutcomeCertSeen || o.Adapter.Certificate == nil || len(o.Adapter.Findings) != 0 {
			t.Errorf("observation %+v", o)
		}
	}
	want := []string{"kubernetes/prod/api/api-tls", "kubernetes/prod/legacy/legacy-tls", "kubernetes/prod/web/www-tls"}
	if !reflect.DeepEqual(stores, want) {
		t.Fatalf("stores %v, want %v", stores, want)
	}
	for k, v := range map[string]int{
		kubernetes.StatSecrets: 4, kubernetes.StatSecretsRead: 4, kubernetes.StatSecretsNotRead: 0,
		kubernetes.StatBadCertificate: 1, kubernetes.StatCertificateWithoutSecret: 1, kubernetes.StatReferenceWithoutSecret: 1,
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
	if www.Kubernetes.ChainLength != 2 || www.Kubernetes.CertManager == nil || www.Kubernetes.CertManager.Name != "www" ||
		!reflect.DeepEqual(www.Kubernetes.Hostnames, []string{"example.test", "www.example.test"}) {
		t.Errorf("www kubernetes %+v", www.Kubernetes)
	}
	if !*legacy.Certificate.SelfSigned || legacy.Certificate.KeyStrength != "2048" || legacy.Kubernetes.ChainLength != 1 {
		t.Errorf("legacy %+v %+v", legacy.Certificate, legacy.Kubernetes)
	}

	// Lists are namespaced; Secret listings ask for metadata; Secret data is
	// only fetched one named Secret at a time, never listed.
	gets := map[string]bool{}
	for _, r := range tr.Requests() {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/v1/namespaces/") && !strings.Contains(p, "/namespaces/") {
			t.Errorf("cluster-wide request %s", r.URL)
		}
		switch {
		case strings.HasSuffix(p, "/secrets"):
			if r.Header.Get("Accept") != acceptMetadata {
				t.Errorf("secret list %s Accept %q", r.URL, r.Header.Get("Accept"))
			}
		case strings.Contains(p, "/secrets/"):
			gets[p] = true
		}
	}
	wantGets := map[string]bool{
		"/api/v1/namespaces/api/secrets/api-tls": true, "/api/v1/namespaces/legacy/secrets/legacy-tls": true,
		"/api/v1/namespaces/web/secrets/broken-tls": true, "/api/v1/namespaces/web/secrets/www-tls": true,
	}
	if !reflect.DeepEqual(gets, wantGets) {
		t.Errorf("secret gets %v", gets)
	}
	assertNoLeak(t, res, logs.Bytes())
	submitTo(t, submittest.VendoredSpecPath(), res.Observations)
	submitTo(t, submittest.CloudProposedSpecPath(), res.Observations)
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
	env, _ := newEnv(load(t, "cluster"), v2)
	first := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": ca}), "")
	env2, _ := newEnv(load(t, "cluster"), v2)
	second := syncOK(t, newAdapter(env2), config(map[string]string{"ca_file": ca}), first.Cursor)
	if len(second.Observations) != 0 || second.Stats[kubernetes.StatUnchanged] != 4 {
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
	if cur.ResourceVersion != "5001" || len(cur.Secrets) != 4 {
		t.Fatalf("cursor %+v", cur)
	}
	cur.Secrets["web/www-tls"] = "stale"
	cur.Secrets["old/gone-tls"] = "x"
	c, _ := json.Marshal(cur)
	env3, _ := newEnv(load(t, "cluster"), v2)
	third := syncOK(t, newAdapter(env3), config(map[string]string{"ca_file": ca}), adapter.Cursor(c))
	if len(third.Observations) != 1 || third.Observations[0].Target.Store != "kubernetes/prod/web/www-tls" ||
		third.Stats[kubernetes.StatRemoved] != 1 || third.Stats[kubernetes.StatUnchanged] != 3 {
		t.Fatalf("third run %v %v", third.Observations, third.Stats)
	}
}

func TestFeatureOff(t *testing.T) {
	const since = adapter.Cursor(`{"secrets":{}}`)
	env, logs := newEnv(load(t, "cluster"), adapter.Features{})
	res := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": caFile(t)}), since)
	if len(res.Observations) != 0 || res.Cursor != since || res.Stats[kubernetes.StatSkippedFeatureDisabled] != 4 {
		t.Fatalf("%v %q %v", res.Observations, res.Cursor, res.Stats)
	}
	if !strings.Contains(logs.String(), adapter.EnvLocalStoreV1) {
		t.Error("no warning names the feature switch")
	}
	// Local store on, the 0.10.0 evidence off: Secrets reported without a
	// certificate are held back and not recorded as sent.
	env2, logs2 := newEnv(load(t, "cluster"), adapter.Features{LocalStoreV1: true})
	res2 := syncOK(t, newAdapter(env2), config(map[string]string{"ca_file": caFile(t)}), "")
	var cur struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(res2.Cursor), &cur); err != nil {
		t.Fatal(err)
	}
	if len(res2.Observations) != 0 || len(cur.Secrets) != 0 || res2.Stats[kubernetes.StatSkippedFeatureDisabled] != 4 {
		t.Fatalf("%v %q %v", res2.Observations, res2.Cursor, res2.Stats)
	}
	if !strings.Contains(logs2.String(), adapter.EnvAdapterEvidenceV2) {
		t.Error("no warning names the evidence switch")
	}
}

// Without any Secret permission (the default RBAC) the run succeeds from
// references alone; with read_tls_crt=true a refused Secret is an error.
func TestRBACMissing(t *testing.T) {
	env, logs := newEnv(load(t, "rbac-missing"), v2)
	cfg := config(map[string]string{"ca_file": caFile(t), "namespaces": "web", "gateway_api": ""})
	res := syncOK(t, newAdapter(env), cfg, "")
	// Without the metadata listing the adapter cannot tell whether a Secret
	// exists, so cert-manager's not-yet-issued pending-tls is reported too
	// (its Certificate says ready false).
	if len(res.Observations) != 2 || res.Observations[0].Target.Store != "kubernetes/prod/web/pending-tls" ||
		res.Observations[1].Target.Store != "kubernetes/prod/web/www-tls" ||
		res.Stats["rbac_missing_secrets"] != 1 || res.Stats[kubernetes.StatSecretsNotRead] != 2 ||
		res.Stats[kubernetes.StatCertificateWithoutSecret] != 0 {
		t.Fatalf("%v %v", res.Observations, res.Stats)
	}
	if cm := res.Observations[0].Adapter.Kubernetes.CertManager; cm == nil || cm.Name != "pending" || cm.Ready == nil || *cm.Ready {
		t.Errorf("pending cert-manager %+v", cm)
	}
	www := res.Observations[1].Adapter
	if cm := www.Kubernetes.CertManager; cm == nil || cm.Name != "www" ||
		!reflect.DeepEqual(www.Kubernetes.Hostnames, []string{"example.test", "www.example.test"}) {
		t.Errorf("www %+v", www.Kubernetes)
	}
	if strings.Contains(logs.String(), `"level":"WARN"`) {
		t.Errorf("missing Secret permission is warned about in the default mode: %s", logs.String())
	}

	env2, logs2 := newEnv(load(t, "rbac-missing"), v2)
	cfg2 := config(map[string]string{"ca_file": caFile(t), "namespaces": "web", "gateway_api": "", "read_tls_crt": "true", "cert_manager": "false"})
	_, err := newAdapter(env2).Sync(context.Background(), cfg2, "")
	if !errors.Is(err, kubernetes.ErrRBAC) || !adapter.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), saCred) || strings.Contains(logs.String(), saCred) || strings.Contains(logs2.String(), saCred) {
		t.Fatal("token leaked")
	}
}

func TestOptionalResourcesMissing(t *testing.T) {
	env, logs := newEnv(load(t, "optional-missing"), v2)
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

// A server that ignores the metadata-only Accept header and answers a full
// SecretList is refused: its items are not used.
func TestFullSecretListRefused(t *testing.T) {
	tr := &rewrite{next: load(t, "cluster"), from: `"PartialObjectMetadataList"`, to: `"SecretList"`}
	env, _ := newEnv(tr, v2)
	_, err := newAdapter(env).Sync(context.Background(), config(map[string]string{"ca_file": caFile(t)}), "")
	if err == nil || !strings.Contains(err.Error(), "PartialObjectMetadataList") {
		t.Fatalf("error %v", err)
	}
}

// rewrite replaces text in every response body.
type rewrite struct {
	next     http.RoundTripper
	from, to string
}

func (rw *rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := rw.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(b), rw.from, rw.to)))
	return resp, nil
}

// Every tls.key in the Kubernetes fixtures, including those inside a
// kubectl last-applied annotation, is the low-entropy placeholder or empty.
func TestFixtureKeysArePlaceholders(t *testing.T) {
	const placeholder = "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"
	seen := 0
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if k == "tls.key" {
					seen++
					if s, ok := e.(string); !ok || (s != placeholder && s != "") {
						t.Errorf("%s: tls.key is not the placeholder", path)
					}
				}
				walk(path, e)
			}
		case []any:
			for _, e := range x {
				walk(path, e)
			}
		case string:
			var inner any
			if strings.Contains(x, "tls.key") {
				if json.Unmarshal([]byte(x), &inner) != nil {
					t.Errorf("%s: a string mentions tls.key but is not JSON", path)
					return
				}
				walk(path, inner)
			}
		}
	}
	err := filepath.WalkDir(fixture.Dir("kubernetes"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // a fixture path
		if err != nil {
			return err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		walk(p, v)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 4 {
		t.Fatalf("only %d tls.key values found; the walk is not reaching the fixtures", seen)
	}
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
	env, _ := newEnv(&expiring{next: load(t, "cluster")}, v2)
	res := syncOK(t, newAdapter(env), config(map[string]string{"ca_file": caFile(t)}), "")
	if len(res.Observations) != 4 || res.Stats[kubernetes.StatContinueExpired] != 1 {
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
	env, _ := newEnv(tr, v2)
	cfg := config(map[string]string{"ca_file": "", "in_cluster": "true", "api_server": ""})
	cfg.Credentials = nil
	res := syncOK(t, newAdapter(env), cfg, "")
	if len(res.Observations) != 4 || res.Observations[0].Target.Host != "kubernetes.default.svc" {
		t.Fatalf("%v", res.Observations)
	}
	for _, r := range tr.Requests() {
		if r.Header.Get("Authorization") != "Bearer "+saCred || r.URL.Host != "kubernetes.default.svc" {
			t.Fatalf("request %s", r.URL)
		}
	}

	// The pod's token is never sent to another API server (L5): in_cluster
	// with an external api_server needs an explicit bearer_token.
	tr2 := load(t, "cluster")
	env2, _ := newEnv(tr2, v2)
	ext := config(map[string]string{"ca_file": "", "in_cluster": "true"})
	ext.Credentials = nil
	if err := newAdapter(env2).Validate(ext); err == nil {
		t.Error("in_cluster with an external api_server and no bearer_token accepted")
	}
	if _, err := newAdapter(env2).Sync(context.Background(), ext, ""); err == nil || !strings.Contains(err.Error(), "bearer_token is required") {
		t.Errorf("sync error %v", err)
	}
	if n := len(tr2.Requests()); n != 0 {
		t.Errorf("%d requests made without a permitted token", n)
	}
	// With a bearer_token it goes to the external server, with that token.
	ext.Credentials = map[string]string{"bearer_token": "k8s_token"}
	if _, err := newAdapter(env2).Sync(context.Background(), ext, ""); err != nil {
		t.Fatal(err)
	}
	for _, r := range tr2.Requests() {
		if r.URL.Host != "k8s.example.test:6443" {
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
		"read without ns":     {"read_tls_crt": "true"},
		"bad read flag":       {"read_tls_crt": "maybe", "namespaces": "web"},
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
	if err := a.Validate(config(map[string]string{"read_tls_crt": "true", "namespaces": "web,api"})); err != nil {
		t.Errorf("opt-in with namespaces refused: %v", err)
	}
	inCluster := config(map[string]string{"ca_file": "", "in_cluster": "true", "api_server": ""})
	inCluster.Credentials = nil
	if err := a.Validate(inCluster); err != nil {
		t.Errorf("in_cluster with the in-cluster server refused: %v", err)
	}
	inCluster.Settings["api_server"] = "https://kubernetes.default.svc.cluster.local"
	if err := a.Validate(inCluster); err != nil {
		t.Errorf("in_cluster with the in-cluster FQDN refused: %v", err)
	}
	inCluster.Settings["api_server"] = "https://kubernetes.default.svc:6443"
	if err := a.Validate(inCluster); err == nil {
		t.Error("in_cluster token for a non-443 port accepted")
	}
}

func TestDescribe(t *testing.T) {
	d := newAdapter(adapter.Env{}).Describe()
	if d.Name != "kubernetes" || d.Source != "kubernetes" {
		t.Fatalf("%+v", d)
	}
}
