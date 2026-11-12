package azure_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/azure"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Synthetic values the tests check never leak. None is a real credential.
const (
	clientSecretValue = "synthetic-client-secret-value-7f3a"
	tenantID          = "99999999-8888-4777-8666-555555555555"
	clientID          = "12345678-1234-4234-8234-123456789abc"
	subscriptionID    = "11111111-2222-3333-4444-555555555555"
)

var tokens = map[string]string{
	"https://management.azure.com/.default": "synthetic-arm-access-0001",
	"https://vault.azure.net/.default":      "synthetic-vault-access-0002",
	"https://graph.microsoft.com/.default":  "synthetic-graph-access-0003",
}

var t0 = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)

type staticCreds map[string]string

func (s staticCreds) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := s[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

// fakeAzure plays Entra ID (token endpoint), IMDS and the APIs: API calls
// are checked for the token of their audience and then answered by an
// override or the recorded fixtures.
type fakeAzure struct {
	t        *testing.T
	fixtures *fixture.Transport

	mu         sync.Mutex
	hosts      []string
	tokenCalls map[string]int
	tokenFail  int // status the token endpoint answers with, 0: success
	imdsCalls  int
	override   map[string]func(r *http.Request) *http.Response
	throttle   map[string]int // path -> number of 429 answers still to give
}

func newFake(t *testing.T, dir string) *fakeAzure {
	t.Helper()
	tr, err := fixture.Load(fixture.Dir("azure", dir))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAzure{t: t, fixtures: tr, tokenCalls: map[string]int{}, override: map[string]func(*http.Request) *http.Response{}, throttle: map[string]int{}}
}

func jsonResponse(r *http.Request, status int, body string, hdr ...string) *http.Response {
	h := http.Header{"Content-Type": {"application/json"}}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func audience(host string) string {
	switch {
	case host == "management.azure.com":
		return "https://management.azure.com/.default"
	case host == "graph.microsoft.com":
		return "https://graph.microsoft.com/.default"
	case strings.HasSuffix(host, ".vault.azure.net"):
		return "https://vault.azure.net/.default"
	}
	return ""
}

func (f *fakeAzure) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.hosts = append(f.hosts, r.URL.Host)
	f.mu.Unlock()
	switch r.URL.Host {
	case "login.microsoftonline.com":
		if r.URL.Path != "/"+tenantID+"/oauth2/v2.0/token" || r.Method != http.MethodPost {
			return nil, fmt.Errorf("unexpected token request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		if f.tokenFail != 0 {
			return jsonResponse(r, f.tokenFail, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. `+clientSecretValue+`"}`), nil
		}
		if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != clientID || form.Get("client_secret") != clientSecretValue {
			return jsonResponse(r, 401, `{"error":"invalid_client"}`), nil
		}
		tok, ok := tokens[form.Get("scope")]
		if !ok {
			return jsonResponse(r, 400, `{"error":"invalid_scope"}`), nil
		}
		f.mu.Lock()
		f.tokenCalls[form.Get("scope")]++
		f.mu.Unlock()
		return jsonResponse(r, 200, `{"token_type":"Bearer","expires_in":3599,"access_token":"`+tok+`"}`), nil
	case "169.254.169.254":
		if r.Header.Get("Metadata") != "true" {
			return jsonResponse(r, 400, `{"error":"invalid_request"}`), nil
		}
		f.mu.Lock()
		f.imdsCalls++
		f.mu.Unlock()
		tok := tokens[r.URL.Query().Get("resource")+"/.default"]
		return jsonResponse(r, 200, `{"access_token":"`+tok+`","expires_in":"86399","token_type":"Bearer"}`), nil
	}
	aud := audience(r.URL.Host)
	if aud == "" {
		f.t.Errorf("request to unexpected host %s", r.URL.Host)
		return nil, errors.New("unexpected host")
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+tokens[aud] {
		f.t.Errorf("%s %s: wrong token for audience %s", r.Method, r.URL.Path, aud)
	}
	f.mu.Lock()
	n := f.throttle[r.URL.Path]
	if n > 0 {
		f.throttle[r.URL.Path] = n - 1
	}
	h := f.override[r.URL.Path]
	f.mu.Unlock()
	if n > 0 {
		return jsonResponse(r, 429, `{"error":{"code":"TooManyRequests"}}`, "Retry-After", "7"), nil
	}
	if h != nil {
		return h(r), nil
	}
	return f.fixtures.RoundTrip(r)
}

func (f *fakeAzure) count(path string) int {
	n := 0
	for _, r := range f.fixtures.Requests() {
		if r.URL.Path == path {
			n++
		}
	}
	return n
}

type harness struct {
	env  adapter.Env
	clk  *clock.Fake
	logs *bytes.Buffer
}

func newHarness(f *fakeAzure, feats adapter.Features) *harness {
	logs := &bytes.Buffer{}
	clk := clock.NewFake(t0)
	return &harness{
		clk:  clk,
		logs: logs,
		env: adapter.Env{
			HTTP:     &http.Client{Transport: f},
			Creds:    staticCreds{"azure_client_secret": clientSecretValue},
			Clock:    clk,
			Log:      slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			Features: feats,
		},
	}
}

var allOn = adapter.Features{CloudResourceV1: true, LocalStoreV1: true}

func config(name, kind string, settings map[string]string) adapter.Config {
	s := map[string]string{"tenant_id": tenantID, "client_id": clientID}
	for k, v := range settings {
		s[k] = v
	}
	return adapter.Config{Name: name, Adapter: kind, Settings: s, Credentials: map[string]string{azure.CredClientSecret: "azure_client_secret"}}
}

func (h *harness) sync(t *testing.T, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	t.Helper()
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	f, ok := adapter.Lookup(cfg.Adapter)
	if !ok {
		t.Fatalf("adapter %s not registered", cfg.Adapter)
	}
	a := f(h.env)
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	return a.Sync(context.Background(), cfg, since)
}

// clean is the redaction check: no token, client secret, key armour or
// secret-shaped text in the observations, the cursor or the logs.
func clean(t *testing.T, res adapter.Result, logs string, extra ...string) {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	all := string(b) + "\n" + logs
	leaks := append([]string{clientSecretValue, "PRIVATE KEY", "-----BEGIN"}, extra...)
	for _, tok := range tokens {
		leaks = append(leaks, tok)
	}
	for _, l := range leaks {
		if strings.Contains(all, l) {
			t.Errorf("output contains %q", l)
		}
	}
	if hits := adapter.FindSecrets([]byte(all)); len(hits) > 0 {
		t.Errorf("output matches secret patterns %v", hits)
	}
}

// accepted submits observations to a fake core for the contract at path
// and requires every one to be accepted.
func accepted(t *testing.T, core *submittest.Core, obs []submit.Observation) {
	t.Helper()
	if len(obs) == 0 {
		t.Fatal("no observations to submit")
	}
	cl, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("submit: %v; core errors %v", err, core.Errors())
	}
	if res.Accepted != len(obs) || len(res.Rejected) > 0 {
		t.Fatalf("accepted %d of %d, rejected %+v", res.Accepted, len(obs), core.Rejected())
	}
}

func cloudCore(t *testing.T) *submittest.Core {
	t.Helper()
	c, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func vendoredCore(t *testing.T) *submittest.Core {
	t.Helper()
	c, err := submittest.NewCoreWithSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func byID(obs []submit.Observation) map[string]submit.Observation {
	m := map[string]submit.Observation{}
	for _, o := range obs {
		k := o.Target.ResourceID
		if k == "" {
			k = o.Target.Host + "|" + o.Target.Store + "|" + o.Adapter.Certificate.SHA1
		}
		m[k] = o
	}
	return m
}

const (
	kvSHA1  = "ba969cbdbe8805ffd8027e920d15d6b1fcae24ec"
	webSHA1 = "122ea81c2e0c3ed45f7f20ca936902dc027c4662"
	agwSHA1 = "0f71d56bd69ac8638afc9ff25a800915e5e81742"
	pemSHA1 = "5d931e448022715a263f23b7747d545babbb5156"
	vault   = "https://kv-contoso-prod.vault.azure.net"
)

func TestRegistered(t *testing.T) {
	for _, n := range []string{azure.NameKeyVault, azure.NameAppService, azure.NameAppGateway, azure.NameEntra, azure.NameDefender} {
		f, ok := adapter.Lookup(n)
		if !ok {
			t.Fatalf("%s not registered", n)
		}
		if d := f(adapter.Env{}).Describe(); d.Name != n || d.Source != n || len(d.Credentials) != 1 {
			t.Errorf("%s: description %+v", n, d)
		}
	}
}

func TestKeyVault(t *testing.T) {
	f := newFake(t, "keyvault")
	h := newHarness(f, allOn)
	cfg := config("kv-prod", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"})
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String())
	m := byID(res.Observations)
	if len(m) != 4 {
		t.Fatalf("got %d observations, want 4: %v", len(m), m)
	}
	web := m[vault+"/certificates/web-tls"]
	if web.Outcome != submit.OutcomeCertSeen || web.Adapter.Certificate.SHA1 != kvSHA1 ||
		web.Adapter.Certificate.CommonName != "www.contoso.example.test" || web.Adapter.RenewalMode != submit.RenewalExternalAutomated ||
		web.Adapter.Custody.KeyCustody != submit.KeyPresent || web.Adapter.Custody.KeyExportable == nil || *web.Adapter.Custody.KeyExportable ||
		web.Target.Host != "kv-contoso-prod.vault.azure.net" || web.Target.Kind != submit.KindCloudResource || web.Target.Provider != "azure" {
		t.Errorf("web-tls: %+v %+v", web.Target, web.Adapter)
	}
	man := m[vault+"/certificates/partner-manual"]
	if man.Adapter.Certificate.SHA1 != pemSHA1 || man.Adapter.RenewalMode != submit.RenewalManual || man.Adapter.Certificate.NotAfter != nil {
		t.Errorf("partner-manual (x5t fallback): %+v", man.Adapter.Certificate)
	}
	for _, id := range []string{"/secrets/legacy-pem", "/secrets/partner-pfx"} {
		o := m[vault+id]
		if o.Outcome != submit.OutcomeReached || len(o.Adapter.Findings) != 1 || o.Adapter.Findings[0].Code != submit.FindingSecretNotRead || o.Adapter.Custody.KeyCustody != submit.KeyUnknown {
			t.Errorf("%s: %+v", id, o.Adapter)
		}
	}
	if res.Stats[azure.StatSkippedCertificateBacked] != 1 || res.Stats[azure.StatSkippedNotCertificate] != 1 {
		t.Errorf("stats %v", res.Stats)
	}
	// Pagination followed the nextLink; no secret value was read.
	if f.count("/certificates") != 2 || f.count("/secrets/legacy-pem") != 0 {
		t.Errorf("requests: list %d, secret value %d", f.count("/certificates"), f.count("/secrets/legacy-pem"))
	}
	if f.tokenCalls["https://vault.azure.net/.default"] != 1 {
		t.Errorf("token calls %v: want one cached vault token", f.tokenCalls)
	}
	accepted(t, cloudCore(t), res.Observations)

	// Delta: nothing changed, nothing re-read.
	gets := f.count("/certificates/web-tls")
	res2, err := h.sync(t, cfg, res.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Observations) != 0 || f.count("/certificates/web-tls") != gets || res2.Stats[azure.StatUnchanged] != 6 {
		t.Errorf("delta: %d observations, stats %v", len(res2.Observations), res2.Stats)
	}
}

func TestKeyVaultPEMSecretPublicPartOnly(t *testing.T) {
	der, err := os.ReadFile(filepath.Join(fixture.Root(), "azure", "pem-secret-certificate.b64"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "NOTAREALKEYxSYNTHETICxMARKER"
	armour := "-----" + "BEGIN"
	value := armour + " PRIVATE" + " KEY-----\n" + marker + "AAAA\n-----END PRIVATE" + " KEY-----\n" +
		armour + " CERTIFICATE-----\n" + strings.TrimSpace(string(der)) + "\n-----END CERTIFICATE-----\n"
	f := newFake(t, "keyvault")
	f.override["/secrets/legacy-pem"] = func(r *http.Request) *http.Response {
		b, _ := json.Marshal(map[string]any{"id": vault + "/secrets/legacy-pem/v1", "contentType": "application/x-pem-file", "value": value})
		return jsonResponse(r, 200, string(b))
	}
	h := newHarness(f, allOn)
	res, err := h.sync(t, config("kv-prod", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod", "read_pem_entries": "true"}), "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String(), marker)
	o := byID(res.Observations)[vault+"/secrets/legacy-pem"]
	if o.Outcome != submit.OutcomeCertSeen || o.Adapter.Certificate == nil || o.Adapter.Certificate.SHA1 != pemSHA1 || o.Adapter.Custody.KeyCustody != submit.KeyPresent {
		t.Fatalf("pem secret: %+v", o.Adapter)
	}
	// A PKCS#12 secret is never fetched, even when values may be read.
	if pfx := byID(res.Observations)[vault+"/secrets/partner-pfx"]; len(pfx.Adapter.Findings) != 1 {
		t.Errorf("pfx: %+v", pfx.Adapter)
	}
	accepted(t, cloudCore(t), res.Observations)
}

func TestAppService(t *testing.T) {
	f := newFake(t, "appservice")
	h := newHarness(f, allOn)
	cfg := config("web", azure.NameAppService, map[string]string{"subscriptions": subscriptionID})
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String())
	if len(res.Observations) != 2 {
		t.Fatalf("got %d observations", len(res.Observations))
	}
	prefix := "/subscriptions/" + subscriptionID + "/resourceGroups/rg-web/providers/Microsoft.Web/"
	m := byID(res.Observations)
	mg := m[prefix+"certificates/app-contoso-managed"]
	if mg.Adapter.Certificate.SHA1 != webSHA1 || mg.Adapter.RenewalMode != submit.RenewalExternalAutomated || mg.Target.Region != "australiaeast" ||
		len(mg.Adapter.Bindings) != 1 || mg.Adapter.Bindings[0] != (submit.Binding{Hostname: "app.contoso.example.test", Port: 443, ResourceID: prefix + "sites/app-contoso"}) {
		t.Errorf("managed: %+v", mg.Adapter)
	}
	kv := m[prefix+"certificates/api-from-keyvault"]
	if kv.Adapter.Certificate.SHA1 != "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678" || kv.Adapter.RenewalMode != submit.RenewalUnknown ||
		kv.Adapter.Certificate.NotAfter == nil || len(kv.Adapter.Bindings) != 1 || kv.Adapter.Bindings[0].Hostname != "api.contoso.example.test" {
		t.Errorf("key vault backed: %+v %+v", kv.Adapter, kv.Adapter.Certificate)
	}
	accepted(t, cloudCore(t), res.Observations)
	res2, err := h.sync(t, cfg, res.Cursor)
	if err != nil || len(res2.Observations) != 0 || res2.Stats[azure.StatUnchanged] != 2 {
		t.Fatalf("delta: %v %d %v", err, len(res2.Observations), res2.Stats)
	}
}

func TestAppGatewayAndThrottling(t *testing.T) {
	f := newFake(t, "appgateway")
	path := "/subscriptions/" + subscriptionID + "/providers/Microsoft.Network/applicationGateways"
	f.throttle[path] = 2
	h := newHarness(f, allOn)
	cfg := config("edge", azure.NameAppGateway, map[string]string{"subscriptions": subscriptionID})
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String())
	if len(res.Observations) != 1 {
		t.Fatalf("got %d observations", len(res.Observations))
	}
	o := res.Observations[0]
	g := "/subscriptions/" + subscriptionID + "/resourceGroups/rg-edge/providers/Microsoft.Network/applicationGateways/agw-shop"
	want := []submit.Binding{
		{Hostname: "shop.contoso.example.test", Port: 443, ResourceID: g + "/httpListeners/shop-https"},
		{Hostname: "www.shop.contoso.example.test", Port: 443, ResourceID: g + "/httpListeners/shop-https"},
	}
	if o.Target.ResourceID != g+"/sslCertificates/shop-tls" || o.Adapter.Certificate.SHA1 != agwSHA1 || o.Adapter.RenewalMode != submit.RenewalManual ||
		fmt.Sprint(o.Adapter.Bindings) != fmt.Sprint(want) || o.Adapter.Certificate.CommonName != "shop.contoso.example.test" {
		t.Errorf("listener certificate (leaf of the PKCS#7 chain): %+v %+v", o.Target, o.Adapter)
	}
	if res.Stats[azure.StatThrottled] != 2 || res.Stats[azure.StatListenerNoHostname] != 1 || res.Stats[azure.StatSkippedNoCertificate] != 1 {
		t.Errorf("stats %v", res.Stats)
	}
	sleeps := h.clk.Sleeps()
	if fmt.Sprint(sleeps) != fmt.Sprint([]time.Duration{7 * time.Second, 7 * time.Second}) {
		t.Errorf("sleeps %v, want Retry-After 7s twice", sleeps)
	}
	accepted(t, cloudCore(t), res.Observations)
}

func TestThrottlingGivesUp(t *testing.T) {
	f := newFake(t, "appgateway")
	f.throttle["/subscriptions/"+subscriptionID+"/providers/Microsoft.Network/applicationGateways"] = 100
	h := newHarness(f, allOn)
	_, err := h.sync(t, config("edge", azure.NameAppGateway, map[string]string{"subscriptions": subscriptionID}), "")
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Fatalf("err %v", err)
	}
}

func TestEntra(t *testing.T) {
	f := newFake(t, "entra")
	h := newHarness(f, allOn)
	cfg := config("entra", azure.NameEntra, nil)
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String(), "Qx7", "Zr2")
	m := byID(res.Observations)
	if len(m) != 2 {
		t.Fatalf("got %d observations: %v", len(m), m)
	}
	app := "/applications/aaaaaaaa-0000-4000-8000-000000000001"
	k := m[app+"/keyCredentials/cccccccc-0000-4000-8000-000000000001"]
	if k.Outcome != submit.OutcomeCertSeen || k.Adapter.Certificate.SHA1 != kvSHA1 || k.Adapter.Certificate.NotAfter == nil || k.Adapter.Custody.KeyCustody != submit.KeyAbsent || k.Target.Host != "graph.microsoft.com" {
		t.Errorf("key credential: %+v %+v", k.Target, k.Adapter)
	}
	p := m[app+"/passwordCredentials/dddddddd-0000-4000-8000-000000000001"]
	if p.Outcome != submit.OutcomeReached || p.Adapter.Certificate != nil || len(p.Adapter.Findings) != 1 ||
		p.Adapter.Findings[0].Code != submit.FindingSecretCredentialExpiry || p.Adapter.Findings[0].NotAfter == nil ||
		!p.Adapter.Findings[0].NotAfter.Equal(time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("password credential: %+v", p.Adapter)
	}
	if res.Stats[azure.StatSkippedNoThumbprint] != 1 || res.Stats[azure.StatRemoved] != 1 {
		t.Errorf("stats %v", res.Stats)
	}
	if !strings.Contains(string(res.Cursor), "ZGVsdGEtdG9rZW4tMQ") {
		t.Errorf("cursor %s lacks the delta link", res.Cursor)
	}
	accepted(t, cloudCore(t), res.Observations)

	// The next sync follows the delta link and sees one new password credential.
	res2, err := h.sync(t, cfg, res.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Observations) != 1 || res2.Observations[0].Adapter.Findings[0].CredentialID != "dddddddd-0000-4000-8000-000000000009" ||
		!strings.Contains(string(res2.Cursor), "ZGVsdGEtdG9rZW4tMg") {
		t.Fatalf("delta: %+v %s", res2.Observations, res2.Cursor)
	}
	clean(t, res2, h.logs.String(), "Qx7", "Zr2")

	// An expired delta token (410) starts a full read again.
	expired, _ := adapter.EncodeCursor(map[string]string{"delta_link": "https://graph.microsoft.com/v1.0/applications/delta?$deltatoken=ZXhwaXJlZA"})
	res3, err := h.sync(t, cfg, expired)
	if err != nil || len(res3.Observations) != 2 || res3.Stats[azure.StatResync] != 1 {
		t.Fatalf("resync: %v %d %v", err, len(res3.Observations), res3.Stats)
	}
}

func TestEntraRefusesForeignDeltaLink(t *testing.T) {
	f := newFake(t, "entra")
	h := newHarness(f, allOn)
	evil, _ := adapter.EncodeCursor(map[string]string{"delta_link": "https://graph.example.test/v1.0/applications/delta?$deltatoken=x"})
	_, err := h.sync(t, config("entra", azure.NameEntra, nil), evil)
	if err == nil || !strings.Contains(err.Error(), "refusing to send a token") {
		t.Fatalf("err %v", err)
	}
	for _, host := range f.hosts {
		if host == "graph.example.test" {
			t.Fatal("a request went to the foreign host")
		}
	}
}

func TestKeyVaultRefusesForeignNextLink(t *testing.T) {
	f := newFake(t, "keyvault")
	f.override["/certificates"] = func(r *http.Request) *http.Response {
		return jsonResponse(r, 200, `{"value":[],"nextLink":"https://collector-test.example.test/certificates?$skiptoken=x"}`)
	}
	h := newHarness(f, allOn)
	_, err := h.sync(t, config("kv", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}), "")
	if err == nil || !strings.Contains(err.Error(), "refusing to send a token") {
		t.Fatalf("err %v", err)
	}
}

func TestDefender(t *testing.T) {
	f := newFake(t, "defender")
	h := newHarness(f, adapter.Features{LocalStoreV1: true})
	cfg := config("mde", azure.NameDefender, map[string]string{"page_size": "2"})
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	clean(t, res, h.logs.String())
	if len(res.Observations) != 3 {
		t.Fatalf("got %d observations", len(res.Observations))
	}
	m := byID(res.Observations)
	dev2 := "89abcdef0123456789abcdef0123456789abcdef"
	for k, want := range map[string]string{
		"web01.contoso.example.test|windows/LocalMachine/My|" + kvSHA1: "",
		"web01.contoso.example.test|windows/CurrentUser/My|" + pemSHA1: "",
		dev2 + "|windows/defender/other|" + webSHA1:                    `C:\ProgramData\Contoso\agent\client.cer`,
	} {
		o, ok := m[k]
		if !ok || o.Target.Kind != submit.KindStore || o.Target.Path != want || o.Adapter.Source != azure.NameDefender || o.Adapter.Custody.KeyCustody != submit.KeyUnknown {
			t.Errorf("%s: %+v", k, o)
		}
	}
	reqs := f.fixtures.Requests()
	if len(reqs) != 2 {
		t.Fatalf("%d hunting requests, want 2 pages", len(reqs))
	}
	b, _ := io.ReadAll(reqs[1].Body)
	if !bytes.Contains(b, []byte("DeviceTvmCertificateInfo")) || !bytes.Contains(b, []byte(`take 2`)) {
		t.Errorf("query %s", b)
	}
	// Store observations are in the vendored 0.9.0 contract.
	accepted(t, vendoredCore(t), res.Observations)

	// Not due again before min_interval.
	res2, err := h.sync(t, cfg, res.Cursor)
	if err != nil || len(res2.Observations) != 0 || res2.Stats[azure.StatNotDue] != 1 || len(f.fixtures.Requests()) != 2 {
		t.Fatalf("not due: %v %d %v", err, len(res2.Observations), res2.Stats)
	}
	h.clk.Advance(25 * time.Hour)
	res3, err := h.sync(t, cfg, res.Cursor)
	if err != nil || len(res3.Observations) != 3 {
		t.Fatalf("after interval: %v %d", err, len(res3.Observations))
	}
}

// TestFeatureSwitchesOff: with the switches off nothing outside the
// current core contract is sent, the skip is counted and logged, and the
// cursor stays where it was.
func TestFeatureSwitchesOff(t *testing.T) {
	cases := []struct {
		dir, kind string
		settings  map[string]string
		env       string
	}{
		{"keyvault", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}, adapter.EnvCloudResourceV1},
		{"appservice", azure.NameAppService, map[string]string{"subscriptions": subscriptionID}, adapter.EnvCloudResourceV1},
		{"appgateway", azure.NameAppGateway, map[string]string{"subscriptions": subscriptionID}, adapter.EnvCloudResourceV1},
		{"entra", azure.NameEntra, nil, adapter.EnvCloudResourceV1},
		{"defender", azure.NameDefender, map[string]string{"page_size": "2"}, adapter.EnvLocalStoreV1},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			f := newFake(t, c.dir)
			// The other switch on: it must not open this adapter's shape.
			feats := adapter.Features{LocalStoreV1: true}
			if c.env == adapter.EnvLocalStoreV1 {
				feats = adapter.Features{CloudResourceV1: true}
			}
			h := newHarness(f, feats)
			since := adapter.Cursor("")
			res, err := h.sync(t, config("x", c.kind, c.settings), since)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Observations) != 0 || res.Stats[azure.StatSkippedFeatureDisabled] == 0 || res.Cursor != since {
				t.Fatalf("observations %d, stats %v, cursor %q", len(res.Observations), res.Stats, res.Cursor)
			}
			if !strings.Contains(h.logs.String(), c.env) {
				t.Errorf("log does not name %s: %s", c.env, h.logs.String())
			}
			clean(t, res, h.logs.String())
		})
	}
}

// TestCloudShapeRejectedByCurrentContract shows why the switch exists: the
// vendored 0.9.0 contract refuses a cloud_resource observation.
func TestCloudShapeRejectedByCurrentContract(t *testing.T) {
	f := newFake(t, "appservice")
	h := newHarness(f, allOn)
	res, err := h.sync(t, config("web", azure.NameAppService, map[string]string{"subscriptions": subscriptionID}), "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := submittest.LoadSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(submit.ObservationBatch{Observations: res.Observations[:1]})
	if err := spec.Validate("ObservationBatch", b); err == nil {
		t.Fatal("the vendored contract accepted a cloud_resource observation")
	}
	prop, err := submittest.LoadSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := prop.Validate("ObservationBatch", b); err != nil {
		t.Fatalf("proposal refused it: %v", err)
	}
}

func TestAuthFailure(t *testing.T) {
	f := newFake(t, "keyvault")
	f.tokenFail = http.StatusUnauthorized
	h := newHarness(f, allOn)
	res, err := h.sync(t, config("kv", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}), "")
	if !errors.Is(err, azure.ErrAuth) {
		t.Fatalf("err %v, want ErrAuth", err)
	}
	if strings.Contains(err.Error(), clientSecretValue) || strings.Contains(err.Error(), "AADSTS") || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error text %q", err)
	}
	clean(t, res, h.logs.String())

	// A missing credential reference is an authentication error too.
	f2 := newFake(t, "keyvault")
	h2 := newHarness(f2, allOn)
	h2.env.Creds = staticCreds{}
	if _, err := h2.sync(t, config("kv", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}), ""); !errors.Is(err, azure.ErrAuth) {
		t.Fatalf("missing credential: %v", err)
	}

	// 403 from the API: no retry, ErrAuth.
	f3 := newFake(t, "keyvault")
	f3.override["/certificates"] = func(r *http.Request) *http.Response {
		return jsonResponse(r, 403, `{"error":{"code":"Forbidden","message":"Caller is not authorized"}}`)
	}
	h3 := newHarness(f3, allOn)
	_, err = h3.sync(t, config("kv", azure.NameKeyVault, map[string]string{"vaults": "kv-contoso-prod"}), "")
	if !errors.Is(err, azure.ErrAuth) || !strings.Contains(err.Error(), "HTTP 403") || len(h3.clk.Sleeps()) != 0 {
		t.Fatalf("403: %v, sleeps %v", err, h3.clk.Sleeps())
	}
}

func TestManagedIdentity(t *testing.T) {
	f := newFake(t, "entra")
	h := newHarness(f, allOn)
	h.env.Creds = staticCreds{}
	cfg := adapter.Config{Name: "entra", Adapter: azure.NameEntra, Settings: map[string]string{"auth": azure.AuthManagedIdentity}}
	res, err := h.sync(t, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Observations) != 2 || f.imdsCalls != 1 || len(f.tokenCalls) != 0 {
		t.Fatalf("observations %d, imds %d, token endpoint %v", len(res.Observations), f.imdsCalls, f.tokenCalls)
	}
	clean(t, res, h.logs.String())
}

func TestValidate(t *testing.T) {
	bad := []adapter.Config{
		config("a", azure.NameKeyVault, nil), // no vaults
		config("a", azure.NameKeyVault, map[string]string{"vaults": "Not_A_Vault!"}),
		config("a", azure.NameKeyVault, map[string]string{"vaults": "kv1x", "read_pem_entries": "maybe"}),
		config("a", azure.NameAppService, nil), // no subscriptions
		config("a", azure.NameAppGateway, map[string]string{"subscriptions": "prod"}),
		config("a", azure.NameDefender, map[string]string{"page_size": "0"}),
		config("a", azure.NameDefender, map[string]string{"min_interval": "daily"}),
		config("a", azure.NameEntra, map[string]string{"auth": "password"}),
		config("a", azure.NameEntra, map[string]string{"client_id": "not-a-guid"}),
		config("a", azure.NameEntra, map[string]string{"rate_per_second": "-1"}),
		{Name: "a", Adapter: azure.NameEntra, Settings: map[string]string{"tenant_id": tenantID, "client_id": clientID}}, // no client_secret reference
	}
	for i, cfg := range bad {
		f, _ := adapter.Lookup(cfg.Adapter)
		if err := f(adapter.Env{}).Validate(cfg); err == nil {
			t.Errorf("config %d accepted: %+v", i, cfg.Settings)
		}
	}
	good := config("a", azure.NameKeyVault, map[string]string{"vaults": "https://KV-Contoso-Prod.vault.azure.net/"})
	f, _ := adapter.Lookup(azure.NameKeyVault)
	if err := f(adapter.Env{}).Validate(good); err != nil {
		t.Errorf("vault URL form refused: %v", err)
	}
}
