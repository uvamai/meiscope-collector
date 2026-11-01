package egress_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

const (
	proxyUser = "svc-collector"
	proxyPass = "pr0xy-p4ssw0rd-synthetic"
)

type credSource map[string]string

func (c credSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := c[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

// connectProxy is a forward proxy that tunnels CONNECT only and, when
// auth is set, requires Basic Proxy-Authorization.
type connectProxy struct {
	*httptest.Server
	mu       sync.Mutex
	connects []string
	denied   int
}

func newProxy(t *testing.T, auth string) *connectProxy {
	t.Helper()
	p := &connectProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if auth != "" && r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)) {
			p.mu.Lock()
			p.denied++
			p.mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		up, err := net.DialTimeout("tcp", r.Host, 5*time.Second) //nolint:gosec // the test proxy dials the test core
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		p.mu.Lock()
		p.connects = append(p.connects, r.Host)
		p.mu.Unlock()
		hj, _ := w.(http.Hijacker)
		c, _, err := hj.Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *connectProxy) seen() ([]string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...), p.denied
}

func caFile(t *testing.T, core *submittest.Core) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: core.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func obs() submit.Observation {
	return submit.Observation{
		Target: submit.Target{Kind: submit.KindFile, Host: "app01.example.test", Path: "/opt/a.jks"}, Method: submit.MethodAdapter,
		ObservedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{Source: "osquery", File: &submit.FileDigest{SHA256: strings.Repeat("ab", 32)}},
	}
}

// TestSubmissionThroughAuthenticatedProxy: with a proxy configured, the
// submission reaches the core through CONNECT with the credential from the
// credential source, and the credential appears in no log or error.
func TestSubmissionThroughAuthenticatedProxy(t *testing.T) {
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	proxy := newProxy(t, proxyUser+":"+proxyPass)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := egress.Config{ProxyURL: proxy.URL, CredentialRef: "proxy_credential", CABundle: caFile(t, core)} //nolint:gosec // test-only, synthetic value
	creds := credSource{"proxy_credential": proxyUser + ":" + proxyPass}
	tr, err := egress.Transport(cfg, creds, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := submit.New(core.URL, egress.Client(tr, 10*time.Second))
	res, err := cl.Submit(context.Background(), []submit.Observation{obs()})
	if err != nil || res.Accepted != 1 {
		t.Fatalf("%+v %v; core errors %v", res, err, core.Errors())
	}
	connects, denied := proxy.seen()
	coreHost := strings.TrimPrefix(core.URL, "https://")
	if len(connects) != 1 || connects[0] != coreHost || denied != 0 {
		t.Fatalf("proxy saw connects %v (want %s), denied %d", connects, coreHost, denied)
	}
	log.Info("submitted", "config", cfg, "result", res)
	assertNoSecret(t, logs.String())
}

func assertNoSecret(t *testing.T, s string) {
	t.Helper()
	for _, leak := range []string{proxyPass, base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))} {
		if strings.Contains(s, leak) {
			t.Fatalf("credential in output: %s", s)
		}
	}
}

func TestProxyFailuresNeverLeakCredential(t *testing.T) {
	core, _ := submittest.NewProposedCore()
	defer core.Close()
	ca := caFile(t, core)
	// The proxy wants other credentials: 407, and the error must not show ours.
	proxy := newProxy(t, "someone:else")
	cfg := egress.Config{ProxyURL: proxy.URL, CredentialRef: "proxy_credential", CABundle: ca} //nolint:gosec // test-only, synthetic value
	tr, err := egress.Transport(cfg, credSource{"proxy_credential": proxyUser + ":" + proxyPass}, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := submit.New(core.URL, egress.Client(tr, 5*time.Second), submit.WithRetry(retry.Policy{Attempts: 0}))
	_, err = cl.Submit(context.Background(), []submit.Observation{obs()})
	if err == nil {
		t.Fatal("submission succeeded with the wrong proxy credential")
	}
	assertNoSecret(t, err.Error())
	if _, denied := proxy.seen(); denied == 0 {
		t.Fatal("proxy never saw the request")
	}

	// A missing credential names the reference, never a value.
	tr, _ = egress.Transport(cfg, credSource{}, egress.Options{})
	cl, _ = submit.New(core.URL, egress.Client(tr, 5*time.Second), submit.WithRetry(retry.Policy{Attempts: 0}))
	if _, err = cl.Submit(context.Background(), []submit.Observation{obs()}); err == nil || !strings.Contains(err.Error(), "proxy_credential") {
		t.Fatalf("missing credential: %v", err)
	}
	// A malformed credential value is not echoed.
	tr, _ = egress.Transport(cfg, credSource{"proxy_credential": "no-colon-secret-value"}, egress.Options{})
	cl, _ = submit.New(core.URL, egress.Client(tr, 5*time.Second), submit.WithRetry(retry.Policy{Attempts: 0}))
	if _, err = cl.Submit(context.Background(), []submit.Observation{obs()}); err == nil || strings.Contains(err.Error(), "no-colon-secret-value") {
		t.Fatalf("malformed credential: %v", err)
	}
}

func TestUserinfoInProxyURLRefused(t *testing.T) {
	for _, u := range []string{"http://" + proxyUser + ":" + proxyPass + "@proxy.example.test:3128", "http://" + proxyUser + "@proxy.example.test:3128"} {
		_, err := egress.Transport(egress.Config{ProxyURL: u}, nil, egress.Options{})
		if !errors.Is(err, egress.ErrProxyUserinfo) {
			t.Fatalf("%s: %v", u, err)
		}
		assertNoSecret(t, err.Error())
	}
	// The same through the environment is refused at request time.
	env := func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + proxyUser + ":" + proxyPass + "@proxy.example.test:3128")
	}
	tr, err := egress.Transport(egress.Config{}, nil, egress.Options{EnvProxy: env})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://core.example.test/", nil)
	_, perr := tr.Proxy(req)
	if !errors.Is(perr, egress.ErrProxyUserinfo) {
		t.Fatalf("env proxy: %v", perr)
	}
	assertNoSecret(t, perr.Error())
}

func TestConfigErrors(t *testing.T) {
	for name, cfg := range map[string]egress.Config{
		"scheme":    {ProxyURL: "socks5://p.example.test:1080"},
		"no host":   {ProxyURL: "http://"},
		"not a URL": {ProxyURL: "http://%zz"},
		"no bundle": {CABundle: filepath.Join(t.TempDir(), "missing.pem")},
	} {
		if _, err := egress.Transport(cfg, nil, egress.Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := egress.Transport(egress.Config{CABundle: bad}, nil, egress.Options{}); err == nil {
		t.Error("non-PEM bundle accepted")
	}
	if _, err := egress.Transport(egress.Config{CredentialRef: "x"}, nil, egress.Options{}); err == nil {
		t.Error("credential without a source accepted")
	}
	env := func(*http.Request) (*url.URL, error) { return nil, errors.New("bad") }
	tr, _ := egress.Transport(egress.Config{}, nil, egress.Options{EnvProxy: env})
	req, _ := http.NewRequest(http.MethodGet, "https://core.example.test/", nil)
	if _, err := tr.Proxy(req); err == nil {
		t.Error("invalid env proxy accepted")
	}
	cfg := egress.LoadConfig(func(k string) string {
		return map[string]string{"MEISCOPE_PROXY_URL": " http://p.example.test:3128 ", "MEISCOPE_NO_PROXY": "a", "MEISCOPE_PROXY_CREDENTIAL": "r", "MEISCOPE_CA_BUNDLE": "/ca"}[k]
	})
	if cfg.ProxyURL != "http://p.example.test:3128" || cfg.NoProxy != "a" || cfg.CredentialRef != "r" || cfg.CABundle != "/ca" {
		t.Fatalf("%+v", cfg)
	}
}

func TestNoProxyBypass(t *testing.T) {
	tr, err := egress.Transport(egress.Config{ProxyURL: "http://proxy.example.test:3128", NoProxy: "internal.example.test, .corp.test,10.0.0.0/8"}, nil, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for host, proxied := range map[string]bool{
		"core.example.test": true, "internal.example.test": false, "a.corp.test": false, "corp.test": false,
		"notcorp.test": true, "10.1.2.3": false, "11.1.2.3": true,
	} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		u, err := tr.Proxy(req)
		if err != nil || (u != nil) != proxied {
			t.Errorf("%s: proxy %v err %v, want proxied=%v", host, u, err, proxied)
		}
	}
	all, _ := egress.Transport(egress.Config{ProxyURL: "http://proxy.example.test:3128", NoProxy: "*"}, nil, egress.Options{})
	req, _ := http.NewRequest(http.MethodGet, "https://x.example.test/", nil)
	if u, _ := all.Proxy(req); u != nil {
		t.Error("* did not bypass")
	}
}

func TestEnvironmentProxyUsedWhenNotConfigured(t *testing.T) {
	core, _ := submittest.NewProposedCore()
	defer core.Close()
	proxy := newProxy(t, "")
	pu, _ := url.Parse(proxy.URL)
	tr, err := egress.Transport(egress.Config{CABundle: caFile(t, core)}, nil, egress.Options{EnvProxy: http.ProxyURL(pu)})
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := submit.New(core.URL, egress.Client(tr, 10*time.Second))
	if res, err := cl.Submit(context.Background(), []submit.Observation{obs()}); err != nil || res.Accepted != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if c, _ := proxy.seen(); len(c) != 1 {
		t.Fatalf("connects %v", c)
	}
}
