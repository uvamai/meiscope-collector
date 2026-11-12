package egress_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/redirect"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// TestCABundleOnlyTrustsOnlyTheBundle: with CABundleOnly the transport's
// roots are exactly the bundle (no system roots); without it the bundle is
// added to the system pool.
func TestCABundleOnlyTrustsOnlyTheBundle(t *testing.T) {
	now := time.Now()
	ca := testpki.NewRoot(t, "core test CA", now)
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, []byte(testpki.PEM(ca.Cert)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{CABundle: p}
	only, err := egress.Transport(cfg, nil, egress.Options{CABundleOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(ca.Cert)
	if !only.TLSClientConfig.RootCAs.Equal(want) {
		t.Fatal("CABundleOnly: the roots are not exactly the bundle")
	}

	// The bundle-only transport still reaches a server under the bundle CA,
	// and refuses one under another CA (as the system roots would not help).
	leaf, key := ca.Issue(t, testpki.LeafTemplate("core", now.Add(-time.Hour), 24*time.Hour, "127.0.0.1"))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	hc := egress.Client(only, 5*time.Second)
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("bundle-only transport refused a server under the bundle CA: %v", err)
	}
	_ = resp.Body.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer other.Close()
	resp, err = hc.Get(other.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("bundle-only transport trusted a server outside the bundle")
	}

	if sys, serr := x509.SystemCertPool(); serr == nil && sys != nil && !sys.Equal(x509.NewCertPool()) {
		merged, err := egress.Transport(cfg, nil, egress.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if merged.TLSClientConfig.RootCAs.Equal(want) {
			t.Fatal("default: the system roots were dropped")
		}
	}
}

// TestClientDoesNotFollowRedirects: a 307 from the configured URL to another
// server is returned as it is; the other server never sees the body or the
// Authorization header, and redirect.Check names the refusal.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal?token=x", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	hc := egress.Client(http.DefaultTransport, 5*time.Second)
	req, err := http.NewRequest(http.MethodPost, origin.URL+"/collector/v1/observations", strings.NewReader(`{"secret-body":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer synthetic-token")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || hits.Load() != 0 {
		t.Fatalf("status %d, redirect target hit %d times", resp.StatusCode, hits.Load())
	}
	rerr := redirect.Check(resp)
	if !errors.Is(rerr, redirect.ErrRefused) || !strings.Contains(rerr.Error(), "307") || strings.Contains(rerr.Error(), "token=x") {
		t.Fatalf("redirect error %v", rerr)
	}
}
