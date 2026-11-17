package egress_test

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/egress"
)

func pemOf(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedOnlyNeedsABundle(t *testing.T) {
	_, err := egress.Transport(egress.Config{}, nil, egress.Options{PinnedOnly: true})
	if !errors.Is(err, egress.ErrNoPinnedCA) {
		t.Fatalf("err = %v", err)
	}
	if _, err := egress.Transport(egress.Config{}, nil, egress.Options{}); err != nil {
		t.Fatalf("unpinned, no bundle: %v", err)
	}
}

// AC-G3-14: a server certificate the system trusts but the bundle does not is
// refused when pinned, and accepted when not (the positive control). The
// system store is faked with SSL_CERT_FILE, which Go reads on Linux only.
func TestPinnedOnlyIgnoresSystemRoots(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SSL_CERT_FILE sets the system roots on Linux only")
	}
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer srv.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()

	dir := t.TempDir()
	sysFile := filepath.Join(dir, "system.pem")
	bundle := filepath.Join(dir, "bundle.pem")
	pemOf(t, srv, sysFile)  // trusted by the "system" only
	pemOf(t, other, bundle) // the bundle holds a different CA
	t.Setenv("SSL_CERT_FILE", sysFile)
	t.Setenv("SSL_CERT_DIR", dir+"/none")

	for _, pinned := range []bool{false, true} {
		tr, err := egress.Transport(egress.Config{CABundle: bundle}, nil, egress.Options{PinnedOnly: pinned})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := egress.Client(tr, 0).Get(srv.URL)
		if !pinned {
			if err != nil {
				t.Fatalf("control: the system-trusted server was refused: %v", err)
			}
			_ = resp.Body.Close()
			continue
		}
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("pinned: a certificate outside the bundle was accepted")
		}
	}
	if hits != 1 {
		t.Fatalf("server saw %d requests, want 1 (the control only)", hits)
	}
}
