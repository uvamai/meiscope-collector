package egress_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

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
	now := time.Now()
	sysCA := testpki.NewRoot(t, "system-trusted CA", now)
	bundleCA := testpki.NewRoot(t, "bundle CA", now)
	leaf, key := sysCA.Issue(t, testpki.LeafTemplate("core.test", now.Add(-time.Hour), 24*time.Hour, "127.0.0.1"))
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	sysFile := filepath.Join(dir, "system.pem")
	bundle := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(sysFile, []byte(testpki.PEM(sysCA.Cert)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte(testpki.PEM(bundleCA.Cert)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Go reads the system roots once per process, so the two requests run in a
	// child process that starts with SSL_CERT_FILE already set.
	cmd := exec.Command(os.Args[0], "-test.run=^TestPinnedChild$")
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+sysFile, "SSL_CERT_DIR="+dir+"/none", "PIN_URL="+srv.URL, "PIN_BUNDLE="+bundle)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("server saw %d requests, want 1 (the control only)", n)
	}
}

// TestPinnedChild runs only inside TestPinnedOnlyIgnoresSystemRoots.
func TestPinnedChild(t *testing.T) {
	url, bundle := os.Getenv("PIN_URL"), os.Getenv("PIN_BUNDLE")
	if url == "" {
		t.Skip("helper for TestPinnedOnlyIgnoresSystemRoots")
	}
	for _, pinned := range []bool{false, true} {
		tr, err := egress.Transport(egress.Config{CABundle: bundle}, nil, egress.Options{PinnedOnly: pinned})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := egress.Client(tr, 0).Get(url)
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
}
