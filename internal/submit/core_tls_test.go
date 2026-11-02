package submit_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// The collector-to-core connection uses full certificate verification and
// TLS 1.2 or later, through both the default client and the egress
// transport. Only pkg/probe may relax TLS (see internal/tlsguard).
func TestCoreConnectionVerifiesTLS(t *testing.T) {
	now := time.Now()
	root := testpki.NewRoot(t, "Core Test Root", now)
	other := testpki.NewRoot(t, "Other Root", now)
	leaf, key := root.Issue(t, testpki.LeafTemplate("core.example.test", now.Add(-time.Hour), 24*time.Hour, "core.example.test"))
	expired, ekey := root.Issue(t, testpki.LeafTemplate("core.example.test", now.Add(-48*time.Hour), 24*time.Hour, "core.example.test"))
	bundle := filepath.Join(t.TempDir(), "core-ca.pem")
	if err := os.WriteFile(bundle, []byte(testpki.PEM(root.Cert)), 0o600); err != nil {
		t.Fatal(err)
	}
	otherBundle := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(otherBundle, []byte(testpki.PEM(other.Cert)), 0o600); err != nil {
		t.Fatal(err)
	}

	server := func(cert tls.Certificate, maxVersion uint16) string {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"domains":["example.test"]}`)
		}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion}
		s.StartTLS()
		t.Cleanup(s.Close)
		_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
		return "https://core.example.test:" + port
	}
	good := server(testpki.TLSCertificate(leaf, key), 0)
	legacy := server(testpki.TLSCertificate(leaf, key), tls.VersionTLS11)
	stale := server(testpki.TLSCertificate(expired, ekey), 0)

	// core.example.test resolves to the test server on loopback.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	client := func(caBundle string) *http.Client {
		tr, err := egress.Transport(egress.Config{CABundle: caBundle}, nil, egress.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.Fatalf("egress TLS config %+v", tr.TLSClientConfig)
		}
		tr.Proxy = nil
		tr.DialContext = dial
		return egress.Client(tr, 10*time.Second)
	}
	defaultClient := func() *http.Client {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DialContext = dial
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}

	for _, tc := range []struct {
		name, url string
		hc        *http.Client
		wantErr   string
	}{
		{"trusted core", good, client(bundle), ""},
		{"TLS 1.1 only", legacy, client(bundle), "protocol version"},
		{"expired certificate", stale, client(bundle), "certificate"},
		{"untrusted root", good, client(otherBundle), "certificate"},
		{"system roots only", good, client(""), "certificate"},
		{"default transport, untrusted", good, defaultClient(), "certificate"},
		{"default transport, TLS 1.1", legacy, defaultClient(), "protocol version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := submit.New(tc.url, tc.hc, submit.WithRetry(retry.Policy{}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.OwnedDomains(context.Background())
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("trusted core refused: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
