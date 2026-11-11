package identity_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// enrolled enrols a fresh key against core and saves it in a temp dir.
func enrolled(t *testing.T, core *enroltest.Core) (*identity.Store, string) {
	t.Helper()
	key, err := identity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := enrol.New(core.URL, core.Client(), "test")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := cl.Enrol(context.Background(), "mse1_"+t.Name(), csr)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	s, err := identity.Save(dir, core.URL, key, cred)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestCSRAsksForNothing(t *testing.T) {
	key, err := identity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := identity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(p))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a PEM CSR: %q", p)
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(csr.Subject.Names) != 0 || len(csr.Extensions) != 0 || len(csr.Attributes) != 0 ||
		len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) != 0 {
		t.Fatalf("CSR asks for something: %+v", csr)
	}
	if strings.Contains(p, "PRIVATE KEY") {
		t.Fatal("the CSR must not carry the private key")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	core := enroltest.NewCore(t)
	s, dir := enrolled(t, core)
	if s.CollectorID() != enroltest.CollectorID || s.CoreURL() != core.URL {
		t.Fatalf("id %q core %q", s.CollectorID(), s.CoreURL())
	}
	got, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.CollectorID() != s.CollectorID() || got.CoreURL() != s.CoreURL() ||
		!got.NotAfter().Equal(s.NotAfter()) || len(got.ScopeKeys()) != 1 ||
		got.ScopeKeys()[0] != core.ScopeKeys()[0] {
		t.Fatalf("loaded %+v, saved %+v", got, s)
	}
	if !identity.Exists(dir) {
		t.Fatal("Exists is false after Save")
	}
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(filepath.Join(dir, "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("identity.pem mode %v, want 0600", st.Mode().Perm())
	}
	ds, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ds.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v, want 0700", ds.Mode().Perm())
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("leftover temporary file %s", e.Name())
		}
	}
}

func TestLoadRefusesIdentityReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	core := enroltest.NewCore(t)
	_, dir := enrolled(t, core)
	if err := os.Chmod(filepath.Join(dir, "identity.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(dir); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("err %v, want a refusal that names 0600", err)
	}
}

func TestLoadNotEnrolled(t *testing.T) {
	if _, err := identity.Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "enrol") {
		t.Fatalf("err %v", err)
	}
}

func TestSaveRefusesBadCredentials(t *testing.T) {
	core := enroltest.NewCore(t)
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key)
	cl, _ := enrol.New(core.URL, core.Client(), "test")
	good, err := cl.Enrol(context.Background(), "mse1_good", csr)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := identity.NewKey()
	cases := map[string]func(c *identity.Credentials){
		"no collector id": func(c *identity.Credentials) { c.CollectorID = "" },
		"no certificate":  func(c *identity.Credentials) { c.CertificateChain = "" },
		"wrong block": func(c *identity.Credentials) {
			c.CertificateChain = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
		},
		"no CA bundle": func(c *identity.Credentials) { c.CABundle = "not pem" },
		"no scope key": func(c *identity.Credentials) { c.ScopeSigningKeys = nil },
		"three scope keys": func(c *identity.Credentials) {
			c.ScopeSigningKeys = append(c.ScopeSigningKeys, c.ScopeSigningKeys[0], c.ScopeSigningKeys[0])
		},
		"short scope key": func(c *identity.Credentials) { c.ScopeSigningKeys[0].PublicKey = "AAAA" },
		"bad key id":      func(c *identity.Credentials) { c.ScopeSigningKeys[0].KeyID = "Bad Key" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			c.ScopeSigningKeys = append([]identity.ScopeSigningKey(nil), good.ScopeSigningKeys...)
			mutate(&c)
			if _, err := identity.Save(filepath.Join(t.TempDir(), "s"), core.URL, key, c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("certificate for another key", func(t *testing.T) {
		if _, err := identity.Save(filepath.Join(t.TempDir(), "s"), core.URL, other, good); err == nil {
			t.Fatal("accepted a certificate that is not for the key")
		}
	})
}

func TestRenewAtTwoThirds(t *testing.T) {
	core := enroltest.NewCore(t)
	core.Lifetime = 30 * 24 * time.Hour
	s, _ := enrolled(t, core)
	want := s.NotBefore().Add(s.NotAfter().Sub(s.NotBefore()) * 2 / 3)
	if !s.RenewAt().Equal(want) {
		t.Fatalf("RenewAt %v, want %v", s.RenewAt(), want)
	}
	if d := s.RenewAt().Sub(s.NotBefore()); d < 19*24*time.Hour || d > 21*24*time.Hour {
		t.Fatalf("renewal %v after issuance, want about 20 days", d)
	}
}

func get(t *testing.T, hc *http.Client, url string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestTransportPresentsCertificateAndFollowsRenewal(t *testing.T) {
	core := enroltest.NewCore(t)
	s, dir := enrolled(t, core)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: s.Transport(core.Transport())}
	if code := get(t, hc, core.URL+"/collector/v1/scopes"); code != http.StatusOK {
		t.Fatalf("GET /scopes over mTLS: %d", code)
	}
	first := core.LastClientSerial()

	// Renew with a new key; the same client must present the new certificate.
	key2, _ := identity.NewKey()
	csr2, _ := identity.CSR(key2)
	cl, _ := enrol.New(core.URL, hc, "test")
	cred, err := cl.Renew(context.Background(), csr2)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(key2, cred); err != nil {
		t.Fatal(err)
	}
	if code := get(t, hc, core.URL+"/collector/v1/scopes"); code != http.StatusOK {
		t.Fatalf("GET /scopes after renewal: %d", code)
	}
	second := core.LastClientSerial()
	if second == first {
		t.Fatal("the transport still presents the old certificate after Replace")
	}
	// The renewed identity is what a restart loads.
	got, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter().Equal(s.NotAfter()) {
		t.Fatal("Load does not return the renewed certificate")
	}
}

func TestTransportTrustsOnlyThePinnedCA(t *testing.T) {
	core := enroltest.NewCore(t)
	s, _ := enrolled(t, core)
	other := enroltest.NewCore(t) // a different CA
	hc := &http.Client{Timeout: 10 * time.Second, Transport: s.Transport(nil)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, other.URL+"/collector/v1/scopes", http.NoBody)
	if resp, err := hc.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("connected to a core whose certificate is not from the pinned CA")
	}
}

func TestReplaceRefusesAnotherCollector(t *testing.T) {
	core := enroltest.NewCore(t)
	s, _ := enrolled(t, core)
	key, _ := identity.NewKey()
	ca := testpki.NewRoot(t, "x", time.Now())
	leaf := testpki.Create(t, testpki.LeafTemplate("x", time.Now(), time.Hour), ca.Cert, key.Public(), ca.Key)
	cred := identity.Credentials{
		CollectorID: "another", CertificateChain: testpki.PEM(leaf), CABundle: testpki.PEM(ca.Cert),
		ScopeSigningKeys: s.ScopeKeys(),
	}
	if err := s.Replace(key, cred); err == nil {
		t.Fatal("Replace accepted credentials for another collector")
	}
}
