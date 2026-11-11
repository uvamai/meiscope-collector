// Package enroltest is a fake Meiscope core for tests: a TLS server with its
// own test CA that serves the enrolment surface of collector contract 0.9.0
// (POST /collector/v1/enrol, POST /collector/v1/certificate) and, over
// mTLS, GET /collector/v1/scopes. Certificates are issued for the CSR's
// public key, as the real core does.
package enroltest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// Tokens the fake core answers specially; any other non-empty token is
// redeemed once.
const (
	TokenUsed = "mse1_used" // 401
	TokenDup  = "mse1_dup"  // 409
	TokenBusy = "mse1_busy" // 503
)

// CollectorID is the id the fake core gives every collector.
const CollectorID = "0b7f3c52-6a2e-4c61-9d4b-2f8e1a7c5d10"

// Core is a running fake core.
type Core struct {
	URL      string
	CA       *testpki.CA
	ScopeKey ed25519.PrivateKey
	KeyID    string
	// Lifetime of issued collector certificates (default 30 days).
	Lifetime time.Duration

	srv *httptest.Server
	t   testing.TB

	mu       sync.Mutex
	redeemed map[string]bool
	scopes   []byte // GET /scopes answer
	// ClientSerials records the serial of the client certificate of each
	// authenticated request, in order.
	ClientSerials []string
	// Bodies records each request body by path (tests assert on what was
	// sent, e.g. that no private key was).
	Bodies map[string][][]byte
}

// NewCore starts a fake core and stops it at the end of the test.
func NewCore(t testing.TB) *Core {
	t.Helper()
	now := time.Now()
	ca := testpki.NewRoot(t, "fake core CA", now)
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &Core{
		CA: ca, ScopeKey: sk, KeyID: "scope-test-1", Lifetime: 30 * 24 * time.Hour,
		t: t, redeemed: map[string]bool{}, Bodies: map[string][][]byte{},
		scopes: []byte(`{"scopes":[]}`),
	}
	leaf, key := ca.Issue(t, testpki.LeafTemplate("core.test", now.Add(-time.Hour), 24*time.Hour, "127.0.0.1"))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)},
		ClientAuth:   tls.VerifyClientCertIfGiven, // as the real core: /enrol needs none
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c.srv = srv
	c.URL = srv.URL
	return c
}

// CAPEM is the core's CA certificate, PEM.
func (c *Core) CAPEM() string { return testpki.PEM(c.CA.Cert) }

// CAFile writes the CA certificate to a file in dir and returns its path
// (MEISCOPE_CA_BUNDLE for the first contact).
func (c *Core) CAFile(dir string) string {
	c.t.Helper()
	p := filepath.Join(dir, "core-ca.pem")
	if err := os.WriteFile(p, []byte(c.CAPEM()), 0o600); err != nil {
		c.t.Fatal(err)
	}
	return p
}

// Client is an HTTP client that trusts the core but presents no client
// certificate (the first contact).
func (c *Core) Client() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(c.CA.Cert)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}}
}

// Transport is a plain transport (no TLS settings) to wrap with
// identity.Store.Transport.
func (c *Core) Transport() *http.Transport { return &http.Transport{} }

// ScopeKeys returns the pinned-key list the core hands out.
func (c *Core) ScopeKeys() []identity.ScopeSigningKey {
	pub, _ := c.ScopeKey.Public().(ed25519.PublicKey)
	return []identity.ScopeSigningKey{{KeyID: c.KeyID, PublicKey: base64.StdEncoding.EncodeToString(pub)}}
}

// SetScopes sets the GET /scopes answer: each payload is signed with the
// core's scope key.
func (c *Core) SetScopes(payloads ...[]byte) {
	type signed struct {
		Payload   json.RawMessage `json:"payload"`
		Signature []byte          `json:"signature"`
		KeyID     string          `json:"key_id"`
	}
	list := struct {
		Scopes []signed `json:"scopes"`
	}{Scopes: []signed{}}
	for _, p := range payloads {
		list.Scopes = append(list.Scopes, signed{Payload: p, Signature: ed25519.Sign(c.ScopeKey, p), KeyID: c.KeyID})
	}
	b, err := json.Marshal(list)
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.scopes = b
	c.mu.Unlock()
}

// LastClientSerial is the serial of the client certificate of the last
// authenticated request ("" if none).
func (c *Core) LastClientSerial() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ClientSerials) == 0 {
		return ""
	}
	return c.ClientSerials[len(c.ClientSerials)-1]
}

// BodiesFor returns the request bodies received on path, in order.
func (c *Core) BodiesFor(path string) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.Bodies[path]...)
}

// Requests returns how many requests reached path.
func (c *Core) Requests(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.Bodies[path])
}

func problem(w http.ResponseWriter, status int, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status})
}

func (c *Core) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	c.mu.Lock()
	c.Bodies[r.URL.Path] = append(c.Bodies[r.URL.Path], body)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		c.ClientSerials = append(c.ClientSerials, r.TLS.PeerCertificates[0].SerialNumber.String())
	}
	c.mu.Unlock()

	authed := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/collector/v1/enrol":
		var req struct {
			Token string `json:"token"`
			CSR   string `json:"csr"`
		}
		if json.Unmarshal(body, &req) != nil || req.CSR == "" {
			problem(w, http.StatusBadRequest, "malformed request")
			return
		}
		c.mu.Lock()
		used := c.redeemed[req.Token]
		c.mu.Unlock()
		switch {
		case req.Token == TokenUsed || used:
			problem(w, http.StatusUnauthorized, "token refused")
			return
		case req.Token == TokenDup:
			problem(w, http.StatusConflict, "collector name exists")
			return
		case req.Token == TokenBusy:
			problem(w, http.StatusServiceUnavailable, "CA did not issue")
			return
		}
		cred, err := c.issue(req.CSR)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		c.mu.Lock()
		c.redeemed[req.Token] = true
		c.mu.Unlock()
		writeCred(w, cred)
	case r.Method == http.MethodPost && r.URL.Path == "/collector/v1/certificate":
		if !authed {
			problem(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if json.Unmarshal(body, &req) != nil {
			problem(w, http.StatusBadRequest, "malformed request")
			return
		}
		cred, err := c.issue(req.CSR)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		writeCred(w, cred)
	case r.Method == http.MethodGet && r.URL.Path == "/collector/v1/scopes":
		if !authed {
			problem(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		c.mu.Lock()
		b := c.scopes
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	default:
		problem(w, http.StatusNotFound, "not found")
	}
}

func writeCred(w http.ResponseWriter, cred identity.Credentials) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cred)
}

// issue checks the CSR as the core does (self-signed, asks for nothing) and
// issues a client certificate for its public key.
func (c *Core) issue(csrPEM string) (identity.Credentials, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return identity.Credentials{}, fmt.Errorf("not a PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return identity.Credentials{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return identity.Credentials{}, err
	}
	if len(csr.Subject.Names) != 0 || len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.URIs) != 0 {
		return identity.Credentials{}, fmt.Errorf("the CSR asks for something")
	}
	now := time.Now()
	u, _ := url.Parse("urn:meiscope:collector:5e0c2a7d-0000-4000-8000-000000000001:" + CollectorID)
	tmpl := &x509.Certificate{
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(c.Lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{u},
	}
	tmpl.Subject.CommonName = CollectorID
	leaf := testpki.Create(c.t, tmpl, c.CA.Cert, csr.PublicKey, c.CA.Key)
	return identity.Credentials{
		CollectorID:      CollectorID,
		CertificateChain: testpki.PEM(leaf, c.CA.Cert),
		CABundle:         c.CAPEM(),
		ScopeSigningKeys: c.ScopeKeys(),
		NotAfter:         leaf.NotAfter,
	}, nil
}
