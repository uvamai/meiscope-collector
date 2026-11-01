package probe

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// pki is a root, an intermediate and a leaf for www.example.test.
type pki struct {
	root, inter *testpki.CA
	leaf        *x509.Certificate
	leafKey     crypto.Signer
	roots       *x509.CertPool
}

func newPKI(t *testing.T, now time.Time, notBefore time.Time, lifetime time.Duration) *pki {
	t.Helper()
	root := testpki.NewRoot(t, "Probe Test Root", now)
	inter := root.NewIntermediate(t, "Probe Test Intermediate", now)
	leaf, key := inter.Issue(t, testpki.LeafTemplate("www.example.test", notBefore, lifetime, "www.example.test"))
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return &pki{root: root, inter: inter, leaf: leaf, leafKey: key, roots: roots}
}

// server is a loopback TCP server that optionally runs a plaintext
// preamble and then a TLS server handshake on each connection.
type server struct {
	ln          net.Listener
	conns       atomic.Int32
	clientCerts atomic.Int32
	mu          sync.Mutex
	received    []string
	hsErr       error
	wg          sync.WaitGroup
}

func (s *server) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *server) record(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, line)
}

func (s *server) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.received)
}

func startServer(t *testing.T, cfg *tls.Config, preamble func(s *server, c net.Conn, br *bufio.Reader) bool) *server {
	t.Helper()
	return startServerWrap(t, cfg, preamble, nil)
}

// startServerWrap is startServer with the TLS server running on wrap(conn)
// (the TDS framing for SQL Server); wrap nil means the connection itself.
func startServerWrap(t *testing.T, cfg *tls.Config, preamble func(s *server, c net.Conn, br *bufio.Reader) bool, wrap func(net.Conn) net.Conn) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln}
	if cfg != nil {
		cfg = cfg.Clone()
		cfg.ClientAuth = tls.RequestClientCert
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				s.clientCerts.Add(1)
			}
			return nil
		}
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				if preamble != nil && !preamble(s, c, br) {
					return
				}
				if cfg == nil {
					return
				}
				var tconn net.Conn = &bufConn{Conn: c, r: br}
				if wrap != nil {
					tconn = wrap(tconn)
				}
				tc := tls.Server(tconn, cfg)
				err := tc.Handshake()
				s.mu.Lock()
				s.hsErr = err
				s.mu.Unlock()
				if err == nil {
					// Record anything the client sends after the handshake.
					buf := make([]byte, 64)
					if n, _ := tc.Read(buf); n > 0 {
						s.record("APPDATA:" + string(buf[:n]))
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func newProber(roots *x509.CertPool, now time.Time) *Prober {
	return New(Options{Roots: roots, Now: func() time.Time { return now }})
}

func TestProbeVerifiedChain(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	cfg := tlsCfg(t, p, p.inter.Cert)
	cfg.Certificates[0].OCSPStaple = []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	srv := startServer(t, cfg, nil)

	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Verified || !res.Verification.ChainVerified || !res.Verification.HostnameMatches || len(res.Verification.Reasons) != 0 {
		t.Fatalf("verification %+v", res.Verification)
	}
	if res.Verification.VerifiedAgainst != "custom roots" || !res.Verification.LeafIssuerServed || !res.Verification.ChainInOrder {
		t.Fatalf("verification %+v", res.Verification)
	}
	if res.TLSVersion != "TLS 1.3" || res.ALPN != "h2" || !res.OCSPStapled || res.CipherSuite == "" {
		t.Fatalf("session %+v", res)
	}
	if len(res.Chain) != 2 || res.AddressClass != ClassLoopback || len(res.Notes) != 1 || res.StartTLS != StartTLSNone {
		t.Fatalf("result %+v", res)
	}
	_ = srv.ln.Close()
	srv.wg.Wait()
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
	if srv.clientCerts.Load() != 0 {
		t.Fatal("a client certificate was presented")
	}
	if srv.hsErr == nil {
		t.Fatal("server handshake completed; the probe must stop after the certificate chain")
	}
	if l := srv.lines(); len(l) != 0 {
		t.Fatalf("server received data: %v", l)
	}
}

// tlsCfg builds a server config serving p.leaf plus chain.
func tlsCfg(t *testing.T, p *pki, chain ...*x509.Certificate) *tls.Config {
	t.Helper()
	tc := tls.Certificate{Certificate: [][]byte{p.leaf.Raw}, PrivateKey: p.leafKey, Leaf: p.leaf}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return &tls.Config{Certificates: []tls.Certificate{tc}, NextProtos: []string{"h2"}}
}

func TestProbeTLS12(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	cfg := tlsCfg(t, p, p.inter.Cert)
	cfg.MaxVersion = tls.VersionTLS12
	cfg.Certificates[0].OCSPStaple = []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	srv := startServer(t, cfg, nil)
	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.TLSVersion != "TLS 1.2" || !res.OCSPStapled || !res.Verification.Verified {
		t.Fatalf("result %+v", res)
	}
	_ = srv.ln.Close()
	srv.wg.Wait()
	if srv.clientCerts.Load() != 0 || srv.hsErr == nil {
		t.Fatalf("client cert %d, server handshake err %v", srv.clientCerts.Load(), srv.hsErr)
	}
}

func TestProbeVerificationFailures(t *testing.T) {
	now := time.Now()
	good := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	expired := newPKI(t, now, now.Add(-100*24*time.Hour), 90*24*time.Hour)
	future := newPKI(t, now, now.Add(48*time.Hour), 90*24*time.Hour)
	other := testpki.NewRoot(t, "Other Root", now)
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other.Cert)

	tests := []struct {
		name    string
		p       *pki
		chain   []*x509.Certificate
		roots   *x509.CertPool
		sni     string
		reasons []string
		served  bool
	}{
		{"hostname mismatch", good, []*x509.Certificate{good.inter.Cert}, good.roots, "other.example.test", []string{ReasonHostnameMismatch}, true},
		{"expired", expired, []*x509.Certificate{expired.inter.Cert}, expired.roots, "www.example.test", []string{ReasonExpired}, true},
		{"not yet valid", future, []*x509.Certificate{future.inter.Cert}, future.roots, "www.example.test", []string{ReasonNotYetValid}, true},
		{"unknown authority", good, []*x509.Certificate{good.inter.Cert}, otherRoots, "www.example.test", []string{ReasonUnknownAuthority}, true},
		{"missing intermediate", good, nil, good.roots, "www.example.test", []string{ReasonUnknownAuthority, ReasonMissingIntermediate}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, tlsCfg(t, tc.p, tc.chain...), nil)
			res, err := newProber(tc.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: tc.sni})
			if err != nil {
				t.Fatal(err)
			}
			v := res.Verification
			if v.Verified || !slices.Equal(v.Reasons, tc.reasons) || v.LeafIssuerServed != tc.served || v.Detail == "" {
				t.Fatalf("verification %+v, want reasons %v", v, tc.reasons)
			}
		})
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	a, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func TestProbeHostnameResolution(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), nil)
	pr := New(Options{Roots: p.roots, Now: func() time.Time { return now }, Resolver: fakeResolver{
		"www.example.test": {netip.MustParseAddr("127.0.0.1")},
		"empty.test":       {},
	}})
	res, err := pr.Probe(context.Background(), Target{Host: "WWW.example.test.", Port: srv.port()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Verified || res.IP != "127.0.0.1" {
		t.Fatalf("result %+v", res)
	}
	if _, err := pr.Probe(context.Background(), Target{Host: "missing.test", Port: srv.port()}); err == nil {
		t.Fatal("want resolve error")
	}
	if _, err := pr.Probe(context.Background(), Target{Host: "empty.test", Port: srv.port()}); err == nil {
		t.Fatal("want no-address error")
	}
}

func TestProbeRefusesForbiddenTargets(t *testing.T) {
	var dials atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			_ = c.Close()
		}
	}()
	pr := New(Options{Resolver: fakeResolver{
		"sneaky.test":    {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")},
		"v6meta.test":    {netip.MustParseAddr("fd00:ec2::254")},
		"mapped.test":    {netip.MustParseAddr("::ffff:169.254.169.254")},
		"nat64.test":     {netip.MustParseAddr("64:ff9b::a9fe:a9fe")},
		"alibaba.test":   {netip.MustParseAddr("100.100.100.200")},
		"azurewire.test": {netip.MustParseAddr("168.63.129.16")},
	}})
	port := ln.Addr().(*net.TCPAddr).Port
	tests := []struct {
		host string
		want error
	}{
		{"169.254.169.254", ErrForbiddenTarget},
		{"169.254.0.1", ErrForbiddenTarget},
		{"fe80::1", ErrForbiddenTarget},
		{"[fe80::1]", ErrForbiddenTarget},
		{"::ffff:169.254.169.254", ErrForbiddenTarget},
		{"fd00:ec2::254", ErrForbiddenTarget},
		{"fd20:ce::254", ErrForbiddenTarget},
		{"0.0.0.0", ErrForbiddenTarget},
		{"224.0.0.1", ErrForbiddenTarget},
		{"metadata.google.internal", ErrForbiddenTarget},
		{"METADATA", ErrForbiddenTarget},
		{"sneaky.test", ErrForbiddenTarget},
		{"v6meta.test", ErrForbiddenTarget},
		{"mapped.test", ErrForbiddenTarget},
		{"nat64.test", ErrForbiddenTarget},
		{"alibaba.test", ErrForbiddenTarget},
		{"azurewire.test", ErrForbiddenTarget},
		{"10.0.0.0/8", ErrCIDR},
		{"2001:db8::/32", ErrCIDR},
		{"10.0.0.1-10.0.0.9", ErrRange},
		{"10.0.0.1-9", ErrRange},
		{"a.test,b.test", ErrRange},
		{"a.test b.test", ErrRange},
		{"*.example.test", ErrRange},
		{"", ErrInvalidHost},
		{"exa$mple.test", ErrInvalidHost},
		{strings.Repeat("a", 254), ErrInvalidHost},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			_, err := pr.Probe(context.Background(), Target{Host: tc.host, Port: port})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("%d connections were made to refused targets", n)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		in   Target
		want error
		mode string
		port int
	}{
		{"defaults", Target{Host: "example.test"}, nil, StartTLSNone, 443},
		{"smtp auto", Target{Host: "example.test", Port: 25}, nil, StartTLSSMTP, 25},
		{"submission auto", Target{Host: "example.test", Port: 587}, nil, StartTLSSMTP, 587},
		{"imap auto", Target{Host: "example.test", Port: 143}, nil, StartTLSIMAP, 143},
		{"pop3 auto", Target{Host: "example.test", Port: 110}, nil, StartTLSPOP3, 110},
		{"ldap auto", Target{Host: "example.test", Port: 389}, nil, StartTLSLDAP, 389},
		{"implicit tls 993", Target{Host: "example.test", Port: 993, StartTLS: StartTLSAuto}, nil, StartTLSNone, 993},
		{"explicit none on 25", Target{Host: "example.test", Port: 25, StartTLS: StartTLSNone}, nil, StartTLSNone, 25},
		{"bad mode", Target{Host: "example.test", StartTLS: "xmpp"}, ErrInvalidSTARTTLS, "", 0},
		{"port high", Target{Host: "example.test", Port: 65536}, ErrInvalidPort, "", 0},
		{"port negative", Target{Host: "example.test", Port: -1}, ErrInvalidPort, "", 0},
		{"timeout too long", Target{Host: "example.test", Timeout: 16 * time.Second}, ErrInvalidTimeout, "", 0},
		{"timeout too short", Target{Host: "example.test", Timeout: time.Millisecond}, ErrInvalidTimeout, "", 0},
		{"bad sni", Target{Host: "example.test", SNI: "a/b"}, ErrCIDR, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err == nil && (got.StartTLS != tc.mode || got.Port != tc.port || got.Timeout != DefaultTimeout && tc.in.Timeout == 0) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestClassifyAddr(t *testing.T) {
	tests := map[string]string{
		"8.8.8.8":          ClassPublic,
		"10.1.2.3":         ClassPrivate,
		"192.168.1.1":      ClassPrivate,
		"100.64.0.1":       ClassPrivate,
		"fd12::1":          ClassPrivate,
		"127.0.0.1":        ClassLoopback,
		"::1":              ClassLoopback,
		"64:ff9b::808:808": ClassPublic,
	}
	for addr, want := range tests {
		got, forbidden := ClassifyAddr(netip.MustParseAddr(addr))
		if got != want || forbidden {
			t.Errorf("%s: %s %v, want %s", addr, got, forbidden, want)
		}
	}
}

func TestDialGuard(t *testing.T) {
	p := New(Options{})
	meta := netip.MustParseAddr("169.254.169.254")
	loop := netip.MustParseAddr("127.0.0.1")
	if err := p.dialGuard(meta)(context.Background(), "tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrForbiddenTarget) {
		t.Fatalf("err = %v", err)
	}
	if err := p.dialGuard(loop)(context.Background(), "tcp", "127.0.0.1:80", nil); err != nil {
		t.Fatalf("err = %v", err)
	}
	if err := p.dialGuard(loop)(context.Background(), "tcp", "10.0.0.1:80", nil); err == nil {
		t.Fatal("dial to an address other than the vetted one must be refused")
	}
	if err := p.dialGuard(loop)(context.Background(), "tcp", "bogus", nil); err == nil {
		t.Fatal("want parse error")
	}
}

func TestProbeTimeoutAndFailures(t *testing.T) {
	// A server that accepts and stays silent: the probe must give up at the deadline.
	silent := startServer(t, nil, func(_ *server, _ net.Conn, _ *bufio.Reader) bool {
		time.Sleep(3 * time.Second)
		return false
	})
	start := time.Now()
	_, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: silent.port(), StartTLS: StartTLSSMTP, Timeout: time.Second})
	if err == nil || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
	// A server that closes at once: handshake error, no retry.
	closer := startServer(t, nil, nil)
	if _, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: closer.port(), Timeout: time.Second}); err == nil {
		t.Fatal("want handshake error")
	}
	_ = closer.ln.Close()
	closer.wg.Wait()
	if n := closer.conns.Load(); n != 1 {
		t.Fatalf("%d connections, want exactly 1 (no retries)", n)
	}
	// Nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if _, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: port, Timeout: time.Second}); err == nil {
		t.Fatal("want connect error")
	}
	if _, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: 70000}); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	v := verifyChain(nil, "x", nil, time.Now())
	if v.Verified || !slices.Equal(v.Reasons, []string{ReasonNoCertificate}) || v.VerifiedAgainst != "system roots" {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyChainOutOfOrder(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	v := verifyChain([]*x509.Certificate{p.leaf, p.root.Cert, p.inter.Cert}, "www.example.test", p.roots, now)
	if !v.Verified || v.ChainInOrder {
		t.Fatalf("%+v", v)
	}
	// A self-signed leaf counts as "issuer served".
	self := testpki.Create(t, testpki.LeafTemplate("self.test", now.Add(-time.Hour), 24*time.Hour, "self.test"), nil, p.root.Key.Public(), p.root.Key)
	v = verifyChain([]*x509.Certificate{self}, "self.test", p.roots, now)
	if v.Verified || !v.LeafIssuerServed || !slices.Equal(v.Reasons, []string{ReasonUnknownAuthority}) {
		t.Fatalf("%+v", v)
	}
	if got := classify(errors.New("x"), nil, now, true); !slices.Equal(got, []string{ReasonOther}) {
		t.Fatalf("%v", got)
	}
	if got := classify(x509.CertificateInvalidError{Reason: x509.Expired}, []*x509.Certificate{p.leaf}, now, true); !slices.Equal(got, []string{ReasonExpired}) {
		t.Fatalf("%v", got)
	}
}
