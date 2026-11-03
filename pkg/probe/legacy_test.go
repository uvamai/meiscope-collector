package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// rsaPKI is like newPKI but with an RSA leaf, which RSA key exchange needs.
func rsaPKI(t *testing.T, now time.Time) *pki {
	t.Helper()
	root := testpki.NewRoot(t, "Legacy Test Root", now)
	inter := root.NewIntermediate(t, "Legacy Test Intermediate", now)
	key := testpki.RSAKey(t, 2048)
	tmpl := testpki.LeafTemplate("www.example.test", now.Add(-time.Hour), 90*24*time.Hour, "www.example.test")
	tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	leaf := testpki.Create(t, tmpl, inter.Cert, key.Public(), inter.Key)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return &pki{root: root, inter: inter, leaf: leaf, leafKey: key, roots: roots}
}

func findingCodes(fs []Finding) []string {
	var c []string
	for _, f := range fs {
		c = append(c, f.Code)
	}
	return c
}

// recorder sits between the probe and the server and keeps every byte the
// client sends, so tests can check what went over the wire.
type recorder struct {
	ln   net.Listener
	mu   sync.Mutex
	sent []byte
	wg   sync.WaitGroup
}

func startRecorder(t *testing.T, backend string) *recorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{ln: ln}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, err := net.Dial("tcp", backend)
		if err != nil {
			return
		}
		defer func() { _ = b.Close() }()
		go func() { _, _ = io.Copy(c, b) }()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				r.mu.Lock()
				r.sent = append(r.sent, buf[:n]...)
				r.mu.Unlock()
				if _, werr := b.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); r.wg.Wait() })
	return r
}

func (r *recorder) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

// clientMessages parses the recorded TLS records into record content types
// and handshake message types.
func (r *recorder) clientMessages(t *testing.T) (records []byte, handshakes []byte) {
	t.Helper()
	r.mu.Lock()
	b := slices.Clone(r.sent)
	r.mu.Unlock()
	for len(b) >= 5 {
		typ, n := b[0], int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			t.Fatalf("truncated TLS record of type %d", typ)
		}
		payload := b[5 : 5+n]
		records = append(records, typ)
		if typ == 22 { // handshake: walk the messages
			for len(payload) >= 4 {
				handshakes = append(handshakes, payload[0])
				l := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
				if len(payload) < 4+l {
					break
				}
				payload = payload[4+l:]
			}
		}
		b = b[5+n:]
	}
	if len(b) != 0 {
		t.Fatalf("%d stray bytes after the last TLS record", len(b))
	}
	return records, handshakes
}

func TestProbeLegacyProtocolVersions(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		version uint16
		name    string
		finding string
	}{
		{tls.VersionTLS10, "TLS 1.0", FindingLegacyTLS10},
		{tls.VersionTLS11, "TLS 1.1", FindingLegacyTLS11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
			cfg := tlsCfg(t, p, p.inter.Cert)
			cfg.MinVersion, cfg.MaxVersion = tc.version, tc.version
			srv := startServer(t, cfg, nil)
			res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test"})
			if err != nil {
				t.Fatalf("a %s-only server must still be inspected: %v", tc.name, err)
			}
			if res.TLSVersion != tc.name || len(res.Chain) != 2 || !res.Verification.Verified {
				t.Fatalf("result %+v", res)
			}
			if got := findingCodes(res.Findings); !slices.Equal(got, []string{tc.finding}) {
				t.Fatalf("findings %v, want [%s]", got, tc.finding)
			}
		})
	}
}

// TestProbeRSAKeyExchangeSendsNoSecret: a server that only offers RSA key
// exchange is inspected, reported, and receives nothing but a ClientHello and
// an alert: no ClientKeyExchange (which would carry the pre-master secret),
// no ChangeCipherSpec, no client certificate.
func TestProbeRSAKeyExchangeSendsNoSecret(t *testing.T) {
	now := time.Now()
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			p := rsaPKI(t, now)
			cfg := tlsCfg(t, p, p.inter.Cert)
			cfg.MinVersion, cfg.MaxVersion = version, version
			cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
			if version == tls.VersionTLS12 {
				cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
			}
			srv := startServer(t, cfg, nil)
			rec := startRecorder(t, srv.ln.Addr().String())
			res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: rec.port(), SNI: "www.example.test"})
			if err != nil {
				t.Fatalf("an RSA-kex-only server must still be inspected: %v", err)
			}
			if got := findingCodes(res.Findings); !slices.Contains(got, FindingRSAKeyExchange) {
				t.Fatalf("findings %v, want %s", got, FindingRSAKeyExchange)
			}
			if version == tls.VersionTLS10 && !slices.Contains(findingCodes(res.Findings), FindingLegacyTLS10) {
				t.Fatalf("findings %v, want %s too", findingCodes(res.Findings), FindingLegacyTLS10)
			}
			_ = rec.ln.Close()
			rec.wg.Wait()
			records, handshakes := rec.clientMessages(t)
			if !slices.Equal(handshakes, []byte{1}) {
				t.Fatalf("client handshake messages %v, want only ClientHello (1)", handshakes)
			}
			for _, typ := range records {
				if typ != 22 && typ != 21 { // handshake (the ClientHello) and alert only
					t.Fatalf("client sent a TLS record of content type %d; records %v", typ, records)
				}
			}
			if srv.clientCerts.Load() != 0 {
				t.Fatal("a client certificate was presented")
			}
		})
	}
}

func TestModernSessionHasNoFindings(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), nil)
	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("TLS 1.3 session reported findings %v", findingCodes(res.Findings))
	}
}

func TestSessionFindings(t *testing.T) {
	for _, tc := range []struct {
		version, suite uint16
		want           []string
	}{
		{tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, nil},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil},
		{tls.VersionTLS12, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, []string{FindingRSAKeyExchange}},
		{tls.VersionTLS11, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, []string{FindingLegacyTLS11}},
		{tls.VersionTLS10, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, []string{FindingLegacyTLS10, FindingRSAKeyExchange}},
	} {
		if got := findingCodes(sessionFindings(tc.version, tc.suite)); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: got %v, want %v", tls.VersionName(tc.version), tls.CipherSuiteName(tc.suite), got, tc.want)
		}
	}
	ids := inspectionCipherSuites()
	if !slices.Contains(ids, tls.TLS_RSA_WITH_AES_128_GCM_SHA256) || !slices.Contains(ids, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Fatalf("inspection suites must include secure and RSA key exchange suites: %v", ids)
	}
}
