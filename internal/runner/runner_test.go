package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// listener is a loopback server that counts connections and runs handle.
type listener struct {
	ln    net.Listener
	conns atomic.Int32
	open  atomic.Int32
}

func listen(t *testing.T, handle func(net.Conn)) *listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{ln: ln}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.conns.Add(1)
			l.open.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer l.open.Add(-1)
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return l
}

func (l *listener) port() int { return l.ln.Addr().(*net.TCPAddr).Port }

type pki struct {
	cfg   *tls.Config
	roots *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	now := time.Now()
	root := testpki.NewRoot(t, "Runner Test Root", now)
	leaf, key := root.Issue(t, testpki.LeafTemplate("www.example.test", now.Add(-time.Hour), 24*time.Hour, "www.example.test", "portal.example.test"))
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return pki{cfg: &tls.Config{Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}, MinVersion: tls.VersionTLS12}, roots: roots}
}

func tlsServer(t *testing.T, p pki) *listener {
	return listen(t, func(c net.Conn) { _ = tls.Server(c, p.cfg).Handshake() })
}

func silentServer(t *testing.T) *listener {
	return listen(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func testScope(targets ...scope.Target) *scope.Scope {
	return &scope.Scope{
		ID: "scope-1", TenantID: "tenant-1", Version: 1, Targets: targets,
		Policy: scope.ScanPolicy{RatePer24: 10, Burst: 10, ConnectTimeoutSeconds: 2, CanaryPercent: 100},
	}
}

type sink struct {
	mu  sync.Mutex
	obs []submit.Observation
}

func (s *sink) emit(o submit.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obs = append(s.obs, o)
}

func (s *sink) outcomes() map[int][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[int][]string{}
	for _, o := range s.obs {
		m[o.Target.Port] = append(m[o.Target.Port], o.Target.SNI+"="+o.Outcome)
	}
	for _, v := range m {
		slices.Sort(v)
	}
	return m
}

func TestRunProbesExactlyTheListedTargets(t *testing.T) {
	p := newPKI(t)
	ok := tlsServer(t, p)
	plain := listen(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 1)); _, _ = io.WriteString(c, "HTTP/1.1 400 Bad\r\n\r\n") })
	unlisted := tlsServer(t, p)
	closed := closedPort(t)

	sc := testScope(
		scope.Target{Host: "127.0.0.1", Port: ok.port(), Protocol: scope.ProtocolTLS},
		scope.Target{Host: "127.0.0.1", Port: plain.port(), Protocol: scope.ProtocolTLS},
		scope.Target{Host: "127.0.0.1", Port: closed, Protocol: scope.ProtocolTLS},
	)
	sc.NamesByIP = map[string][]string{"127.0.0.1": {"www.example.test", "portal.example.test"}}
	var s sink
	rep, err := New(Options{Roots: p.roots}).Run(context.Background(), sc, s.emit)
	if err != nil {
		t.Fatal(err)
	}
	got := s.outcomes()
	want := map[int][]string{
		ok.port():    {"portal.example.test=cert_seen", "www.example.test=cert_seen"},
		plain.port(): {"portal.example.test=reached", "www.example.test=reached"},
		closed:       {"portal.example.test=refused", "www.example.test=refused"},
	}
	for port, w := range want {
		if !slices.Equal(got[port], w) {
			t.Errorf("port %d: %q, want %q", port, got[port], w)
		}
	}
	// One connection per name on the open targets; the closed port was
	// tried once and its second name reported without a new connection.
	if ok.conns.Load() != 2 || plain.conns.Load() != 2 {
		t.Fatalf("connections: tls %d, plain %d", ok.conns.Load(), plain.conns.Load())
	}
	if unlisted.conns.Load() != 0 {
		t.Fatalf("an unlisted endpoint received %d connections", unlisted.conns.Load())
	}
	if rep.Attempts != 6 || rep.Planned != 3 || rep.NotRun != 0 {
		t.Fatalf("report %+v", rep)
	}
	for _, o := range s.obs {
		if o.Outcome == submit.OutcomeCertSeen && (len(o.ServedChain) == 0 || o.TLS.Version == "" || o.TLS.Protocol != "tls") {
			t.Fatalf("cert_seen observation %+v", o)
		}
		if o.Outcome != submit.OutcomeCertSeen && len(o.ServedChain) != 0 {
			t.Fatalf("chain on %s", o.Outcome)
		}
	}
}

func TestDryRunConnectsToNothing(t *testing.T) {
	srv := tlsServer(t, newPKI(t))
	sc := testScope(scope.Target{Host: "127.0.0.1", Port: srv.port()})
	sc.Policy.DryRun = true
	var s sink
	rep, err := New(Options{}).Run(context.Background(), sc, s.emit)
	if err != nil || !rep.DryRun || rep.Planned != 1 || len(s.obs) != 0 || srv.conns.Load() != 0 {
		t.Fatalf("dry run: %v %+v, %d observations, %d connections", err, rep, len(s.obs), srv.conns.Load())
	}
}

func TestDenyListAndWindow(t *testing.T) {
	srv := tlsServer(t, newPKI(t))
	sc := testScope(scope.Target{Host: "127.0.0.1", Port: srv.port()}, scope.Target{Host: "localhost", Port: srv.port()})
	sc.Policy.Deny = []string{"127.0.0.0/8", "::1"}
	var s sink
	rep, _ := New(Options{}).Run(context.Background(), sc, s.emit)
	// The IP target is denied in the plan; the name resolves into the denied
	// network and is refused right before the dial.
	if srv.conns.Load() != 0 || rep.Denied != 1 || len(s.obs) != 0 {
		t.Fatalf("deny: %d connections, %+v, %d observations", srv.conns.Load(), rep, len(s.obs))
	}

	sc = testScope(scope.Target{Host: "127.0.0.1", Port: srv.port()})
	now := time.Now().UTC()
	start := now.Add(2 * time.Hour).Format("15:04")
	end := now.Add(3 * time.Hour).Format("15:04")
	sc.Policy.Windows = []scope.Window{{Start: start, End: end}}
	rep, err := New(Options{}).Run(context.Background(), sc, s.emit)
	if srv.conns.Load() != 0 || rep.NotRun != 1 || err != nil {
		t.Fatalf("outside window: %d connections, %+v, %v", srv.conns.Load(), rep, err)
	}
}

// Pause must take effect in under 10 s: every open connection closes, the
// run returns, and nothing new is dialled afterwards.
func TestPauseStopsAtOnce(t *testing.T) {
	var servers []*listener
	var targets []scope.Target
	for range 20 {
		l := silentServer(t)
		servers = append(servers, l)
		targets = append(targets, scope.Target{Host: "127.0.0.1", Port: l.port()})
	}
	sum := func(f func(*listener) int32) (n int32) {
		for _, l := range servers {
			n += f(l)
		}
		return n
	}
	open := func() int32 { return sum(func(l *listener) int32 { return l.open.Load() }) }
	conns := func() int32 { return sum(func(l *listener) int32 { return l.conns.Load() }) }

	sc := testScope(targets...)
	sc.Policy.ConnectTimeoutSeconds = 15
	sc.Policy.RatePer24 = 0.5 // slow, so most attempts are still queued
	sc.Policy.Burst = 4

	r := New(Options{Workers: 8})
	done := make(chan error, 1)
	var s sink
	go func() { _, err := r.Run(context.Background(), sc, s.emit); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for open() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if open() == 0 {
		t.Fatal("no connection opened")
	}
	start := time.Now()
	r.Pause()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPaused) {
			t.Fatalf("run ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pause took more than 10 s")
	}
	took := time.Since(start)
	deadline = time.Now().Add(2 * time.Second)
	for open() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if open() != 0 {
		t.Fatalf("%d connections still open after pause", open())
	}
	if took > time.Second {
		t.Fatalf("pause took %v", took)
	}
	before := conns()
	time.Sleep(500 * time.Millisecond)
	if after := conns(); after != before {
		t.Fatalf("connections after pause: %d, at pause %d", after, before)
	}
	if len(s.obs) != 0 {
		t.Fatalf("%d observations from cancelled attempts", len(s.obs))
	}
	if _, err := r.Run(context.Background(), sc, s.emit); !errors.Is(err, ErrPaused) {
		t.Fatalf("run while paused: %v", err)
	}
	r.Resume()
	if r.Paused() {
		t.Fatal("still paused")
	}
	t.Logf("pause took %v with %d connections open", took, before)
}

func TestPlan(t *testing.T) {
	sc := testScope(
		scope.Target{Host: "192.0.2.1", Port: 443},
		scope.Target{Host: "192.0.2.2", Port: 443},
		scope.Target{Host: "mail.example.test", Port: 587, Protocol: scope.ProtocolSMTPStartTLS},
		scope.Target{Host: "old.example.test", Port: 443},
		scope.Target{Host: "198.51.100.9", Port: 3389},
	)
	sc.NamesByIP = map[string][]string{"192.0.2.1": {"WWW.example.test", "legacy.old.example.test"}, "192.0.2.2": {"x.old.example.test"}}
	sc.Policy.Deny = []string{"old.example.test", "198.51.100.0/24", " ", "bad/prefix"}
	jobs, denied := Plan(sc)
	if len(jobs) != 2 || len(denied) != 3 {
		t.Fatalf("jobs %+v denied %+v", jobs, denied)
	}
	if !slices.Equal(jobs[0].SNIs, []string{"www.example.test"}) || jobs[0].IP != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("job 0 %+v", jobs[0])
	}
	if !slices.Equal(jobs[1].SNIs, []string{"mail.example.test"}) || jobs[1].IP.IsValid() {
		t.Fatalf("job 1 %+v", jobs[1])
	}
	plain := testScope(scope.Target{Host: "192.0.2.3", Port: 443})
	if jobs, _ := Plan(plain); !slices.Equal(jobs[0].SNIs, []string{""}) {
		t.Fatalf("ip without names %+v", jobs)
	}
}

func TestModeAndProtocolNames(t *testing.T) {
	for _, p := range scope.Protocols {
		if Mode(p) == "auto" {
			t.Errorf("protocol %q has no mode", p)
		}
	}
	for port, want := range map[int]string{25: "smtp-starttls", 636: "ldaps", 3389: "rdp", 443: "https", 993: "imaps", 7000: "tls"} {
		j := Job{Target: scope.Target{Host: "192.0.2.1", Port: port}}
		if got := observation(j, "", time.Now(), "refused", nil).TLS.Protocol; got != want {
			t.Errorf("port %d: %q, want %q", port, got, want)
		}
	}
	for in, want := range map[string]string{"ok": "cert_seen", "refused": "refused", "timeout": "timeout", "no_tls": "reached", "handshake_failed": "tls_failed"} {
		if got := ContractOutcome(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
}
