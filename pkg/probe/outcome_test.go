package probe

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestOutcome(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	cfg := tlsCfg(t, p, p.inter.Cert)
	pr := newProber(p.roots, now)
	probe := func(port int, mode string) error {
		_, err := pr.Probe(context.Background(), Target{Host: "127.0.0.1", Port: port, StartTLS: mode, Timeout: time.Second})
		return err
	}

	ok := startServer(t, cfg, nil)
	if got := Outcome(probe(ok.port(), StartTLSNone)); got != OutcomeOK {
		t.Errorf("tls server: %q", got)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if got := Outcome(probe(closed, StartTLSNone)); got != OutcomeRefused {
		t.Errorf("closed port: %q", got)
	}

	http := startServer(t, nil, func(_ *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = br.Peek(1)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return false
	})
	if got := Outcome(probe(http.port(), StartTLSNone)); got != OutcomeNoTLS {
		t.Errorf("plain HTTP: %q", got)
	}
	silent := startServer(t, nil, func(_ *server, c net.Conn, br *bufio.Reader) bool {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, br)
		return false
	})
	if got := Outcome(probe(silent.port(), StartTLSNone)); got != OutcomeNoTLS {
		t.Errorf("silent server: %q", got)
	}
	if got := Outcome(probe(silent.port(), StartTLSSMTP)); got != OutcomeNoTLS {
		t.Errorf("silent SMTP: %q", got)
	}
	inject := startServer(t, cfg, postgresFake("Sx"))
	if got := Outcome(probe(inject.port(), StartTLSPostgres)); got != OutcomeHandshakeFailed {
		t.Errorf("injection: %q", got)
	}
	alert := startServer(t, nil, func(_ *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = br.Peek(1)
		_, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, 40}) // fatal handshake_failure alert
		return false
	})
	if got := Outcome(probe(alert.port(), StartTLSNone)); got != OutcomeHandshakeFailed {
		t.Errorf("alert: %q", got)
	}

	// Nothing on the network, or cancelled: not an observation.
	for name, err := range map[string]error{
		"forbidden": probe2(pr, "169.254.169.254"),
		"invalid":   probe2(pr, "10.0.0.0/8"),
		"cancelled": &PhaseError{Phase: PhaseConnect, Err: context.Canceled},
		"guard":     &PhaseError{Phase: PhaseConnect, Err: ErrDialGuard},
		"budget":    ErrBudgetExhausted,
		"timeout":   nil,
	} {
		if name == "timeout" {
			continue
		}
		if got := Outcome(err); got != "" {
			t.Errorf("%s: %q, want no outcome", name, got)
		}
	}
	if got := Outcome(&PhaseError{Phase: PhaseConnect, Err: context.DeadlineExceeded}); got != OutcomeTimeout {
		t.Errorf("connect deadline: %q", got)
	}
	if got := (&PhaseError{Phase: PhaseStartTLS, Mode: "smtp", Err: ErrSTARTTLSNotOffered}).Error(); got != "starttls smtp: server does not offer STARTTLS" {
		t.Errorf("message %q", got)
	}
}

func probe2(p *Prober, host string) error {
	_, err := p.Probe(context.Background(), Target{Host: host, Port: 443})
	return err
}

func TestNewAllow(t *testing.T) {
	a, err := NewAllow([]string{".Corp.Example.", "lab.test"}, []netip.Prefix{netip.MustParsePrefix("10.1.2.3/24"), netip.MustParsePrefix("::ffff:192.0.2.1/120")})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.String(); got != "corp.example,lab.test,10.1.2.0/24,192.0.2.0/24" {
		t.Fatalf("allow %q", got)
	}
	if !a.allowsHost("www.corp.example") || a.allowsHost("corp.example.evil.test") || !a.allowsHost("10.1.2.200") || a.allowsHost("10.1.3.1") {
		t.Fatal("matching")
	}
	for _, bad := range [][]string{{"*.example"}, {""}, {"a,b"}} {
		if _, err := NewAllow(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewAllow(nil, []netip.Prefix{{}}); err == nil {
		t.Error("invalid prefix accepted")
	}
	if _, err := NewAllow(nil, nil); err == nil || errors.Is(err, ErrNotAllowed) {
		t.Errorf("empty: %v", err)
	}
}
