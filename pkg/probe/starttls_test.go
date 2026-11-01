package probe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func readCmd(s *server, br *bufio.Reader) (string, bool) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", false
	}
	line = strings.TrimRight(line, "\r\n")
	s.record(line)
	return line, true
}

// smtpFake is a fake SMTP server: greeting, EHLO (optionally advertising
// STARTTLS), then the STARTTLS reply given.
func smtpFake(advertise bool, startTLSReply string) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = io.WriteString(c, "220-fake.example.test ESMTP\r\n220 ready\r\n")
		if _, ok := readCmd(s, br); !ok {
			return false
		}
		ext := "250-SIZE 1000\r\n250 8BITMIME\r\n"
		if advertise {
			ext = "250-SIZE 1000\r\n250-STARTTLS\r\n250 8BITMIME\r\n"
		}
		_, _ = io.WriteString(c, "250-fake.example.test hello\r\n"+ext)
		if _, ok := readCmd(s, br); !ok {
			return false
		}
		_, _ = io.WriteString(c, startTLSReply)
		return strings.HasPrefix(startTLSReply, "220")
	}
}

func TestSTARTTLSSMTP(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), smtpFake(true, "220 go ahead\r\n"))
	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test", StartTLS: StartTLSSMTP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Verified || res.StartTLS != StartTLSSMTP || res.ALPN != "" {
		t.Fatalf("result %+v", res)
	}
	_ = srv.ln.Close()
	srv.wg.Wait()
	// Only EHLO and STARTTLS: no AUTH, MAIL, QUIT or anything else.
	if got := srv.lines(); !slices.Equal(got, []string{"EHLO [127.0.0.1]", "STARTTLS"}) {
		t.Fatalf("server received %q", got)
	}
	if srv.clientCerts.Load() != 0 || srv.conns.Load() != 1 {
		t.Fatalf("client certs %d, conns %d", srv.clientCerts.Load(), srv.conns.Load())
	}
}

func TestSTARTTLSSMTPFailures(t *testing.T) {
	tests := []struct {
		name     string
		preamble func(*server, net.Conn, *bufio.Reader) bool
		want     error
	}{
		{"not advertised", smtpFake(false, ""), ErrSTARTTLSNotOffered},
		{"refused", smtpFake(true, "454 TLS not available\r\n"), ErrSTARTTLSRefused},
		{"injection", smtpFake(true, "220 go ahead\r\n250 injected\r\n"), ErrPreTLSInjection},
		{"bad greeting", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, "554 go away\r\n")
			return false
		}, nil},
		{"malformed", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, "hi\r\n")
			return false
		}, nil},
		{"bad code", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, "abc ready\r\n")
			return false
		}, nil},
		{"bad separator", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, "220xready\r\n")
			return false
		}, nil},
		{"long line", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, "220 "+strings.Repeat("x", 5000)+"\r\n")
			return false
		}, errLineTooLong},
		{"too many lines", func(_ *server, c net.Conn, _ *bufio.Reader) bool {
			_, _ = io.WriteString(c, strings.Repeat("220-x\r\n", maxReplyLines+1))
			return false
		}, errTooManyLines},
		{"ehlo rejected", func(s *server, c net.Conn, br *bufio.Reader) bool {
			_, _ = io.WriteString(c, "220 ready\r\n")
			readCmd(s, br)
			_, _ = io.WriteString(c, "502 no\r\n")
			return false
		}, nil},
		{"ehlo eof", func(s *server, c net.Conn, br *bufio.Reader) bool {
			_, _ = io.WriteString(c, "220 ready\r\n")
			readCmd(s, br)
			return false
		}, nil},
		{"starttls eof", smtpFake(true, ""), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, nil, tc.preamble)
			_, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), StartTLS: StartTLSSMTP, Timeout: 2 * time.Second})
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "go away") || strings.Contains(err.Error(), "injected") {
				t.Fatalf("server text leaked into error: %v", err)
			}
		})
	}
}

func TestSTARTTLSIMAPAndPOP3(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	imap := func(s *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = io.WriteString(c, "* OK IMAP4rev1 ready\r\n")
		if _, ok := readCmd(s, br); !ok {
			return false
		}
		_, _ = io.WriteString(c, "* CAPABILITY IMAP4rev1\r\na1 OK begin TLS\r\n")
		return true
	}
	pop3 := func(s *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = io.WriteString(c, "+OK POP3 ready\r\n")
		if _, ok := readCmd(s, br); !ok {
			return false
		}
		_, _ = io.WriteString(c, "+OK begin TLS\r\n")
		return true
	}
	for _, tc := range []struct {
		mode     string
		preamble func(*server, net.Conn, *bufio.Reader) bool
		want     []string
	}{
		{StartTLSIMAP, imap, []string{"a1 STARTTLS"}},
		{StartTLSPOP3, pop3, []string{"STLS"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := startServer(t, tlsCfg(t, p, p.inter.Cert), tc.preamble)
			res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test", StartTLS: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Verification.Verified {
				t.Fatalf("%+v", res.Verification)
			}
			_ = srv.ln.Close()
			srv.wg.Wait()
			if got := srv.lines(); !slices.Equal(got, tc.want) {
				t.Fatalf("server received %q", got)
			}
		})
	}
}

func TestSTARTTLSIMAPAndPOP3Failures(t *testing.T) {
	reply := func(greet, resp string) func(*server, net.Conn, *bufio.Reader) bool {
		return func(s *server, c net.Conn, br *bufio.Reader) bool {
			_, _ = io.WriteString(c, greet)
			if resp == "" {
				return false
			}
			readCmd(s, br)
			_, _ = io.WriteString(c, resp)
			return false
		}
	}
	tests := []struct {
		name, mode string
		preamble   func(*server, net.Conn, *bufio.Reader) bool
		want       error
	}{
		{"imap bad greeting", StartTLSIMAP, reply("* BYE\r\n", ""), nil},
		{"imap refused", StartTLSIMAP, reply("* OK\r\n", "a1 NO\r\n"), ErrSTARTTLSRefused},
		{"imap too many untagged", StartTLSIMAP, reply("* OK\r\n", strings.Repeat("* x\r\n", maxReplyLines+1)), errTooManyLines},
		{"imap eof", StartTLSIMAP, reply("* OK\r\n", "* x\r\n"), nil},
		{"imap no greeting", StartTLSIMAP, reply("", ""), nil},
		{"pop3 bad greeting", StartTLSPOP3, reply("-ERR\r\n", ""), nil},
		{"pop3 refused", StartTLSPOP3, reply("+OK\r\n", "-ERR no\r\n"), ErrSTARTTLSRefused},
		{"pop3 eof", StartTLSPOP3, reply("+OK\r\n", ""), nil},
		{"pop3 no greeting", StartTLSPOP3, reply("", ""), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, nil, tc.preamble)
			_, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), StartTLS: tc.mode, Timeout: 2 * time.Second})
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// ldapFake reads the StartTLS request and replies with resultCode rc, or
// with raw when non-nil.
func ldapFake(rc byte, raw []byte) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		req := ldapStartTLSRequest()
		got := make([]byte, len(req))
		if _, err := io.ReadFull(br, got); err != nil {
			return false
		}
		s.record(fmt.Sprintf("%x", got))
		resp := raw
		if resp == nil {
			resp = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, rc, 0x04, 0x00, 0x04, 0x00}
		}
		_, _ = c.Write(resp)
		return rc == 0 && raw == nil
	}
}

func TestSTARTTLSLDAP(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), ldapFake(0, nil))
	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test", StartTLS: StartTLSLDAP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Verified {
		t.Fatalf("%+v", res.Verification)
	}
	_ = srv.ln.Close()
	srv.wg.Wait()
	// Exactly one request, the StartTLS extended operation; never a bind.
	want := "301d02010177188016312e332e362e312e342e312e313436362e3230303337"
	if got := srv.lines(); !slices.Equal(got, []string{want}) {
		t.Fatalf("server received %q", got)
	}
	if !bytes.Contains(ldapStartTLSRequest(), []byte("1.3.6.1.4.1.1466.20037")) {
		t.Fatal("request OID")
	}
}

func TestSTARTTLSLDAPFailures(t *testing.T) {
	long := append([]byte{0x30, 0x82, 0xff, 0xff}, make([]byte, 10)...)
	tests := []struct {
		name string
		f    func(*server, net.Conn, *bufio.Reader) bool
		want error
	}{
		{"refused", ldapFake(2, nil), ErrSTARTTLSRefused},
		{"not a sequence", ldapFake(0, []byte{0x02, 0x01, 0x01}), nil},
		{"wrong message id", ldapFake(0, []byte{0x30, 0x0c, 0x02, 0x01, 0x02, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}), nil},
		{"wrong op", ldapFake(0, []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}), nil},
		{"bad result code", ldapFake(0, []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x04, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}), nil},
		{"long form length", ldapFake(0, []byte{0x30, 0x81, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x05, 0x04, 0x00, 0x04, 0x00}), ErrSTARTTLSRefused},
		// Active Directory style: 4-byte non-minimal lengths everywhere.
		{"ad style refused", ldapFake(0, []byte{0x30, 0x84, 0, 0, 0, 0x10, 0x02, 0x01, 0x01, 0x78, 0x84, 0, 0, 0, 0x07, 0x0a, 0x01, 0x34, 0x04, 0x00, 0x04, 0x00}), ErrSTARTTLSRefused},
		{"inner truncated", ldapFake(0, []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x78, 0x07}), nil},
		{"inner bad length", ldapFake(0, []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x78}), nil},
		{"inner long length", ldapFake(0, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x78, 0x85, 0x00}), nil},
		{"indefinite length", ldapFake(0, []byte{0x30, 0x80}), nil},
		{"too large", ldapFake(0, long), nil},
		{"truncated length", ldapFake(0, []byte{0x30, 0x82, 0x01}), nil},
		{"truncated body", ldapFake(0, []byte{0x30, 0x05, 0x02}), nil},
		{"no reply", func(_ *server, _ net.Conn, _ *bufio.Reader) bool { return false }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, nil, tc.f)
			_, err := New(Options{}).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), StartTLS: StartTLSLDAP, Timeout: 2 * time.Second})
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStartTLSUnknownMode(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := startTLS(c1, "xmpp"); !errors.Is(err, ErrInvalidSTARTTLS) {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteError(t *testing.T) {
	c1, c2 := net.Pipe()
	_ = c2.Close()
	_ = c1.Close()
	if err := write(c1, "x"); err == nil {
		t.Fatal("want write error")
	}
}

func TestSTARTTLSLDAPActiveDirectoryLengths(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	ad := []byte{0x30, 0x84, 0, 0, 0, 0x12, 0x02, 0x01, 0x01, 0x78, 0x84, 0, 0, 0, 0x09, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00}
	f := func(s *server, c net.Conn, br *bufio.Reader) bool {
		ldapFake(0, ad)(s, c, br)
		return true
	}
	srv := startServer(t, tlsCfg(t, p, p.inter.Cert), f)
	res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test", StartTLS: StartTLSLDAP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Verified {
		t.Fatalf("%+v", res.Verification)
	}
}
