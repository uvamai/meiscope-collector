package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// readN reads exactly n bytes and records them as hex.
func readN(s *server, br *bufio.Reader, n int) ([]byte, bool) {
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return nil, false
	}
	s.record(fmt.Sprintf("%x", b))
	return b, true
}

// rdpFake answers the X.224 Connection Request with neg (the RDP_NEG_*
// structure after the Connection Confirm header; nil sends none).
func rdpFake(neg []byte) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		if _, ok := readN(s, br, 19); !ok {
			return false
		}
		cc := append([]byte{byte(6 + len(neg)), 0xd0, 0, 0, 0x12, 0x34, 0}, neg...) // #nosec G115 -- len(neg) is 0 or 8
		out := append([]byte{0x03, 0, 0, byte(4 + len(cc))}, cc...)                 // #nosec G115 -- at most 19
		_, _ = c.Write(out)
		return len(neg) == 8 && neg[0] == rdpNegRsp && neg[4] != 0
	}
}

func rdpNeg(typ byte, value uint32) []byte {
	b := []byte{typ, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[4:], value)
	return b
}

func postgresFake(reply string) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		if _, ok := readN(s, br, 8); !ok {
			return false
		}
		_, _ = io.WriteString(c, reply)
		return reply == "S"
	}
}

// mysqlGreeting is a protocol-10 initial handshake with capabilities caps.
func mysqlGreeting(caps uint16) []byte {
	p := []byte{10}
	p = append(p, "8.4.0-fake\x00"...)
	p = append(p, 1, 0, 0, 0)                     // connection id
	p = append(p, "12345678"...)                  // auth-plugin-data part 1
	p = append(p, 0)                              // filler
	p = binary.LittleEndian.AppendUint16(p, caps) // capability flags (lower)
	p = append(p, 0x21, 2, 0, 0, 0, 21)           // charset, status, upper caps, auth data length
	p = append(p, make([]byte, 10)...)
	return append([]byte{byte(len(p)), 0, 0, 0}, p...) // #nosec G115 -- the greeting is under 64 bytes
}

func mysqlFake(greeting []byte, ok bool) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		_, _ = c.Write(greeting)
		if !ok {
			return false
		}
		_, got := readN(s, br, 36)
		return got
	}
}

// mssqlFake answers PRELOGIN with ENCRYPTION=enc.
func mssqlFake(enc byte) func(*server, net.Conn, *bufio.Reader) bool {
	return func(s *server, c net.Conn, br *bufio.Reader) bool {
		typ, p, err := readTDSPacket(br)
		if err != nil {
			return false
		}
		s.record(fmt.Sprintf("tds %#x %x", typ, p))
		reply := []byte{
			tdsOptVersion, 0, 0x0b, 0, 6,
			tdsOptEncryption, 0, 0x11, 0, 1,
			tdsOptTerminator,
			16, 0, 0x07, 0xd0, 0, 0,
			enc,
		}
		_, _ = c.Write(tdsPacket(tdsTabularResult, 1, reply))
		return enc != tdsEncryptNotSup
	}
}

func wrapTDS(c net.Conn) net.Conn { return newTDSConn(c) }

func TestProtocolHandshakes(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	cfg := tlsCfg(t, p, p.inter.Cert)
	// length 32, sequence 1; LONG_PASSWORD|PROTOCOL_41|SSL|SECURE_CONNECTION;
	// max packet 16 MiB; utf8_general_ci; 23 zero bytes. No user name.
	mysqlSSLRequest := "20000001" + "018a0000" + "00000001" + "21" + strings.Repeat("00", 23)
	cases := []struct {
		name     string
		mode     string
		preamble func(*server, net.Conn, *bufio.Reader) bool
		wrap     func(net.Conn) net.Conn
		want     []string // what the server received before TLS, in hex
	}{
		{"rdp", StartTLSRDP, rdpFake(rdpNeg(rdpNegRsp, 1)), nil, []string{fmt.Sprintf("%x", rdpNegotiationRequest())}},
		{"rdp hybrid", StartTLSRDP, rdpFake(rdpNeg(rdpNegRsp, 2)), nil, []string{fmt.Sprintf("%x", rdpNegotiationRequest())}},
		{"postgres", StartTLSPostgres, postgresFake("S"), nil, []string{"0000000804d2162f"}},
		{"mysql", StartTLSMySQL, mysqlFake(mysqlGreeting(0xffff), true), nil, []string{mysqlSSLRequest}},
		{"mssql", StartTLSMSSQL, mssqlFake(0x00), wrapTDS, []string{fmt.Sprintf("tds %#x %x", tdsPrelogin, tdsPreloginRequest()[tdsHeaderLen:])}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServerWrap(t, cfg, tc.preamble, tc.wrap)
			res, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), SNI: "www.example.test", StartTLS: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Verification.Verified || res.StartTLS != tc.mode || len(res.Chain) == 0 {
				t.Fatalf("result %+v", res)
			}
			_ = srv.ln.Close()
			srv.wg.Wait()
			got := srv.lines()
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("server received\n %q\nwant\n %q", got, tc.want)
			}
			if srv.clientCerts.Load() != 0 || srv.conns.Load() != 1 {
				t.Fatalf("client certs %d, conns %d", srv.clientCerts.Load(), srv.conns.Load())
			}
		})
	}
}

func TestProtocolHandshakeFailures(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now, now.Add(-time.Hour), 90*24*time.Hour)
	cfg := tlsCfg(t, p, p.inter.Cert)
	raw := func(b []byte) func(*server, net.Conn, *bufio.Reader) bool {
		return func(_ *server, c net.Conn, br *bufio.Reader) bool {
			_, _ = br.Peek(1)
			_, _ = c.Write(b)
			return false
		}
	}
	cases := []struct {
		name     string
		mode     string
		preamble func(*server, net.Conn, *bufio.Reader) bool
		want     error
	}{
		{"rdp standard security", StartTLSRDP, rdpFake(rdpNeg(rdpNegRsp, 0)), ErrSTARTTLSNotOffered},
		{"rdp no negotiation", StartTLSRDP, rdpFake(nil), ErrSTARTTLSNotOffered},
		{"rdp failure", StartTLSRDP, rdpFake(rdpNeg(rdpNegFailure, 5)), ErrSTARTTLSRefused},
		{"rdp not tpkt", StartTLSRDP, raw([]byte("HTTP/1.1 400 Bad\r\n\r\n")), nil},
		{"postgres no ssl", StartTLSPostgres, postgresFake("N"), ErrSTARTTLSNotOffered},
		{"postgres error", StartTLSPostgres, postgresFake("E"), ErrSTARTTLSRefused},
		{"postgres injection", StartTLSPostgres, postgresFake("Sinjected"), ErrPreTLSInjection},
		{"postgres garbage", StartTLSPostgres, postgresFake("X"), nil},
		{"mysql no ssl", StartTLSMySQL, mysqlFake(mysqlGreeting(0xf7ff), false), ErrSTARTTLSNotOffered},
		{"mysql error packet", StartTLSMySQL, mysqlFake([]byte{5, 0, 0, 0, 0xff, 0x6a, 0x04, 'H', 'o'}, false), ErrSTARTTLSRefused},
		{"mysql truncated", StartTLSMySQL, mysqlFake([]byte{3, 0, 0, 0, 10, 'x', 0}, false), nil},
		{"mysql oversized", StartTLSMySQL, mysqlFake([]byte{0xff, 0xff, 0xff, 0}, false), nil},
		{"mssql not supported", StartTLSMSSQL, mssqlFake(tdsEncryptNotSup), ErrSTARTTLSNotOffered},
		{"mssql wrong packet", StartTLSMSSQL, raw(tdsPacket(0x01, 1, []byte("select"))), nil},
		{"mssql no encryption option", StartTLSMSSQL, raw(tdsPacket(tdsTabularResult, 1, []byte{tdsOptTerminator})), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, cfg, tc.preamble)
			_, err := newProber(p.roots, now).Probe(context.Background(), Target{Host: "127.0.0.1", Port: srv.port(), StartTLS: tc.mode, Timeout: 2 * time.Second})
			if err == nil {
				t.Fatal("probe succeeded")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if bytes.Contains([]byte(err.Error()), []byte("Ho")) || bytes.Contains([]byte(err.Error()), []byte("HTTP")) {
				t.Fatalf("server text leaked into the error: %v", err)
			}
		})
	}
}

func TestAutoModeByPort(t *testing.T) {
	for port, want := range map[int]string{3389: StartTLSRDP, 5432: StartTLSPostgres, 3306: StartTLSMySQL, 1433: StartTLSMSSQL, 636: StartTLSNone, 993: StartTLSNone} {
		got, err := startTLSMode(StartTLSAuto, port)
		if err != nil || got != want {
			t.Errorf("port %d: %q, %v; want %q", port, got, err, want)
		}
	}
}

func TestTDSConnSplitsLargeWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	payload := bytes.Repeat([]byte{0xab}, tdsMaxPacketBytes+10)
	go func() { _, _ = newTDSConn(c1).Write(payload) }()
	r := newTDSConn(c2)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed in TDS framing")
	}
}
