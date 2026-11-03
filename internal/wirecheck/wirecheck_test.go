package wirecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/testpki"
	"github.com/uvamai/meiscope-collector/pkg/probe"
)

// recordProbe runs the real probe through a proxy that keeps every byte
// the client sends, against a TLS server limited to version max.
func recordProbe(t *testing.T, maxVersion uint16) []byte {
	t.Helper()
	now := time.Now()
	root := testpki.NewRoot(t, "Wire Root", now)
	leaf, key := root.Issue(t, testpki.LeafTemplate("www.example.test", now.Add(-time.Hour), time.Hour*24, "www.example.test"))
	cfg := &tls.Config{Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}, MaxVersion: maxVersion}
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = tls.Server(c, cfg).Handshake()
	}()
	px, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	var mu sync.Mutex
	var sent bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := px.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			return
		}
		defer b.Close()
		go func() { _, _ = io.Copy(c, b) }()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			mu.Lock()
			sent.Write(buf[:n])
			mu.Unlock()
			if n > 0 {
				_, _ = b.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	_, err = probe.New(probe.Options{Roots: roots}).Probe(context.Background(), probe.Target{Host: "127.0.0.1", Port: px.Addr().(*net.TCPAddr).Port, SNI: "www.example.test", StartTLS: probe.StartTLSNone})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return bytes.Clone(sent.Bytes())
}

func TestRealProbeStreamsPass(t *testing.T) {
	for name, v := range map[string]uint16{"TLS 1.3": tls.VersionTLS13, "TLS 1.2": tls.VersionTLS12} {
		b := recordProbe(t, v)
		r, err := CheckClient(b)
		if err != nil {
			t.Fatalf("%s: %v (records %v)", name, err, r.Records)
		}
		if !r.TLS || r.PreTLS != 0 || r.Records[0] != recHandshake {
			t.Fatalf("%s: %+v", name, r)
		}
		t.Logf("%s: client records %v", name, r.Records)
	}
}

func record(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...) // #nosec G115 -- test records are small
}

func TestCheckClientRefuses(t *testing.T) {
	hello := record(recHandshake, []byte{1, 0, 0, 2, 3, 3})
	cases := map[string][]byte{
		"finished-sized encrypted record": append(append([]byte(nil), hello...), record(recApplicationData, make([]byte, 53))...),
		"two encrypted records":           append(append(append([]byte(nil), hello...), record(recApplicationData, make([]byte, 19))...), record(recApplicationData, make([]byte, 19))...),
		"client key exchange":             append(append([]byte(nil), hello...), record(recHandshake, []byte{16, 0, 0, 1, 0})...),
		"certificate":                     append(append([]byte(nil), hello...), record(recHandshake, []byte{11, 0, 0, 0})...),
		"heartbeat":                       append(append([]byte(nil), hello...), record(24, []byte{1, 2, 3})...),
		"long alert":                      append(append([]byte(nil), hello...), record(recAlert, []byte{2, 40, 0})...),
		"stray bytes":                     append(append([]byte(nil), hello...), 1, 2),
		"truncated":                       hello[:len(hello)-1],
		"three hellos":                    bytes.Repeat(hello, 3),
	}
	for name, b := range cases {
		if _, err := CheckClient(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Plaintext before TLS (an SSLRequest) and an encrypted alert are fine.
	ok := append(append(append([]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}, hello...), record(recChangeCipherSpec, []byte{1})...), record(recApplicationData, make([]byte, 19))...)
	if r, err := CheckClient(ok); err != nil || r.PreTLS != 8 {
		t.Fatalf("starttls stream: %+v %v", r, err)
	}
	if r, err := CheckClient([]byte("EHLO [127.0.0.1]\r\n")); err != nil || r.TLS {
		t.Fatalf("no tls: %+v %v", r, err)
	}
}

// pcapOf builds a classic little-endian Ethernet pcap of IPv4 TCP packets.
func pcapOf(pkts ...[]byte) []byte {
	var b bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], linkEthernet)
	b.Write(h)
	for _, p := range pkts {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint32(r[8:], uint32(len(p)))  // #nosec G115 -- test packets are small
		binary.LittleEndian.PutUint32(r[12:], uint32(len(p))) // #nosec G115 -- test packets are small
		b.Write(r)
		b.Write(p)
	}
	return b.Bytes()
}

func tcpPacket(srcPort, dstPort uint16, seq uint32, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(payload))) // #nosec G115 -- test packets are small
	ip[9] = 6
	copy(ip[12:], []byte{127, 0, 0, 1})
	copy(ip[16:], []byte{127, 0, 0, 1})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	return append(append(append(eth, ip...), tcp...), payload...)
}

func TestReadStreamsReassembles(t *testing.T) {
	pcap := pcapOf(
		tcpPacket(40000, 443, 100, []byte("abc")),
		tcpPacket(443, 40000, 900, []byte("server")), // server direction: ignored
		tcpPacket(40000, 443, 106, []byte("ghi")),    // out of order
		tcpPacket(40000, 443, 103, []byte("def")),
		tcpPacket(40000, 443, 103, []byte("def")),  // retransmission
		tcpPacket(40001, 8080, 1, []byte("other")), // not a listed port
	)
	streams, err := ReadStreams(bytes.NewReader(pcap), []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 1 || string(streams[0].Bytes) != "abcdefghi" || streams[0].Server != "127.0.0.1:443" {
		t.Fatalf("streams %+v", streams)
	}
	if _, err := ReadStreams(strings.NewReader("not a pcap file at all.."), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}
