// Package wirecheck checks, from what actually crossed the network, that the
// probe stops after the server's certificate: once TLS starts, the client
// may send only its ClientHello, the TLS 1.3 compatibility ChangeCipherSpec
// and one alert. A Finished message, a key exchange, a client certificate or
// any application data would show up as another record and fail the check.
//
// It reads classic pcap files (tcpdump -w) of Ethernet or Linux cooked
// captures, reassembles each TCP stream from client to server, and checks
// the streams sent to the listed server ports.
package wirecheck

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// TLS record content types.
const (
	recChangeCipherSpec = 20
	recAlert            = 21
	recHandshake        = 22
	recApplicationData  = 23
)

// maxEncryptedAlert is the largest TLS 1.3 record that can only be an alert:
// 2 bytes of alert, 1 byte of inner content type and a 16-byte AEAD tag. A
// Finished message (at least 4+32+1+16 = 53 bytes) cannot fit.
const maxEncryptedAlert = 19

// Stream is what one client sent to one server port, in order.
type Stream struct {
	Client, Server string // ip:port
	Bytes          []byte
}

// Result describes a client stream that was checked.
type Result struct {
	PreTLS  int    // plaintext bytes before the ClientHello (STARTTLS, SSLRequest, ...)
	Records []byte // content types of the client's TLS records, in order
	TLS     bool   // the client started TLS
}

// CheckClient checks one client-to-server stream.
func CheckClient(b []byte) (Result, error) {
	start := clientHelloAt(b)
	if start < 0 {
		return Result{PreTLS: len(b)}, nil // no TLS started (closed port, plain server, refused upgrade)
	}
	r := Result{PreTLS: start, TLS: true}
	b = b[start:]
	hellos, encrypted := 0, 0
	for len(b) > 0 {
		if len(b) < 5 {
			return r, fmt.Errorf("%d stray bytes after the last TLS record", len(b))
		}
		typ, n := b[0], int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return r, fmt.Errorf("truncated TLS record of type %d", typ)
		}
		body := b[5 : 5+n]
		r.Records = append(r.Records, typ)
		switch typ {
		case recHandshake:
			for len(body) > 0 {
				if len(body) < 4 {
					return r, errors.New("truncated handshake message")
				}
				if body[0] != 1 {
					return r, fmt.Errorf("client sent handshake message type %d after its ClientHello (only ClientHello is allowed)", body[0])
				}
				m := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if len(body) < 4+m {
					break // a ClientHello split across records
				}
				hellos++
				body = body[4+m:]
			}
			if hellos > 2 { // the first ClientHello and one after a HelloRetryRequest
				return r, fmt.Errorf("client sent %d ClientHello messages", hellos)
			}
		case recChangeCipherSpec:
			if n != 1 {
				return r, errors.New("malformed ChangeCipherSpec")
			}
		case recAlert:
			if n != 2 {
				return r, fmt.Errorf("alert record of %d bytes", n)
			}
		case recApplicationData:
			encrypted++
			if n > maxEncryptedAlert || encrypted > 1 {
				return r, fmt.Errorf("client sent an encrypted record of %d bytes (only one encrypted alert of at most %d bytes is allowed)", n, maxEncryptedAlert)
			}
		default:
			return r, fmt.Errorf("client sent a TLS record of content type %d", typ)
		}
		b = b[5+n:]
	}
	return r, nil
}

// clientHelloAt finds the first TLS record that starts a ClientHello.
func clientHelloAt(b []byte) int {
	for i := 0; i+6 <= len(b); i++ {
		if b[i] == recHandshake && b[i+1] == 3 && b[i+2] >= 1 && b[i+2] <= 3 && b[i+5] == 1 {
			return i
		}
	}
	return -1
}

// Pcap link types.
const (
	linkEthernet = 1
	linkLinuxSLL = 113
)

// ReadStreams reads a classic pcap and returns the reassembled TCP streams
// whose destination port is in serverPorts.
func ReadStreams(r io.Reader, serverPorts []int) ([]Stream, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(hdr) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.BigEndian
	default:
		return nil, errors.New("not a classic pcap file (use tcpdump -w)")
	}
	link := bo.Uint32(hdr[20:])
	if link != linkEthernet && link != linkLinuxSLL {
		return nil, fmt.Errorf("unsupported link type %d", link)
	}
	type seg struct {
		seq  uint32
		data []byte
	}
	flows := map[string][]seg{}
	var order []string
	rec := make([]byte, 16)
	for {
		if _, err := io.ReadFull(r, rec); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("pcap record: %w", err)
		}
		n := bo.Uint32(rec[8:])
		if n > 1<<20 {
			return nil, errors.New("pcap record too large")
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return nil, fmt.Errorf("pcap packet: %w", err)
		}
		src, dst, seq, payload, ok := tcpPayload(pkt, link)
		if !ok || len(payload) == 0 || !slices.Contains(serverPorts, portOf(dst)) {
			continue
		}
		k := src + ">" + dst
		if _, seen := flows[k]; !seen {
			order = append(order, k)
		}
		flows[k] = append(flows[k], seg{seq, payload})
	}
	var out []Stream
	for _, k := range order {
		segs := flows[k]
		// TCP sequence numbers wrap: compare by signed 32-bit difference.
		slices.SortStableFunc(segs, func(a, b seg) int { return int(int32(a.seq - b.seq)) }) // #nosec G115 -- intended wrap-around
		var data []byte
		var next uint32
		for i, s := range segs {
			switch {
			case i == 0:
				data, next = append(data, s.data...), s.seq+uint32(len(s.data)) // #nosec G115 -- segment sizes are small
			case int32(s.seq-next) >= 0: // new data (gaps cannot happen on loopback)
				data, next = append(data, s.data...), s.seq+uint32(len(s.data)) // #nosec G115 -- segment sizes are small
			case int32(s.seq+uint32(len(s.data))-next) > 0: // #nosec G115 -- partly retransmitted
				skip := int(next - s.seq)
				data, next = append(data, s.data[skip:]...), s.seq+uint32(len(s.data)) // #nosec G115 -- segment sizes are small
			}
		}
		src, dst, _ := cut(k)
		out = append(out, Stream{Client: src, Server: dst, Bytes: data})
	}
	return out, nil
}

func cut(k string) (string, string, bool) { return strings.Cut(k, ">") }

func portOf(hostport string) int {
	i := strings.LastIndexByte(hostport, ':')
	p, err := strconv.Atoi(hostport[i+1:])
	if err != nil {
		return 0
	}
	return p
}

// tcpPayload extracts addresses, sequence number and payload of an IPv4 or
// IPv6 TCP packet.
func tcpPayload(pkt []byte, link uint32) (src, dst string, seq uint32, payload []byte, ok bool) {
	var etherType uint16
	switch link {
	case linkEthernet:
		if len(pkt) < 14 {
			return
		}
		etherType, pkt = binary.BigEndian.Uint16(pkt[12:]), pkt[14:]
	case linkLinuxSLL:
		if len(pkt) < 16 {
			return
		}
		etherType, pkt = binary.BigEndian.Uint16(pkt[14:]), pkt[16:]
	}
	var srcIP, dstIP string
	switch etherType {
	case 0x0800:
		if len(pkt) < 20 || pkt[9] != 6 {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:]))
		if total > len(pkt) || ihl < 20 || total < ihl {
			return
		}
		srcIP = fmt.Sprintf("%d.%d.%d.%d", pkt[12], pkt[13], pkt[14], pkt[15])
		dstIP = fmt.Sprintf("%d.%d.%d.%d", pkt[16], pkt[17], pkt[18], pkt[19])
		pkt = pkt[ihl:total]
	case 0x86dd:
		if len(pkt) < 40 || pkt[6] != 6 {
			return
		}
		plen := int(binary.BigEndian.Uint16(pkt[4:]))
		if 40+plen > len(pkt) {
			return
		}
		srcIP = fmt.Sprintf("[%x]", pkt[8:24])
		dstIP = fmt.Sprintf("[%x]", pkt[24:40])
		pkt = pkt[40 : 40+plen]
	default:
		return
	}
	if len(pkt) < 20 {
		return
	}
	off := int(pkt[12]>>4) * 4
	if off < 20 || off > len(pkt) {
		return
	}
	src = fmt.Sprintf("%s:%d", srcIP, binary.BigEndian.Uint16(pkt[0:]))
	dst = fmt.Sprintf("%s:%d", dstIP, binary.BigEndian.Uint16(pkt[2:]))
	return src, dst, binary.BigEndian.Uint32(pkt[4:]), pkt[off:], true
}
