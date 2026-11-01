package probe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Pre-TLS negotiation for RDP, PostgreSQL, MySQL and Microsoft SQL Server.
// Each sends only the protocol's request to start TLS: no user name, no
// password, no database name and no query. Server bytes are parsed with
// fixed bounds and never returned in errors.

// rdpNegotiationRequest is a TPKT-framed X.224 Connection Request carrying
// RDP_NEG_REQ with requestedProtocols PROTOCOL_SSL|PROTOCOL_HYBRID
// (MS-RDPBCGR 2.2.1.1). Asking for HYBRID too lets servers that require
// Network Level Authentication start TLS; CredSSP would only begin after the
// TLS handshake, which the probe abandons at the Certificate message.
func rdpNegotiationRequest() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI 14, dst-ref, src-ref, class 0
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ, flags 0, length 8, SSL|HYBRID
	}
}

// RDP negotiation results.
const (
	rdpNegRsp     = 0x02
	rdpNegFailure = 0x03
	rdpProtoRDP   = 0x00000000 // standard RDP security: no TLS
)

func rdpStartTLS(conn net.Conn, br *bufio.Reader) error {
	if _, err := conn.Write(rdpNegotiationRequest()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return fmt.Errorf("read TPKT header: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if hdr[0] != 0x03 || n < 11 || n > 512 {
		return errors.New("malformed TPKT header")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(br, body); err != nil {
		return fmt.Errorf("read X.224: %w", err)
	}
	// X.224 Connection Confirm: LI, 0xD0, dst-ref(2), src-ref(2), class.
	if body[1]&0xf0 != 0xd0 {
		return errors.New("X.224 reply is not a Connection Confirm")
	}
	neg := body[7:]
	if len(neg) < 8 {
		return fmt.Errorf("%w (no RDP negotiation response: standard RDP security only)", ErrSTARTTLSNotOffered)
	}
	switch neg[0] {
	case rdpNegRsp:
		if binary.LittleEndian.Uint32(neg[4:8]) == rdpProtoRDP {
			return fmt.Errorf("%w (server selected standard RDP security)", ErrSTARTTLSNotOffered)
		}
		return nil
	case rdpNegFailure:
		return fmt.Errorf("%w (RDP negotiation failure code %d)", ErrSTARTTLSRefused, binary.LittleEndian.Uint32(neg[4:8]))
	default:
		return errors.New("malformed RDP negotiation response")
	}
}

// postgresSSLRequest is the PostgreSQL SSLRequest message: length 8, code
// 80877103 (PostgreSQL protocol, "SSL Session Encryption").
func postgresSSLRequest() []byte {
	return []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
}

func postgresStartTLS(conn net.Conn, br *bufio.Reader) error {
	if _, err := conn.Write(postgresSSLRequest()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	b, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read SSLRequest reply: %w", err)
	}
	switch b {
	case 'S':
		return nil // anything buffered after this is caught as injection
	case 'N':
		return ErrSTARTTLSNotOffered
	case 'E':
		return ErrSTARTTLSRefused
	default:
		return errors.New("malformed SSLRequest reply")
	}
}

// MySQL capability flags used by the SSL request.
const (
	mysqlClientLongPassword     = 0x00000001
	mysqlClientProtocol41       = 0x00000200
	mysqlClientSSL              = 0x00000800
	mysqlClientSecureConnection = 0x00008000
)

// readMySQLPacket reads one packet (3-byte little-endian length, sequence).
func readMySQLPacket(br *bufio.Reader) (seq byte, payload []byte, err error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return 0, nil, fmt.Errorf("read packet header: %w", err)
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 1 || n > 1024 {
		return 0, nil, errors.New("malformed MySQL packet length")
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, fmt.Errorf("read packet: %w", err)
	}
	return hdr[3], payload, nil
}

// mysqlStartTLS reads the server's initial handshake (protocol 10), checks
// CLIENT_SSL and sends the 32-byte SSLRequest (capabilities, max packet,
// character set, filler). The SSLRequest carries no user name.
func mysqlStartTLS(conn net.Conn, br *bufio.Reader) error {
	seq, p, err := readMySQLPacket(br)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if p[0] == 0xff {
		return fmt.Errorf("%w (server sent an error packet)", ErrSTARTTLSRefused)
	}
	if p[0] != 10 {
		return errors.New("greeting: unsupported MySQL protocol version")
	}
	// server version (NUL-terminated), connection id (4), auth data (8), filler (1), capabilities (2)
	i := 1
	for i < len(p) && p[i] != 0 {
		i++
	}
	i += 1 + 4 + 8 + 1
	if i+2 > len(p) {
		return errors.New("greeting: truncated")
	}
	if binary.LittleEndian.Uint16(p[i:])&mysqlClientSSL == 0 {
		return ErrSTARTTLSNotOffered
	}
	req := make([]byte, 4+32)
	req[0], req[3] = 32, seq+1
	binary.LittleEndian.PutUint32(req[4:], mysqlClientLongPassword|mysqlClientProtocol41|mysqlClientSSL|mysqlClientSecureConnection)
	binary.LittleEndian.PutUint32(req[8:], 1<<24) // max packet size
	req[12] = 0x21                                // utf8_general_ci; bytes 13..35 are zero filler
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// TDS (MS-TDS) constants.
const (
	tdsPrelogin       = 0x12
	tdsTabularResult  = 0x04
	tdsStatusEOM      = 0x01
	tdsHeaderLen      = 8
	tdsOptVersion     = 0x00
	tdsOptEncryption  = 0x01
	tdsOptTerminator  = 0xff
	tdsEncryptOn      = 0x01
	tdsEncryptNotSup  = 0x02
	tdsMaxPacketBytes = 4096
)

// tdsPreloginRequest is a PRELOGIN packet with VERSION (zeros) and
// ENCRYPTION=ENCRYPT_ON (MS-TDS 2.2.6.5).
func tdsPreloginRequest() []byte {
	payload := []byte{
		tdsOptVersion, 0x00, 0x0b, 0x00, 0x06, // VERSION at 11, length 6
		tdsOptEncryption, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at 17, length 1
		tdsOptTerminator,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version (unknown client)
		tdsEncryptOn,
	}
	return tdsPacket(tdsPrelogin, 1, payload)
}

func tdsPacket(typ, id byte, payload []byte) []byte {
	p := make([]byte, tdsHeaderLen, tdsHeaderLen+len(payload))
	p[0], p[1], p[6] = typ, tdsStatusEOM, id
	binary.BigEndian.PutUint16(p[2:], uint16(tdsHeaderLen+len(payload))) // #nosec G115 -- payload is bounded by tdsMaxPacketBytes
	return append(p, payload...)
}

// readTDSPacket reads one TDS packet and returns its type and payload.
func readTDSPacket(r io.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, tdsHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, fmt.Errorf("read TDS header: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n < tdsHeaderLen || n > tdsMaxPacketBytes+tdsHeaderLen {
		return 0, nil, errors.New("malformed TDS packet length")
	}
	payload = make([]byte, n-tdsHeaderLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read TDS packet: %w", err)
	}
	return hdr[0], payload, nil
}

// mssqlStartTLS sends PRELOGIN and reads the server's ENCRYPTION option.
// The caller then runs TLS inside TDS PRELOGIN packets (tdsConn).
func mssqlStartTLS(conn net.Conn, br *bufio.Reader) error {
	if _, err := conn.Write(tdsPreloginRequest()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	typ, p, err := readTDSPacket(br)
	if err != nil {
		return fmt.Errorf("prelogin reply: %w", err)
	}
	if typ != tdsTabularResult {
		return errors.New("prelogin reply is not a tabular result")
	}
	for i := 0; i+5 <= len(p) && p[i] != tdsOptTerminator; i += 5 {
		if p[i] != tdsOptEncryption {
			continue
		}
		off, n := int(binary.BigEndian.Uint16(p[i+1:])), int(binary.BigEndian.Uint16(p[i+3:]))
		if n != 1 || off >= len(p) {
			return errors.New("malformed prelogin ENCRYPTION option")
		}
		if p[off] == tdsEncryptNotSup {
			return ErrSTARTTLSNotOffered
		}
		return nil
	}
	return errors.New("prelogin reply has no ENCRYPTION option")
}

// tdsConn carries the TLS handshake inside TDS PRELOGIN packets, as SQL
// Server expects before login (MS-TDS 3.2.5.2). Only the handshake ever
// crosses it: the probe abandons TLS at the server's Certificate message.
type tdsConn struct {
	net.Conn
	mu     sync.Mutex
	nextID byte
	rbuf   []byte
}

func newTDSConn(c net.Conn) *tdsConn { return &tdsConn{Conn: c, nextID: 2} }

func (c *tdsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for len(b) > 0 {
		n := min(len(b), tdsMaxPacketBytes)
		if _, err := c.Conn.Write(tdsPacket(tdsPrelogin, c.nextID, b[:n])); err != nil {
			return written, err
		}
		c.nextID++
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *tdsConn) Read(b []byte) (int, error) {
	for len(c.rbuf) == 0 {
		typ, p, err := readTDSPacket(c.Conn)
		if err != nil {
			return 0, err
		}
		if typ != tdsPrelogin && typ != tdsTabularResult {
			return 0, errors.New("unexpected TDS packet type during TLS handshake")
		}
		c.rbuf = p
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}
