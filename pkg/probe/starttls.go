package probe

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Bounds on what a plaintext pre-TLS exchange may read.
const (
	maxPreTLSBytes = 64 << 10
	maxReplyLines  = 100
	maxLineBytes   = 2048
)

// Sentinel errors for STARTTLS.
var (
	ErrSTARTTLSNotOffered = errors.New("server does not offer STARTTLS")
	ErrSTARTTLSRefused    = errors.New("server refused STARTTLS")
	ErrPreTLSInjection    = errors.New("server sent data after the STARTTLS reply and before TLS (possible STARTTLS injection); aborted")
	errLineTooLong        = errors.New("server line too long")
	errTooManyLines       = errors.New("server reply has too many lines")
)

// startTLS runs the plaintext upgrade for mode on conn. Server text is never
// returned in errors (it is untrusted); only reply codes are.
func startTLS(conn net.Conn, mode string) error {
	if mode == StartTLSNone {
		return nil
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, maxPreTLSBytes), maxLineBytes)
	var err error
	switch mode {
	case StartTLSSMTP:
		err = smtpStartTLS(conn, br)
	case StartTLSIMAP:
		err = imapStartTLS(conn, br)
	case StartTLSPOP3:
		err = pop3StartTLS(conn, br)
	case StartTLSLDAP:
		err = ldapStartTLS(conn, br)
	default:
		err = ErrInvalidSTARTTLS
	}
	if err != nil {
		return err
	}
	if br.Buffered() > 0 {
		return ErrPreTLSInjection
	}
	return nil
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errLineTooLong
	}
	if err != nil {
		return "", fmt.Errorf("read server line: %w", err)
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// readSMTPReply reads one (possibly multi-line) SMTP reply.
func readSMTPReply(br *bufio.Reader) (code int, lines []string, err error) {
	for i := 0; i < maxReplyLines; i++ {
		line, err := readLine(br)
		if err != nil {
			return 0, nil, err
		}
		if len(line) < 3 {
			return 0, nil, errors.New("malformed SMTP reply")
		}
		c, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, nil, errors.New("malformed SMTP reply code")
		}
		lines = append(lines, line)
		if len(line) == 3 || line[3] == ' ' {
			return c, lines, nil
		}
		if line[3] != '-' {
			return 0, nil, errors.New("malformed SMTP reply separator")
		}
	}
	return 0, nil, errTooManyLines
}

func write(conn net.Conn, s string) error {
	if _, err := io.WriteString(conn, s); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func smtpStartTLS(conn net.Conn, br *bufio.Reader) error {
	code, _, err := readSMTPReply(br)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if code != 220 {
		return fmt.Errorf("greeting: unexpected reply code %d", code)
	}
	// EHLO with an address literal of our own end, as RFC 5321 §4.1.4 allows.
	ehlo := "[127.0.0.1]"
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if v4 := la.IP.To4(); v4 != nil {
			ehlo = "[" + v4.String() + "]"
		} else {
			ehlo = "[IPv6:" + la.IP.String() + "]"
		}
	}
	if err := write(conn, "EHLO "+ehlo+"\r\n"); err != nil {
		return err
	}
	code, lines, err := readSMTPReply(br)
	if err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}
	if code != 250 {
		return fmt.Errorf("ehlo: unexpected reply code %d", code)
	}
	offered := false
	for _, l := range lines[1:] {
		if len(l) > 4 && strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			offered = true
		}
	}
	if !offered {
		return ErrSTARTTLSNotOffered
	}
	if err := write(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	code, _, err = readSMTPReply(br)
	if err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if code != 220 {
		return fmt.Errorf("%w (reply code %d)", ErrSTARTTLSRefused, code)
	}
	return nil
}

func imapStartTLS(conn net.Conn, br *bufio.Reader) error {
	greet, err := readLine(br)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(greet), "* OK") {
		return errors.New("greeting: server did not send * OK")
	}
	if err := write(conn, "a1 STARTTLS\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxReplyLines; i++ {
		line, err := readLine(br)
		if err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		if strings.HasPrefix(line, "* ") {
			continue // untagged data
		}
		if strings.HasPrefix(strings.ToUpper(line), "A1 OK") {
			return nil
		}
		return ErrSTARTTLSRefused
	}
	return errTooManyLines
}

func pop3StartTLS(conn net.Conn, br *bufio.Reader) error {
	greet, err := readLine(br)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if !strings.HasPrefix(greet, "+OK") {
		return errors.New("greeting: server did not send +OK")
	}
	if err := write(conn, "STLS\r\n"); err != nil {
		return err
	}
	line, err := readLine(br)
	if err != nil {
		return fmt.Errorf("stls: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return ErrSTARTTLSRefused
	}
	return nil
}

// ldapStartTLSRequest is LDAPMessage{ messageID 1, ExtendedRequest {
// requestName "1.3.6.1.4.1.1466.20037" } } (RFC 4511 §4.14.1).
func ldapStartTLSRequest() []byte {
	// SEQUENCE(29) { INTEGER 1, [APPLICATION 23](24) { [0](22) OID } }
	return append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, "1.3.6.1.4.1.1466.20037"...)
}

func ldapStartTLS(conn net.Conn, br *bufio.Reader) error {
	if _, err := conn.Write(ldapStartTLSRequest()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	msg, err := readBERElement(br)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	// LDAPMessage ::= SEQUENCE { messageID INTEGER, ExtendedResponse [APPLICATION 24] { resultCode ENUMERATED, ... } }
	tag, body, _, err := berTLV(msg)
	if err != nil || tag != 0x30 {
		return errors.New("malformed LDAP response")
	}
	tag, id, rest, err := berTLV(body)
	if err != nil || tag != 0x02 || !bytes.Equal(id, []byte{0x01}) {
		return errors.New("malformed LDAP response message ID")
	}
	tag, op, _, err := berTLV(rest)
	if err != nil || tag != 0x78 {
		return errors.New("LDAP response is not an ExtendedResponse")
	}
	tag, rc, _, err := berTLV(op)
	if err != nil || tag != 0x0a || len(rc) != 1 {
		return errors.New("malformed LDAP resultCode")
	}
	if rc[0] != 0 {
		return fmt.Errorf("%w (LDAP resultCode %d)", ErrSTARTTLSRefused, rc[0])
	}
	return nil
}

// berTLV splits one BER element with a single-byte tag and a definite
// length in short or long form (up to 4 length bytes, minimal or not, as
// LDAP servers such as Active Directory send).
func berTLV(b []byte) (tag byte, value, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("short BER element")
	}
	tag, l := b[0], int(b[1])
	b = b[2:]
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < n {
			return 0, nil, nil, errors.New("unsupported BER length")
		}
		l = 0
		for _, x := range b[:n] {
			l = l<<8 | int(x)
		}
		b = b[n:]
	}
	if l > len(b) {
		return 0, nil, nil, errors.New("truncated BER element")
	}
	return tag, b[:l], b[l:], nil
}

// readBERElement reads one definite-length BER element (max 64 KiB).
func readBERElement(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := int(hdr[1])
	out := hdr
	if hdr[1]&0x80 != 0 {
		n := int(hdr[1] & 0x7f)
		if n == 0 || n > 4 {
			return nil, errors.New("unsupported BER length")
		}
		lb := make([]byte, n)
		if _, err := io.ReadFull(br, lb); err != nil {
			return nil, fmt.Errorf("read length: %w", err)
		}
		out = append(out, lb...)
		length = 0
		for _, b := range lb {
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > maxPreTLSBytes {
		return nil, errors.New("LDAP response too large")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return append(out, body...), nil
}
