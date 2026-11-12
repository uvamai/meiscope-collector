package adapter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is the contract's certificate fingerprint, not a security primitive
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uvamai/meiscope-collector/internal/submit"
)

// MaxPEMCertificates bounds the certificates read from one PEM bundle.
const MaxPEMCertificates = 64

// ErrNoCertificate is returned when a PEM bundle holds no certificate.
var ErrNoCertificate = errors.New("no certificate in the PEM data")

// ParsePEMCertificates parses the CERTIFICATE blocks of a PEM bundle, in
// order. Blocks of any other type are skipped without being decoded or kept,
// so a bundle that also holds a private key never exposes it.
func ParsePEMCertificates(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(out) < MaxPEMCertificates {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, errors.New("a CERTIFICATE block does not parse as X.509")
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, ErrNoCertificate
	}
	return out, nil
}

// CertificateMetadata describes a parsed certificate in the contract's
// terms. It reads only public certificate fields.
func CertificateMetadata(c *x509.Certificate) *submit.CertificateMetadata {
	s1 := sha1.Sum(c.Raw) //nolint:gosec // fingerprint
	s2 := sha256.Sum256(c.Raw)
	nb, na := c.NotBefore.UTC(), c.NotAfter.UTC()
	ca := c.IsCA
	self := bytes.Equal(c.RawIssuer, c.RawSubject)
	m := &submit.CertificateMetadata{
		SHA1:             hex.EncodeToString(s1[:]),
		SHA256:           hex.EncodeToString(s2[:]),
		Serial:           SerialHex(c.SerialNumber),
		Subject:          Clip(c.Subject.String(), 4096),
		Issuer:           Clip(c.Issuer.String(), 4096),
		CommonName:       Clip(c.Subject.CommonName, 1024),
		NotBefore:        &nb,
		NotAfter:         &na,
		CA:               &ca,
		SelfSigned:       &self,
		KeyAlgorithm:     Clip(c.PublicKeyAlgorithm.String(), 64),
		SigningAlgorithm: Clip(c.SignatureAlgorithm.String(), 64),
		SubjectKeyID:     Clip(hex.EncodeToString(c.SubjectKeyId), 128),
		AuthorityKeyID:   Clip(hex.EncodeToString(c.AuthorityKeyId), 128),
	}
	if bits := keyBits(c); bits > 0 {
		m.KeyStrength = strconv.Itoa(bits)
	}
	for i, n := range c.DNSNames {
		if i == 256 {
			break
		}
		m.DNSNames = append(m.DNSNames, Clip(n, 253))
	}
	return m
}

func keyBits(c *x509.Certificate) int {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// SerialHex formats a serial number as lower-case hex without leading zeros.
func SerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	if n.Sign() < 0 {
		return "-" + new(big.Int).Neg(n).Text(16)
	}
	return n.Text(16)
}

// NormalizeHexSerial turns a serial written as hex with optional separators
// ("0A:1B", "0a 1b") into lower-case hex without leading zeros; "" when it
// is not hex.
func NormalizeHexSerial(s string) string {
	s = strings.NewReplacer(":", "", " ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" || len(s) > 128 {
		return ""
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return ""
	}
	return SerialHex(n)
}

// NormalizeFingerprint turns "AB:CD ..." into lower-case hex of n bytes, or
// "" when it is not one.
func NormalizeFingerprint(s string, n int) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "\t", "").Replace(strings.TrimSpace(s)))
	if len(s) != 2*n {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

// Clip shortens s, trimmed, to at most n bytes on a rune boundary.
func Clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// ObservedAt is the observation time of a run: the clock, in UTC, to the
// second.
func ObservedAt(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

// Fingerprint is a short digest of an observation without its time, for
// delta cursors: an unchanged record has an unchanged fingerprint.
func Fingerprint(o submit.Observation) string {
	o.ObservedAt = time.Time{}
	b, err := json.Marshal(o)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}
