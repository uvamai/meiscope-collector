// Package testpki generates throwaway certificates and keys at test time,
// so no private key is ever committed. It is imported only by tests.
package testpki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" // #nosec G501 -- deliberately produces weak test certificates
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// CA is an issuing certificate and its key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// ECKey returns a fresh P-256 key.
func ECKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// RSAKey returns a fresh RSA key of the given size.
func RSAKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n.Add(n, big.NewInt(1))
}

// Create signs tmpl with parentKey under parent (tmpl itself when parent is nil).
func Create(t testing.TB, tmpl, parent *x509.Certificate, pub any, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = serial(t)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return c
}

// NewRoot creates a self-signed root CA valid around now.
func NewRoot(t testing.TB, cn string, now time.Time) *CA {
	t.Helper()
	k := ECKey(t)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"meiscope test"}},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return &CA{Cert: Create(t, tmpl, nil, k.Public(), k), Key: k}
}

// NewIntermediate creates an intermediate CA under ca.
func (ca *CA) NewIntermediate(t testing.TB, cn string, now time.Time) *CA {
	t.Helper()
	k := ECKey(t)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return &CA{Cert: Create(t, tmpl, ca.Cert, k.Public(), ca.Key), Key: k}
}

// LeafTemplate is a TLS server template for the given names.
func LeafTemplate(cn string, notBefore time.Time, lifetime time.Duration, dns ...string) *x509.Certificate {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		NotBefore:   notBefore,
		NotAfter:    notBefore.Add(lifetime - time.Second),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dns,
	}
	for _, d := range dns {
		if ip := net.ParseIP(d); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	return tmpl
}

// Issue signs a leaf under ca with a fresh P-256 key.
func (ca *CA) Issue(t testing.TB, tmpl *x509.Certificate) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	k := ECKey(t)
	return Create(t, tmpl, ca.Cert, k.Public(), ca.Key), k
}

// PEM encodes certificates as concatenated CERTIFICATE blocks.
func PEM(certs ...*x509.Certificate) string {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

// TLSCertificate builds a tls.Certificate serving leaf followed by chain.
func TLSCertificate(leaf *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) tls.Certificate {
	tc := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return tc
}

// PKCS7 wraps certificates in a degenerate certs-only SignedData (RFC 5652).
func PKCS7(t testing.TB, certs ...*x509.Certificate) []byte {
	t.Helper()
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
	}
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      contentInfo
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      contentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal signed data: %v", err)
	}
	out, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		// [0] EXPLICIT, written by hand: asn1.Marshal ignores tags on a
		// RawValue whose FullBytes is set.
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
	if err != nil {
		t.Fatalf("marshal content info: %v", err)
	}
	return out
}

// MD5Signed re-signs a SHA-256/RSA certificate with MD5, which Go refuses
// to create directly. key must be the issuer's RSA key.
func MD5Signed(t testing.TB, c *x509.Certificate, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	sha256RSA := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	md5RSA := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04}
	tbs := bytes.Replace(c.RawTBSCertificate, sha256RSA, md5RSA, 1)
	h := md5.Sum(tbs) // #nosec G401 -- deliberately weak test certificate
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5, h[:])
	if err != nil {
		t.Fatalf("md5 sign: %v", err)
	}
	der, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}{
		TBS: asn1.RawValue{FullBytes: tbs},
		Alg: asn1.RawValue{FullBytes: append(append([]byte{0x30, 0x0d}, md5RSA...), 0x05, 0x00)},
		Sig: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal md5 certificate: %v", err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse md5 certificate: %v", err)
	}
	return out
}
