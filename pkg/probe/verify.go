package probe

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// Verification failure reasons.
const (
	ReasonExpired             = "expired"
	ReasonNotYetValid         = "not_yet_valid"
	ReasonUnknownAuthority    = "unknown_authority"
	ReasonMissingIntermediate = "missing_intermediate"
	ReasonHostnameMismatch    = "hostname_mismatch"
	ReasonNoCertificate       = "no_certificate"
	ReasonOther               = "other"
)

// Verification is the outcome of verifying a served chain.
type Verification struct {
	Verified bool `json:"verified"`
	// ChainVerified ignores the host name; HostnameMatches checks only it.
	ChainVerified   bool     `json:"chain_verified"`
	HostnameMatches bool     `json:"hostname_matches"`
	VerifiedAgainst string   `json:"verified_against"`
	Reasons         []string `json:"failure_reasons,omitempty"`
	Detail          string   `json:"detail,omitempty"`
	// LeafIssuerServed is false when the server did not send the
	// certificate that issued its leaf (and the leaf is not self-signed).
	LeafIssuerServed bool `json:"leaf_issuer_served"`
	// ChainInOrder is true when each served certificate is signed by the next.
	ChainInOrder bool `json:"chain_in_order"`
}

// verifyChain verifies chain (leaf first) for name at now. roots nil means
// the system trust store; on Windows and macOS that is the OS verifier.
func verifyChain(chain []*x509.Certificate, name string, roots *x509.CertPool, now time.Time) Verification {
	v := Verification{VerifiedAgainst: "system roots"}
	if roots != nil {
		v.VerifiedAgainst = "custom roots"
	}
	if len(chain) == 0 {
		v.Reasons = []string{ReasonNoCertificate}
		return v
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	v.LeafIssuerServed = issuerServed(chain)
	v.ChainInOrder = inOrder(chain)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	v.ChainVerified = err == nil
	if err != nil {
		v.Reasons = append(v.Reasons, classify(err, chain, now, v.LeafIssuerServed)...)
		v.Detail = Clean(err.Error())
	}
	herr := leaf.VerifyHostname(name)
	v.HostnameMatches = herr == nil
	if herr != nil {
		v.Reasons = append(v.Reasons, ReasonHostnameMismatch)
		if v.Detail == "" {
			v.Detail = Clean(herr.Error())
		}
	}
	v.Verified = v.ChainVerified && v.HostnameMatches
	return v
}

func classify(err error, chain []*x509.Certificate, now time.Time, leafIssuerServed bool) []string {
	var inv x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		var out []string
		for _, c := range chain {
			if now.After(c.NotAfter) {
				out = appendOnce(out, ReasonExpired)
			}
			if now.Before(c.NotBefore) {
				out = appendOnce(out, ReasonNotYetValid)
			}
		}
		if len(out) == 0 {
			out = []string{ReasonExpired}
		}
		return out
	case errors.As(err, &ua):
		if !leafIssuerServed {
			return []string{ReasonUnknownAuthority, ReasonMissingIntermediate}
		}
		return []string{ReasonUnknownAuthority}
	default:
		return []string{ReasonOther}
	}
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func issuerServed(chain []*x509.Certificate) bool {
	leaf := chain[0]
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return true
	}
	for _, c := range chain[1:] {
		if bytes.Equal(c.RawSubject, leaf.RawIssuer) && leaf.CheckSignatureFrom(c) == nil {
			return true
		}
	}
	return false
}

func inOrder(chain []*x509.Certificate) bool {
	for i := 0; i+1 < len(chain); i++ {
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return false
		}
	}
	return true
}
