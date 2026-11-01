// Command gen writes the synthetic Cert Spotter fixture
// (certspotter/issuances-owned.example.json) and the matching issuer names of
// the crt.sh fixture. Every certificate is issued by a throwaway fixture CA
// for names under the reserved owned.example domain (WP0.10: tests use
// reserved names only). Keys come from fixed seeds and Ed25519 signatures are
// deterministic, so the output is the same on every run.
//
//	go run ./internal/ct/testdata/gen
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fixtureCA is one synthetic issuer; crtshName is the issuer_name crt.sh rows
// carry for it.
type fixtureCA struct {
	cn   string
	key  ed25519.PrivateKey
	cert *x509.Certificate
}

func (c fixtureCA) name() string { return "O=Meiscope test data, CN=" + c.cn }

// issuance is one Cert Spotter item: its id (the pagination cursor), the
// certificate serial (shared with the crt.sh rows), validity and names.
type issuance struct {
	id, serial, notBefore, notAfter string
	names                           []string
	ca                              int
}

var issuances = []issuance{
	{"17283841456", "67e50314ae38328291cdac8d5501cce2a5b", "2026-09-19T18:56:57Z", "2026-12-18T18:56:56Z", []string{"mirai.owned.example"}, 1},
	{"17389535029", "56023280154b21e5dfc53baea2269beab8f", "2026-09-24T15:37:12Z", "2026-12-23T15:37:11Z", []string{"owned.example", "www.owned.example"}, 1},
	{"17404892526", "535504b601ff4809b76774758e72a9d7860", "2026-09-25T10:12:32Z", "2026-12-24T10:12:31Z", []string{"hive.owned.example"}, 0},
	{"17495069787", "5aeaad4e8f0b70391bae5bda1b61ab8cf8a", "2026-09-30T05:55:12Z", "2026-12-29T05:55:11Z", []string{"crm.owned.example"}, 0},
}

func seedKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("meiscope ct fixture " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Fatal(err)
	}
	return t
}

func newCA(cn string) fixtureCA {
	key := seedKey(cn)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Meiscope test data"}, CommonName: cn},
		NotBefore:             mustTime("2026-01-01T00:00:00Z"),
		NotAfter:              mustTime("2028-01-01T00:00:00Z"),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return fixtureCA{cn: cn, key: key, cert: cert}
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func main() {
	dir := filepath.Join("internal", "ct", "testdata")
	cas := []fixtureCA{newCA("Fixture CA 1 (synthetic)"), newCA("Fixture CA 2 (synthetic)")}

	type issuer struct {
		FriendlyName string `json:"friendly_name"`
		PubkeySHA256 string `json:"pubkey_sha256"`
		Name         string `json:"name"`
	}
	type item struct {
		ID           string   `json:"id"`
		TBSSHA256    string   `json:"tbs_sha256"`
		CertSHA256   string   `json:"cert_sha256"`
		DNSNames     []string `json:"dns_names"`
		PubkeySHA256 string   `json:"pubkey_sha256"`
		Issuer       issuer   `json:"issuer"`
		NotBefore    string   `json:"not_before"`
		NotAfter     string   `json:"not_after"`
		Revoked      bool     `json:"revoked"`
		CertDER      []byte   `json:"cert_der"`
	}
	var out []item
	for _, is := range issuances {
		serial, ok := new(big.Int).SetString(is.serial, 16)
		if !ok {
			log.Fatalf("serial %s", is.serial)
		}
		ca := cas[is.ca]
		key := seedKey(is.id)
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: is.names[0]},
			DNSNames:     is.names,
			NotBefore:    mustTime(is.notBefore),
			NotAfter:     mustTime(is.notAfter),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(nil, tmpl, ca.cert, key.Public(), ca.key)
		if err != nil {
			log.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Fatal(err)
		}
		out = append(out, item{
			ID: is.id, TBSSHA256: hexSum(cert.RawTBSCertificate), CertSHA256: hexSum(der), DNSNames: is.names,
			PubkeySHA256: hexSum(cert.RawSubjectPublicKeyInfo),
			Issuer:       issuer{FriendlyName: "Meiscope fixture CA (synthetic)", PubkeySHA256: hexSum(ca.cert.RawSubjectPublicKeyInfo), Name: ca.name()},
			NotBefore:    is.notBefore, NotAfter: is.notAfter, CertDER: der,
		})
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certspotter", "issuances-owned.example.json"), append(b, '\n'), 0o600); err != nil {
		log.Fatal(err)
	}

	// The crt.sh rows keep their ids, serials, names and dates; only the
	// issuer names change to the fixture CAs (by crt.sh issuer_ca_id).
	crtsh := filepath.Join(dir, "crtsh", "search-owned.example.json")
	rows, err := os.ReadFile(crtsh)
	if err != nil {
		log.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(rows, &list); err != nil {
		log.Fatal(err)
	}
	byID := map[float64]string{432952: cas[0].name(), 431054: cas[1].name()}
	for _, r := range list {
		id, _ := r["issuer_ca_id"].(float64)
		name, ok := byID[id]
		if !ok {
			log.Fatalf("crt.sh row with unknown issuer_ca_id %v", r["issuer_ca_id"])
		}
		r["issuer_name"] = name
	}
	b, err = json.Marshal(list)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(crtsh, append([]byte(strings.TrimSpace(string(b))), '\n'), 0o600); err != nil {
		log.Fatal(err)
	}
}
