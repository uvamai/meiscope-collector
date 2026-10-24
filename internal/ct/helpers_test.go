package ct

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

var t0 = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

type testCA struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Meiscope Test CA"},
		NotBefore:             t0.Add(-time.Hour),
		NotAfter:              t0.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{der: der, cert: cert, key: key}
}

var poisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// leaf issues a certificate (or a precertificate with the CT poison
// extension) for names.
func (ca testCA) leaf(t *testing.T, serial int64, precert bool, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    t0.Add(-time.Hour),
		NotAfter:     t0.Add(90 * 24 * time.Hour),
	}
	if precert {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: poisonOID, Critical: true, Value: []byte{0x05, 0x00}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeLogEntry builds an RFC 6962 get-entries item.
func fakeLogEntry(t *testing.T, ca testCA, der []byte, precert bool, ts uint64) ctgo.LeafEntry {
	t.Helper()
	te := ctgo.TimestampedEntry{Timestamp: ts}
	var extra []byte
	var err error
	if precert {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			t.Fatal(perr)
		}
		te.EntryType = ctgo.PrecertLogEntryType
		te.PrecertEntry = &ctgo.PreCert{IssuerKeyHash: sha256.Sum256(ca.cert.RawSubjectPublicKeyInfo), TBSCertificate: c.RawTBSCertificate}
		extra, err = cttls.Marshal(ctgo.PrecertChainEntry{PreCertificate: ctgo.ASN1Cert{Data: der}, CertificateChain: []ctgo.ASN1Cert{{Data: ca.der}}})
	} else {
		te.EntryType = ctgo.X509LogEntryType
		te.X509Entry = &ctgo.ASN1Cert{Data: der}
		extra, err = cttls.Marshal(ctgo.CertificateChain{Entries: []ctgo.ASN1Cert{{Data: ca.der}}})
	}
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := cttls.Marshal(ctgo.MerkleTreeLeaf{Version: ctgo.V1, LeafType: ctgo.TimestampedEntryLeafType, TimestampedEntry: &te})
	if err != nil {
		t.Fatal(err)
	}
	return ctgo.LeafEntry{LeafInput: leaf, ExtraData: extra}
}

// fakeRFC6962 serves get-sth and get-entries (at most maxPerReq entries per
// answer, as real logs cap their responses).
func fakeRFC6962(t *testing.T, entries []ctgo.LeafEntry, maxPerReq int) *httptest.Server {
	t.Helper()
	sig, err := cttls.Marshal(ctgo.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: []byte{0x30, 0x00},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ct/v1/get-sth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size": len(entries), "timestamp": t0.UnixMilli(),
			"sha256_root_hash":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"tree_head_signature": base64.StdEncoding.EncodeToString(sig),
		})
	})
	mux.HandleFunc("GET /ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		end, _ := strconv.Atoi(r.URL.Query().Get("end"))
		if start < 0 || end < start || start >= len(entries) {
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		end = min(end, len(entries)-1, start+maxPerReq-1)
		_ = json.NewEncoder(w).Encode(ctgo.GetEntriesResponse{Entries: entries[start : end+1]})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeCertSpotter serves recorded issuances like the real API: filtered by
// domain (with subdomains), ordered by id, after the cursor, pageSize per
// page.
type fakeCertSpotter struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	// status, when non-zero, is answered to every request with retryAfter.
	status     int
	retryAfter string
}

func newFakeCertSpotter(t *testing.T, fixture string, pageSize int) *fakeCertSpotter {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(fixture))
	if err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	if err := json.Unmarshal(b, &items); err != nil {
		t.Fatal(err)
	}
	id := func(m map[string]any) int64 { n, _ := strconv.ParseInt(m["id"].(string), 10, 64); return n }
	sort.Slice(items, func(i, j int) bool { return id(items[i]) < id(items[j]) })
	f := &fakeCertSpotter{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Clone(r.Context()))
		status, ra := f.status, f.retryAfter
		f.mu.Unlock()
		if status != 0 {
			if ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			http.Error(w, "rate limited", status)
			return
		}
		q := r.URL.Query()
		domain := q.Get("domain")
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		page := []map[string]any{}
		for _, it := range items {
			if id(it) <= after {
				continue
			}
			match := false
			for _, n := range it["dns_names"].([]any) {
				s := strings.TrimPrefix(n.(string), "*.")
				if s == domain || strings.HasSuffix(s, "."+domain) {
					match = true
				}
			}
			if match && len(page) < pageSize {
				page = append(page, it)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCertSpotter) reqs() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.requests...)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
