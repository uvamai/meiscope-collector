package ct

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/clock"
)

// CrtShURL is the crt.sh base URL.
const CrtShURL = "https://crt.sh"

// CrtShEntry is one row of crt.sh's JSON output.
type CrtShEntry struct {
	ID           int64  `json:"id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

// Names returns the entry's names (name_value is newline-separated), lower
// case.
func (e CrtShEntry) Names() []string {
	var out []string
	for _, n := range strings.Split(e.NameValue+"\n"+e.CommonName, "\n") {
		if n = normalizeName(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// CrtSh is a client of crt.sh, used only as a fallback (crt.sh has no SLA)
// and for the coverage baseline. Every request is spaced by
// CrtShPoliteness.MinInterval (10 s by default).
type CrtSh struct {
	base string
	hc   *http.Client
	clk  clock.Clock
}

// NewCrtSh returns a client. base is CrtShURL in production.
func NewCrtSh(base string, rt http.RoundTripper, clk clock.Clock, p Politeness, userAgent string) *CrtSh {
	return &CrtSh{base: strings.TrimRight(base, "/"), hc: newHTTPClient(rt, clk, p, userAgent), clk: clk}
}

// Search returns the unexpired certificates crt.sh knows for domain and its
// subdomains. crt.sh merges a precertificate and its certificate into one
// row.
func (c *CrtSh) Search(ctx context.Context, domain string) ([]CrtShEntry, error) {
	q := url.Values{}
	q.Set("q", domain)
	q.Set("output", "json")
	q.Set("exclude", "expired")
	body, err := getBytes(ctx, c.hc, c.clk, c.base+"/?"+q.Encode(), http.Header{"Accept": {"application/json"}}, 64<<20)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	var out []CrtShEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("crt.sh: decode: %w", err)
	}
	return out, nil
}

// Certificate downloads the certificate with crt.sh id (PEM or DER) and
// returns its DER.
func (c *CrtSh) Certificate(ctx context.Context, id int64) ([]byte, error) {
	body, err := getBytes(ctx, c.hc, c.clk, c.base+"/?d="+strconv.FormatInt(id, 10), nil, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN")) {
		blk, _ := pem.Decode(bytes.TrimSpace(body))
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("crt.sh: certificate %d: no PEM CERTIFICATE block", id)
		}
		return blk.Bytes, nil
	}
	return body, nil
}
