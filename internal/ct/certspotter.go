package ct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// CertSpotterURL is the Cert Spotter API base.
const CertSpotterURL = "https://api.certspotter.com"

// CertSpotterKeyRef is the credential reference of the Cert Spotter API key.
const CertSpotterKeyRef = "certspotter_api_key"

// ErrKeyOverHTTP refuses to send the Cert Spotter API key to a plain http://
// URL (MEISCOPE_CT_CERTSPOTTER_URL).
var ErrKeyOverHTTP = errors.New("cert spotter: an API key is configured but MEISCOPE_CT_CERTSPOTTER_URL is not https://; refusing to send the key in clear text")

// maxPages bounds one domain's pagination per poll.
const maxPages = 1000

// Issuance is one item of GET /v1/issuances (fields we use).
type Issuance struct {
	ID         string   `json:"id"`
	TBSSHA256  string   `json:"tbs_sha256"`
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
	CertDER    []byte   `json:"cert_der"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
}

// CertSpotter is a client of the Cert Spotter issuances API
// (https://sslmate.com/help/reference/ct_search_api_v1). It works without an
// API key at the free-tier limits; with a key from the credential source it
// sends it as a bearer token.
type CertSpotter struct {
	base  string
	hc    *http.Client
	clk   clock.Clock
	creds credential.Source
}

// NewCertSpotter returns a client. base is CertSpotterURL in production.
func NewCertSpotter(base string, rt http.RoundTripper, clk clock.Clock, p Politeness, userAgent string, creds credential.Source) *CertSpotter {
	if creds == nil {
		creds = credential.None{}
	}
	return &CertSpotter{base: strings.TrimRight(base, "/"), hc: newHTTPClient(rt, clk, p, userAgent), clk: clk, creds: creds}
}

// Issuances returns the issuances for domain and its subdomains (wildcards
// included) with an id after the cursor `after` ("" for all), following
// the pagination to the end. It returns the issuances and the new cursor.
// Cert Spotter returns unexpired certificates only.
func (c *CertSpotter) Issuances(ctx context.Context, domain, after string) ([]Issuance, string, error) {
	key, err := c.creds.Get(ctx, CertSpotterKeyRef)
	if err != nil && !errors.Is(err, credential.ErrNotFound) {
		return nil, after, fmt.Errorf("cert spotter credential: %w", err)
	}
	hdr := http.Header{"Accept": {"application/json"}}
	if !key.Empty() {
		// The key is a credential: never send it in clear text.
		if !strings.HasPrefix(strings.ToLower(c.base), "https://") {
			return nil, after, ErrKeyOverHTTP
		}
		hdr.Set("Authorization", "Bearer "+key.Reveal())
	}
	var all []Issuance
	cursor := after
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("domain", domain)
		q.Set("include_subdomains", "true")
		q.Set("match_wildcards", "true")
		q.Add("expand", "dns_names")
		q.Add("expand", "cert_der")
		if cursor != "" {
			q.Set("after", cursor)
		}
		body, err := getBytes(ctx, c.hc, c.clk, c.base+"/v1/issuances?"+q.Encode(), hdr, 64<<20)
		if err != nil {
			return all, cursor, fmt.Errorf("cert spotter: %w", err)
		}
		var items []Issuance
		if err := json.Unmarshal(body, &items); err != nil {
			return all, cursor, fmt.Errorf("cert spotter: decode issuances: %w", err)
		}
		if len(items) == 0 {
			return all, cursor, nil
		}
		for _, it := range items {
			if len(it.CertDER) == 0 {
				return all, cursor, fmt.Errorf("cert spotter: issuance %s has no cert_der", it.ID)
			}
			sum := sha256.Sum256(it.CertDER)
			if it.CertSHA256 != "" && !strings.EqualFold(it.CertSHA256, hex.EncodeToString(sum[:])) {
				return all, cursor, fmt.Errorf("cert spotter: issuance %s: cert_der does not match cert_sha256", it.ID)
			}
		}
		all = append(all, items...)
		cursor = items[len(items)-1].ID
	}
	return all, cursor, fmt.Errorf("cert spotter: more than %d pages for one domain", maxPages)
}
