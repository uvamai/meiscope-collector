package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/credential"
)

// Credentials are an AWS access key, or temporary role-session credentials
// when SessionToken is set. They come from credential.Source just in time
// and live only for one sync; Secret never prints.
type Credentials struct {
	AccessKeyID     credential.Secret
	SecretAccessKey credential.Secret
	SessionToken    credential.Secret
}

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	amzDate      = "20060102T150405Z"
)

// unsignedHeaders are never part of the signature (the transport may change
// them after signing).
var unsignedHeaders = map[string]bool{"authorization": true, "user-agent": true, "accept-encoding": true, "content-length": true}

// sign signs r with Signature Version 4 (header form) for region and
// service at now. body is the exact request body (nil for none). The query
// string is re-encoded in canonical form so what is sent is what was signed.
// Every header present on r, except the unsigned ones, is signed, plus host.
func sign(r *http.Request, body []byte, c Credentials, region, service string, now time.Time) {
	now = now.UTC()
	date := now.Format(amzDate)
	r.Header.Set("X-Amz-Date", date)
	if !c.SessionToken.Empty() {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken.Reveal())
	}
	if r.Host == "" {
		r.Host = r.URL.Host
	}
	r.URL.RawQuery = canonicalQuery(r.URL.Query())

	names := []string{"host"}
	values := map[string]string{"host": r.Host}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if unsignedHeaders[lk] || lk == "host" {
			continue
		}
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		names = append(names, lk)
		values[lk] = strings.Join(trimmed, ",")
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + values[n] + "\n")
	}
	signed := strings.Join(names, ";")

	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	bodySum := sha256.Sum256(body)
	canonical := strings.Join([]string{r.Method, path, r.URL.RawQuery, ch.String(), signed, hex.EncodeToString(bodySum[:])}, "\n")
	crSum := sha256.Sum256([]byte(canonical))
	scope := date[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := sigAlgorithm + "\n" + date + "\n" + scope + "\n" + hex.EncodeToString(crSum[:])

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey.Reveal()), date[:8])
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))

	r.Header.Set("Authorization", sigAlgorithm+" Credential="+c.AccessKeyID.Reveal()+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// canonicalQuery encodes q as SigV4 requires: keys sorted, then values,
// each URI-encoded with only unreserved characters left as they are.
func canonicalQuery(q url.Values) string {
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, kv{uriEncode(k), uriEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

func uriEncode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}
