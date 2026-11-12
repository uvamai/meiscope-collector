// Package fixture replays recorded, redacted API responses for adapter
// tests. Every adapter keeps its fixtures under testdata/adapters/<name>/
// at the repository root; HTTP exchanges are JSON files of the form
//
//	{"request": {"method": "GET", "path": "/api/v1/x", "query": "page=0"},
//	 "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": {...}}}
//
// Replay is deterministic: a request matches by method, path and query
// (parameters in any order), and an unmatched request fails the call.
// Optional request fields narrow the match for APIs that put the operation
// elsewhere: "host" (multi-region endpoints), "target" (the X-Amz-Target
// header of AWS JSON protocols) and "body" (a JSON request body, compared
// after canonical re-encoding). An exchange that sets them is preferred over
// one that does not. A response whose Content-Type is not JSON (the XML of
// AWS Query APIs) has its body written as a JSON string and is served as
// that string's text.
package fixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Root returns testdata/adapters at the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "adapters")
}

// Dir returns the fixture directory of an adapter, joined with elem.
func Dir(adapter string, elem ...string) string {
	return filepath.Join(append([]string{Root(), adapter}, elem...)...)
}

// Exchange is one recorded HTTP exchange.
type Exchange struct {
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Query  string `json:"query"`
		Host   string `json:"host,omitempty"`
		Target string `json:"target,omitempty"`
		// Body is a JSON request body; requests match it canonically.
		Body json.RawMessage `json:"body,omitempty"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

// Transport is an http.RoundTripper serving recorded exchanges.
type Transport struct {
	byKey map[string]Exchange

	mu       sync.Mutex
	requests []*http.Request
}

// Load reads every *.json exchange in dir.
func Load(dir string) (*Transport, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("fixture: no exchanges in %s", dir)
	}
	t := &Transport{byKey: map[string]Exchange{}}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			return nil, err
		}
		var ex Exchange
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ex); err != nil {
			return nil, fmt.Errorf("fixture %s: %w", f, err)
		}
		q, err := url.ParseQuery(ex.Request.Query)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", f, err)
		}
		body, err := canonicalJSON(ex.Request.Body)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: request body: %w", f, err)
		}
		k := key(ex.Request.Method, ex.Request.Path, q) + "|" + strings.ToLower(ex.Request.Host) + "|" + ex.Request.Target + "|" + body
		if _, dup := t.byKey[k]; dup {
			return nil, fmt.Errorf("fixture %s: duplicate exchange %s", f, k)
		}
		t.byKey[k] = ex
	}
	return t, nil
}

func key(method, path string, q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			b.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(v) + "&")
		}
	}
	return strings.ToUpper(method) + " " + path + "?" + b.String()
}

// responseBody returns the bytes to serve: the JSON as recorded, or for a
// non-JSON Content-Type the text of a JSON string body.
func responseBody(ex Exchange) []byte {
	ct := ""
	for k, v := range ex.Response.Headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
		}
	}
	if ct != "" && !strings.Contains(ct, "json") {
		var text string
		if json.Unmarshal(ex.Response.Body, &text) == nil {
			return []byte(text)
		}
	}
	return ex.Response.Body
}

// canonicalJSON re-encodes a JSON document with sorted keys; empty input is "".
func canonicalJSON(b []byte) (string, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return "", nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

// RoundTrip serves the recorded response of a matching exchange.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, r.Clone(r.Context()))
	t.mu.Unlock()
	var body string
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		body, _ = canonicalJSON(b)
	}
	base := key(r.Method, r.URL.Path, r.URL.Query())
	host, target := strings.ToLower(r.URL.Hostname()), r.Header.Get("X-Amz-Target")
	var ex Exchange
	ok := false
	for _, k := range []string{
		base + "|" + host + "|" + target + "|" + body,
		base + "||" + target + "|" + body,
		base + "|" + host + "||",
		base + "|||",
	} {
		if ex, ok = t.byKey[k]; ok {
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("fixture: no recorded exchange for %s %s", r.Method, r.URL.RequestURI())
	}
	h := http.Header{}
	for k, v := range ex.Response.Headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: ex.Response.Status,
		Status:     fmt.Sprintf("%d %s", ex.Response.Status, http.StatusText(ex.Response.Status)),
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(responseBody(ex))),
		Request:    r,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}, nil
}

// Requests returns the requests seen so far, in order.
func (t *Transport) Requests() []*http.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*http.Request(nil), t.requests...)
}
