// Package fixture replays recorded, redacted API responses for adapter
// tests. Every adapter keeps its fixtures under testdata/adapters/<name>/
// at the repository root; HTTP exchanges are JSON files of the form
//
//	{"request": {"method": "GET", "path": "/api/v1/x", "query": "page=0"},
//	 "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": {...}}}
//
// Replay is deterministic: a request matches by method, path and query
// (parameters in any order), and an unmatched request fails the call. A
// request may also name "body_contains": the exchange then matches only a
// request whose body contains that text (several exchanges may share a
// method, path and query when they differ by it, as POST queries do).
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
		// BodyContains, when set, must occur in the request body.
		BodyContains string `json:"body_contains,omitempty"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

// Transport is an http.RoundTripper serving recorded exchanges.
type Transport struct {
	byKey map[string][]Exchange

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
	t := &Transport{byKey: map[string][]Exchange{}}
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
		k := key(ex.Request.Method, ex.Request.Path, q)
		for _, prev := range t.byKey[k] {
			if prev.Request.BodyContains == ex.Request.BodyContains {
				return nil, fmt.Errorf("fixture %s: duplicate exchange %s", f, k)
			}
		}
		t.byKey[k] = append(t.byKey[k], ex)
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

// RoundTrip serves the recorded response of a matching exchange.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	t.mu.Lock()
	c := r.Clone(r.Context())
	if body != nil {
		c.Body = io.NopCloser(bytes.NewReader(body))
	}
	t.requests = append(t.requests, c)
	t.mu.Unlock()
	var ex Exchange
	ok := false
	// An exchange naming body text wins over one that does not.
	for _, cand := range t.byKey[key(r.Method, r.URL.Path, r.URL.Query())] {
		if cand.Request.BodyContains != "" && bytes.Contains(body, []byte(cand.Request.BodyContains)) {
			ex, ok = cand, true
			break
		}
		if cand.Request.BodyContains == "" && !ok {
			ex, ok = cand, true
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
		Body:       io.NopCloser(bytes.NewReader(ex.Response.Body)),
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
