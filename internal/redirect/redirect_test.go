package redirect_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// check runs redirect.Check on a hand-made answer to a request for
// https://core.example.test/x with the given status and Location.
func check(code int, loc string) error {
	r := &http.Response{
		StatusCode: code, Header: http.Header{}, Body: http.NoBody,
		Request: &http.Request{URL: &url.URL{Scheme: "https", Host: "core.example.test", Path: "/x"}},
	}
	defer func() { _ = r.Body.Close() }()
	if loc != "" {
		r.Header.Set("Location", loc)
	}
	return redirect.Check(r)
}

func TestCheck(t *testing.T) {
	for _, code := range []int{200, 201, 204, 304, 400, 404, 500} {
		if err := check(code, "https://elsewhere.example.test/"); err != nil {
			t.Errorf("%d: %v", code, err)
		}
	}
	for _, code := range []int{300, 301, 302, 303, 307, 308} {
		err := check(code, "https://elsewhere.example.test/steal?token=secret-value")
		if !errors.Is(err, redirect.ErrRefused) || !strings.Contains(err.Error(), "https://elsewhere.example.test") {
			t.Errorf("%d: %v", code, err)
			continue
		}
		if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "/steal") {
			t.Errorf("%d: the error carries the Location path or query: %v", code, err)
		}
	}
	// A relative Location resolves against the request; none at all is named as unknown.
	if err := check(302, "/other"); err == nil || !strings.Contains(err.Error(), "https://core.example.test") {
		t.Errorf("relative: %v", err)
	}
	if err := check(302, ""); !errors.Is(err, redirect.ErrRefused) || !strings.Contains(err.Error(), "unknown location") {
		t.Errorf("no Location: %v", err)
	}
	if redirect.Check(nil) != nil {
		t.Error("nil response")
	}
}

func TestClientCopies(t *testing.T) {
	if redirect.Client(nil) != nil {
		t.Fatal("nil client")
	}
	orig := &http.Client{}
	c := redirect.Client(orig)
	if c == orig || orig.CheckRedirect != nil || c.CheckRedirect == nil {
		t.Fatal("Client must return a refusing copy and leave the original alone")
	}
	if !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("CheckRedirect does not hand back the 3xx answer")
	}
}
