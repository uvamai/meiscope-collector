package adapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// The Getter never follows a redirect, even with a client that would, so a
// bearer credential never reaches the redirect's target (M3).
func TestGetterRefusesRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("followed"))
	}))
	defer other.Close()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/elsewhere", code)
		}))
		// A client whose own policy follows every redirect.
		hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
		g := &adapter.Getter{HTTP: hc, Env: adapter.Env{Clock: clock.NewFake(t0)}, Bearer: credential.NewSecret("test-only-bearer")}
		u, _ := url.Parse(origin.URL + "/metrics")
		_, err := g.Get(context.Background(), u, "text/plain")
		origin.Close()
		if !adapter.IsStatus(err, code) {
			t.Errorf("%d: error %v, want the redirect status", code, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a redirect was followed %d times", n)
	}
}

// A body with a declared Content-Length is read whole; one past the limit
// is refused.
func TestGetterBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	env := adapter.Env{Clock: clock.NewFake(t0)}
	b, err := (&adapter.Getter{HTTP: srv.Client(), Env: env, MaxBody: 10}).Get(context.Background(), u, "")
	if err != nil || string(b) != "0123456789" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := (&adapter.Getter{HTTP: srv.Client(), Env: env, MaxBody: 9}).Get(context.Background(), u, ""); err == nil {
		t.Fatal("a body over the limit was accepted")
	}
}
