package ct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// TestCertSpotterRefusesKeyOverHTTP: with an API key configured, an http://
// Cert Spotter URL is refused before any request is made.
func TestCertSpotterRefusesKeyOverHTTP(t *testing.T) {
	srv := newFakeCertSpotter(t, csFixture, 100)
	cs := NewCertSpotter(srv.URL, nil, clock.NewFake(t0), CertSpotterPoliteness, "test", staticCreds{CertSpotterKeyRef: "k-1"})
	_, _, err := cs.Issuances(context.Background(), "owned.example", "")
	if !errors.Is(err, ErrKeyOverHTTP) {
		t.Fatalf("err %v, want ErrKeyOverHTTP", err)
	}
	if n := len(srv.reqs()); n != 0 {
		t.Fatalf("%d requests reached the http:// server", n)
	}
	// Without a key, http:// stays allowed (local mirrors, tests).
	cs = NewCertSpotter(srv.URL, nil, clock.NewFake(t0), CertSpotterPoliteness, "test", nil)
	if _, _, err := cs.Issuances(context.Background(), "owned.example", ""); err != nil {
		t.Fatalf("keyless http: %v", err)
	}
}

// TestCTClientDoesNotFollowRedirects: a 307 from the Cert Spotter URL to
// another server is not followed, so the API key is not replayed there.
func TestCTClientDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer elsewhere.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/v1/issuances", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	cs := NewCertSpotter(origin.URL, origin.Client().Transport, clock.NewFake(t0), CertSpotterPoliteness, "test", staticCreds{CertSpotterKeyRef: "k-1"})
	_, _, err := cs.Issuances(context.Background(), "owned.example", "")
	if !errors.Is(err, redirect.ErrRefused) {
		t.Fatalf("err %v, want redirect.ErrRefused", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect target was called %d times", hits.Load())
	}
}
