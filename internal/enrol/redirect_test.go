package enrol_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// TestEnrolDoesNotFollowRedirects: a 307 (which would replay the POST body,
// the one-time token and the CSR) to another server is not followed.
func TestEnrolDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer elsewhere.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	cl, err := enrol.New(origin.URL, origin.Client(), "meiscope-collector/test")
	if err != nil {
		t.Fatal(err)
	}
	const token = "mse1_redirect_synthetic" //nolint:gosec // a fake token
	_, err = cl.Enrol(context.Background(), token, newCSR(t))
	if !errors.Is(err, redirect.ErrRefused) || strings.Contains(err.Error(), token) {
		t.Fatalf("err %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the token was replayed to the redirect target (%d requests)", hits.Load())
	}
	// The caller's client is not changed.
	if origin.Client().CheckRedirect != nil {
		t.Fatal("enrol.New changed the caller's http.Client")
	}
}
