package osquery_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/redirect"
)

// TestFleetDoesNotFollowRedirects: a 307 from the configured Fleet to another
// server is not followed, so the API token is not replayed there.
func TestFleetDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	var leaked atomic.Bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), fleetToken) {
			leaked.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	env, logs := newEnv(t, origin.Client().Transport)
	cfg := fleetConfig()
	cfg.Settings["url"] = origin.URL
	cfg.Settings["queries"] = "meiscope_certificates_posix"
	_, err := newAdapter(env).Sync(context.Background(), cfg, "")
	if !errors.Is(err, redirect.ErrRefused) {
		t.Fatalf("err %v, want redirect.ErrRefused", err)
	}
	if hits.Load() != 0 || leaked.Load() {
		t.Fatalf("redirect target called %d times, token leaked %v", hits.Load(), leaked.Load())
	}
	if strings.Contains(err.Error()+logs.String(), fleetToken) {
		t.Fatal("token in the error or logs")
	}
}
