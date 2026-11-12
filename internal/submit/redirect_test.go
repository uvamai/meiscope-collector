package submit_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// TestSubmitDoesNotFollowRedirects: a 307 from the core URL to another
// server is not followed (a 307 would replay the observation batch), and the
// error says why. It is permanent: retrying would meet the same redirect.
func TestSubmitDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/moved", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	for _, hc := range []*http.Client{nil, origin.Client()} {
		cl, err := submit.New(origin.URL, hc, submit.WithRetry(retry.Policy{Attempts: 2}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cl.Submit(context.Background(), []submit.Observation{ctObservation(1)})
		if !submit.IsPermanent(err) || !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), "307") {
			t.Fatalf("err %v", err)
		}
		if _, err := cl.Scopes(context.Background()); err == nil || !strings.Contains(err.Error(), "not followed") {
			t.Fatalf("scopes: %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect target was called %d times", hits.Load())
	}
}
