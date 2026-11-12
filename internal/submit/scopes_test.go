package submit_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// scopeList is a ScopeList as the contract describes it (one scope).
const scopePayload = `{"id":"7d0f4c3e-2a51-4b8e-9c61-0e2f5a7b9d13","tenant_id":"5e0c2a7d-0000-4000-8000-000000000001","version":3,` +
	`"targets":[{"host":"192.0.2.10","port":443,"protocol":"tls"}],` +
	`"scan_policy":{"deny":[],"rate_per_24":1,"burst":1,"connect_timeout_seconds":5,"windows":[],"canary_percent":1,"dry_run":true},` +
	`"authorisation":{"by":"owner@example.test","at":"2026-11-01T00:00:00Z","document":"TEST-1"},` +
	`"not_before":"2026-11-01T00:00:00Z","not_after":"2026-12-01T00:00:00Z"}`

const scopeList = `{"scopes":[{"payload":` + scopePayload + `,"signature":"c2lnbmF0dXJl","key_id":"scope-1"}]}`

func TestScopesFetchesTheSignedList(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.SpecPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate("ScopeList", []byte(scopeList)); err != nil {
		t.Fatalf("the test list does not follow the contract: %v", err)
	}
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != submit.ScopesPath {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // retried
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(scopeList))
	}))
	defer srv.Close()
	cl, err := submit.New(srv.URL, srv.Client(), submit.WithClock(clock.NewFake(t0)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.Scopes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The payload bytes are kept exactly as received: the signature is
	// over them.
	if len(got) != 1 || got[0].KeyID != "scope-1" || string(got[0].Signature) != "signature" ||
		!bytes.Equal(got[0].Payload, []byte(scopePayload)) || calls.Load() != 2 {
		t.Fatalf("%d calls, scopes %+v", calls.Load(), got)
	}
}

func TestScopesRefusesAnswerWithoutList(t *testing.T) {
	for _, body := range []string{`{}`, `{"scopes":null}`, `[]`} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		cl, _ := submit.New(srv.URL, srv.Client())
		if _, err := cl.Scopes(context.Background()); err == nil {
			t.Errorf("accepted %s", body)
		}
		srv.Close()
	}
	// 401: the collector is not authenticated; not retried.
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	cl, _ := submit.New(srv.URL, srv.Client())
	if _, err := cl.Scopes(context.Background()); !submit.IsPermanent(err) || calls.Load() != 1 {
		t.Fatalf("%v after %d calls", err, calls.Load())
	}
}
