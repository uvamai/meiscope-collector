package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// enrolledFixture is a collector enrolled with a fake core whose clock is
// the test's clock.
type enrolledFixture struct {
	core *enroltest.Core
	clk  clock.Clock
	env  map[string]string
	dir  string
}

func newEnrolledFixture(t *testing.T, clk clock.Clock, lifetime time.Duration) *enrolledFixture {
	t.Helper()
	core := enroltest.NewCore(t)
	if lifetime > 0 {
		core.Lifetime = lifetime
	}
	core.SetNow(clk.Now)
	dir := t.TempDir()
	if _, errOut, err := runEnrol(t, enrolEnv(core, dir), "", "--token", "mse1_enrolled_run"); err != nil {
		t.Fatalf("enrol: %v (%s)", err, errOut)
	}
	return &enrolledFixture{
		core: core, clk: clk, dir: filepath.Join(dir, "state"),
		env: map[string]string{envStateDir: filepath.Join(dir, "state"), envCTInterval: "off"},
	}
}

func (f *enrolledFixture) getenv(k string) string { return f.env[k] }

func (f *enrolledFixture) deps() enrolledDeps {
	none := func(func(string) string) credential.Source { return credential.None{} }
	return enrolledDeps{clk: f.clk, base: f.core.Transport(), ct: ctDeps{clk: f.clk, creds: none}, creds: none}
}

func (f *enrolledFixture) runtime(t *testing.T, cfg platform.Config) *enrolledRuntime {
	t.Helper()
	rt, err := newEnrolledRuntime(f.getenv, cfg, quietLog(), f.deps())
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// corePayload is a valid scope payload (dry run, a documentation address).
func corePayload(t *testing.T, id string, version int64, now time.Time) []byte {
	t.Helper()
	sc := scope.Scope{
		ID: id, TenantID: "tenant-1", Version: version,
		Targets:       []scope.Target{{Host: "192.0.2.10", Port: 443, Protocol: scope.ProtocolTLS}},
		Policy:        scope.ScanPolicy{RatePer24: 1, Burst: 1, DryRun: true},
		Authorisation: scope.Authorisation{By: "owner@example.test", At: now.Add(-time.Hour), Document: "TEST-1"},
		NotBefore:     now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
	}
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnrolledConfigurationErrors(t *testing.T) {
	f := newEnrolledFixture(t, clock.NewFake(time.Now().Truncate(time.Second)), 0)

	// Enrolled + MEISCOPE_SCOPE_FILE is refused, through the run command too.
	f.env[envScopeFile] = filepath.Join(f.dir, "scopes.json")
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"run"}, &out, &errb, f.getenv); code != 1 ||
		!strings.Contains(errb.String(), "MEISCOPE_SCOPE_FILE is set, but this collector is enrolled") {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	delete(f.env, envScopeFile)

	// MEISCOPE_CORE_URL must name the core the collector enrolled with.
	if _, err := newEnrolledRuntime(f.getenv, platform.Config{CoreURL: "https://other-core.example"}, quietLog(), f.deps()); err == nil ||
		!strings.Contains(err.Error(), "enrolled with the core at "+f.core.URL) {
		t.Fatalf("core URL mismatch: %v", err)
	}
	if _, err := newEnrolledRuntime(f.getenv, platform.Config{CoreURL: f.core.URL + "/"}, quietLog(), f.deps()); err != nil {
		t.Fatalf("the same URL with a trailing slash: %v", err)
	}

	// Bounded intervals.
	for k, v := range map[string]string{envScopeRefresh: "10s", envCTInterval: "2m"} {
		f.env[k] = v
		if _, err := newEnrolledRuntime(f.getenv, platform.Config{}, quietLog(), f.deps()); err == nil || !strings.Contains(err.Error(), k) {
			t.Fatalf("%s=%s: %v", k, v, err)
		}
		delete(f.env, k)
	}
	f.env[envCTInterval] = "off"
}

func TestEnrolledScopesFetchedOverMTLSAndVerified(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 0)
	rt := f.runtime(t, platform.Config{})
	ctx := context.Background()
	now := clk.Now()

	f.core.SetScopes(corePayload(t, "scope-a", 1, now), corePayload(t, "scope-b", 1, now))
	if err := rt.scopes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rt.scopes.Signed()); n != 2 {
		t.Fatalf("%d scopes held", n)
	}
	if s := f.core.SerialsFor(submit.ScopesPath); len(s) != 1 || s[0] == "" {
		t.Fatalf("scopes were not fetched over mTLS: %v", s)
	}

	// A tampered signature and an unknown key are refused; a lower version
	// for a known id is refused too.
	good := corePayload(t, "scope-a", 2, now)
	tampered := scope.Signed{Payload: corePayload(t, "scope-c", 1, now), KeyID: f.core.KeyID}
	tampered.Signature = f.core.Sign(tampered.Payload)
	tampered.Signature[0] ^= 0xff
	unknown := scope.Signed{Payload: corePayload(t, "scope-d", 1, now), KeyID: "scope-other-key"}
	unknown.Signature = f.core.Sign(unknown.Payload)
	list, _ := json.Marshal(map[string]any{"scopes": []scope.Signed{
		{Payload: good, Signature: f.core.Sign(good), KeyID: f.core.KeyID}, tampered, unknown,
	}})
	f.core.SetScopesRaw(list)
	if err := rt.scopes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	st := rt.scopes.Status()
	if st.Count != 1 || st.IDs[0] != "scope-a" || st.Refused != 2 {
		t.Fatalf("status %+v", st)
	}
	f.core.SetScopes(corePayload(t, "scope-a", 1, now))
	if err := rt.scopes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st := rt.scopes.Status(); st.Count != 0 || st.Refused != 1 {
		t.Fatalf("a version rollback was accepted: %+v", st)
	}
	// The accepted versions are kept next to the identity.
	if b, err := os.ReadFile(filepath.Join(f.dir, scopeVersionsFile)); err != nil || !strings.Contains(string(b), "scope-a") {
		t.Fatalf("scope versions %s, %v", b, err)
	}

	// A failed fetch keeps the last good set.
	f.core.SetScopes(corePayload(t, "scope-a", 3, now))
	if err := rt.scopes.Refresh(ctx); err != nil || len(rt.scopes.Signed()) != 1 {
		t.Fatalf("%v", err)
	}
	fails := make([]int, submit.DefaultRetry.Attempts+1)
	for i := range fails {
		fails[i] = http.StatusServiceUnavailable
	}
	f.core.FailNext(submit.ScopesPath, fails...)
	if err := rt.scopes.Refresh(ctx); err == nil {
		t.Fatal("the fetch should have failed")
	}
	if st := rt.scopes.Status(); st.Count != 1 || st.LastError == "" {
		t.Fatalf("status %+v", st)
	}

	// GET /status shows the enrolment state and no secrets.
	rec := httptest.NewRecorder()
	rt.handler(platform.HealthHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", http.NoBody))
	var got enrolledStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	if got.CollectorID != enroltest.CollectorID || got.Certificate.State != "valid" || got.Scopes.Count != 1 ||
		got.Scopes.LastError == "" || got.Certificate.NotAfter.IsZero() || got.CT.Enabled {
		t.Fatalf("status %+v", got)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") || strings.Contains(rec.Body.String(), "mse1_") {
		t.Fatal("the status output carries a secret")
	}
}

func TestEnrolledCTPollUsesMTLS(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 0)
	cs, _ := fakeCTServices(t)
	f.env[envCTInterval] = "1h"
	f.env["MEISCOPE_CT_CERTSPOTTER_URL"] = cs.URL
	f.env["MEISCOPE_CT_CRTSH_FALLBACK"] = "false"
	f.core.Submit.SetDomains("owned.example")
	rt := f.runtime(t, platform.Config{})
	if err := rt.pollCT(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(f.core.Submit.Batches()); n != 1 || len(f.core.Submit.Errors()) != 0 {
		t.Fatalf("%d batches, errors %v", n, f.core.Submit.Errors())
	}
	for _, p := range []string{submit.OwnedDomainsPath, submit.ObservationsPath} {
		if s := f.core.SerialsFor(p); len(s) != 1 || s[0] == "" {
			t.Fatalf("%s not over mTLS: %v", p, s)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, ctStateFile)); err != nil {
		t.Fatalf("CT progress not kept next to the identity: %v", err)
	}
	if st := rt.status().CT; !st.Enabled || st.LastPoll.IsZero() || st.LastError != "" {
		t.Fatalf("CT status %+v", st)
	}
}

// waitSleepers waits until n loops of the enrolled runtime are asleep.
func waitSleepers(t *testing.T, clk *clock.Manual, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := clk.WaitSleepers(ctx, n); err != nil {
		t.Fatalf("waiting for %d sleepers (have %d): %v", n, clk.Sleepers(), err)
	}
}

func TestEnrolledRunRenewsAndUsesTheNewCertificate(t *testing.T) {
	clk := clock.NewManual(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 0)
	f.core.SetScopes(corePayload(t, "scope-a", 1, clk.Now()))
	rt := f.runtime(t, platform.Config{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, ln, quietLog(), time.Hour, nil, rt) }()

	waitSleepers(t, clk, 2) // the renewer waits for RenewAt, the scopes for the next refresh
	first := f.core.SerialsFor(submit.ScopesPath)
	if len(first) != 1 || first[0] == "" || f.core.Requests(enrol.CertificatePath) != 0 {
		t.Fatalf("scopes %v, renewals %d", first, f.core.Requests(enrol.CertificatePath))
	}

	clk.Advance(rt.store.RenewAt().Sub(clk.Now()))
	waitSleepers(t, clk, 2)
	if f.core.Requests(enrol.CertificatePath) != 1 || rt.renewer.Status().LastRenewed.IsZero() {
		t.Fatalf("not renewed at RenewAt: %d requests, %+v", f.core.Requests(enrol.CertificatePath), rt.renewer.Status())
	}
	clk.Advance(rt.refresh)
	waitSleepers(t, clk, 2)
	serials := f.core.SerialsFor(submit.ScopesPath)
	if last := serials[len(serials)-1]; last == first[0] || last == "" {
		t.Fatalf("the scope fetch after renewal presented the old certificate: %v", serials)
	}

	// GET /status over the real listener.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/status", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var st enrolledStatus
	decErr := json.NewDecoder(resp.Body).Decode(&st)
	_ = resp.Body.Close()
	if decErr != nil || st.Scopes.Count != 1 || st.Certificate.Renewal.LastRenewed.IsZero() || st.Certificate.State != "valid" {
		t.Fatalf("status %+v, %v", st, decErr)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestEnrolledExpiryStopsCallingTheCore(t *testing.T) {
	clk := clock.NewManual(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, 3*time.Hour)
	f.core.SetScopes(corePayload(t, "scope-a", 1, clk.Now()))
	f.core.Fail(enrol.CertificatePath, http.StatusServiceUnavailable)
	rt := f.runtime(t, platform.Config{})
	done := make(chan struct{})
	go func() { defer close(done); rt.run(context.Background()) }()

	waitSleepers(t, clk, 2)
	clk.Advance(rt.store.RenewAt().Sub(clk.Now()))
	waitSleepers(t, clk, 2) // the renewal failed and backs off
	if n := f.core.Requests(enrol.CertificatePath); n != 1 || rt.status().Certificate.State != "renewal_failing" {
		t.Fatalf("%d renewal requests, status %+v", n, rt.status().Certificate)
	}
	clk.Advance(rt.store.NotAfter().Sub(clk.Now()))
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runtime kept running after the certificate expired")
	}
	if st := rt.status(); st.Certificate.State != "expired" || st.Scopes.Count != 0 || st.Scopes.Stopped == "" {
		t.Fatalf("status %+v", st)
	}
	if len(rt.scopes.Signed()) != 0 {
		t.Fatal("scopes still offered after expiry")
	}
	// Every loop that calls the core has returned (run is done) and none is
	// waiting to call it again. (The fake core may still be recording a
	// request the collector abandoned at the expiry, so its counters are not
	// compared here.)
	clk.Advance(time.Hour)
	if n := clk.Sleepers(); n != 0 {
		t.Fatalf("%d loops still waiting to call the core after expiry", n)
	}
}

func TestEnrolledExpiredAtStartCallsNothing(t *testing.T) {
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	f := newEnrolledFixture(t, clk, time.Hour)
	f.env[envCTInterval] = "1h"
	rt := f.runtime(t, platform.Config{})
	clk.Advance(2 * time.Hour)
	before := f.core.TotalRequests()
	rt.run(context.Background()) // returns at once
	if f.core.TotalRequests() != before || rt.status().Certificate.State != "expired" {
		t.Fatalf("calls %d -> %d, status %+v", before, f.core.TotalRequests(), rt.status().Certificate)
	}
}
