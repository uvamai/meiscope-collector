package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

type probeFixture struct {
	dir, scopeFile, keysFile, stateFile string
	priv                                ed25519.PrivateKey
	port                                int
	conns                               *atomic.Int32
}

func newProbeFixture(t *testing.T) *probeFixture {
	t.Helper()
	now := time.Now()
	root := testpki.NewRoot(t, "Schedule Test Root", now)
	leaf, key := root.Issue(t, testpki.LeafTemplate("www.example.test", now.Add(-time.Hour), 24*time.Hour, "www.example.test"))
	cfg := &tls.Config{Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() { defer c.Close(); _ = tls.Server(c, cfg).Handshake() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := &probeFixture{
		dir: dir, scopeFile: filepath.Join(dir, "scopes.json"), keysFile: filepath.Join(dir, "keys.json"),
		stateFile: filepath.Join(dir, "state.json"), priv: priv, port: ln.Addr().(*net.TCPAddr).Port, conns: &conns,
	}
	keys, _ := json.Marshal([]pinnedKey{{KeyID: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)}})
	if err := os.WriteFile(f.keysFile, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *probeFixture) writeScope(t *testing.T, version int64, mutate func(*scope.Scope)) {
	t.Helper()
	now := time.Now()
	sc := scope.Scope{
		ID: "scope-1", TenantID: "tenant-1", Version: version,
		Targets:       []scope.Target{{Host: "127.0.0.1", Port: f.port, Protocol: scope.ProtocolTLS}},
		NamesByIP:     map[string][]string{"127.0.0.1": {"www.example.test"}},
		Policy:        scope.ScanPolicy{RatePer24: 5, Burst: 5, CanaryPercent: 100},
		Authorisation: scope.Authorisation{By: "owner@example.test", At: now.Add(-time.Hour), Document: "TEST-1"},
		NotBefore:     now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		RescanIntervalSeconds: 60,
	}
	if mutate != nil {
		mutate(&sc)
	}
	payload, _ := json.Marshal(sc)
	b, _ := json.Marshal(map[string]any{"scopes": []scope.Signed{{Payload: payload, Signature: ed25519.Sign(f.priv, payload), KeyID: "k1"}}})
	if err := os.WriteFile(f.scopeFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *probeFixture) env(extra map[string]string) func(string) string {
	m := map[string]string{envScopeFile: f.scopeFile, envScopeKeys: f.keysFile, envScopeState: f.stateFile}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestProbeScheduleSubmitsToTheCore(t *testing.T) {
	f := newProbeFixture(t)
	f.writeScope(t, 1, nil)
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	sub, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	s, err := newProbeSchedule(f.env(nil), sub, io.Discard, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.tick(ctx)
	s.wg.Wait()
	if len(core.Errors()) != 0 || len(core.Rejected()) != 0 || len(core.Batches()) != 1 {
		t.Fatalf("core: errors %v, rejected %v, batches %d", core.Errors(), core.Rejected(), len(core.Batches()))
	}
	if !strings.Contains(string(core.Batches()[0]), `"outcome":"cert_seen"`) || !strings.Contains(string(core.Batches()[0]), `"sni":"www.example.test"`) {
		t.Fatalf("batch %s", core.Batches()[0])
	}
	// Not due again until the rescan interval has passed.
	s.tick(ctx)
	s.wg.Wait()
	if f.conns.Load() != 1 || len(core.Batches()) != 1 {
		t.Fatalf("rescanned early: %d connections, %d batches", f.conns.Load(), len(core.Batches()))
	}
	s.mu.Lock()
	next := s.next["scope-1"]
	s.mu.Unlock()
	if d := time.Until(next); d < 50*time.Second || d > 61*time.Second {
		t.Fatalf("next run in %v, want the 60 s rescan interval", d)
	}
}

func TestProbeScheduleRefusesBadScopes(t *testing.T) {
	f := newProbeFixture(t)
	var out bytes.Buffer
	run := func() {
		t.Helper()
		s, err := newProbeSchedule(f.env(nil), nil, &out, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		s.tick(context.Background())
		s.wg.Wait()
	}

	f.writeScope(t, 2, nil)
	run()
	if f.conns.Load() != 1 {
		t.Fatalf("version 2: %d connections", f.conns.Load())
	}
	// An older, still validly signed version is a replay: refused, even by a
	// new process (the tracker state is on disk).
	f.writeScope(t, 1, nil)
	run()
	// A scope with ranges, and a tampered payload, are refused.
	f.writeScope(t, 3, func(sc *scope.Scope) { sc.ReservedCIDRs = json.RawMessage(`["127.0.0.0/8"]`) })
	run()
	b, _ := os.ReadFile(f.scopeFile)
	if err := os.WriteFile(f.scopeFile, bytes.Replace(b, []byte("TEST-1"), []byte("TEST-2"), 1), 0o600); err != nil { // #nosec G703 -- a test temp file
		t.Fatal(err)
	}
	run()
	if f.conns.Load() != 1 {
		t.Fatalf("a refused scope was probed: %d connections", f.conns.Load())
	}
	if c := strings.Count(out.String(), `"observations"`); c != 1 {
		t.Fatalf("%d batches written, want 1:\n%s", c, out.String())
	}
}

func TestProbeScheduleConfig(t *testing.T) {
	f := newProbeFixture(t)
	if s, err := newProbeSchedule(func(string) string { return "" }, nil, io.Discard, quietLog()); s != nil || err != nil {
		t.Fatalf("no scope file: %v %v", s, err)
	}
	if _, err := newProbeSchedule(f.env(map[string]string{envScopeKeys: ""}), nil, io.Discard, quietLog()); err == nil {
		t.Fatal("scope file without pinned keys accepted")
	}
	bad := filepath.Join(f.dir, "bad-keys.json")
	for _, content := range []string{`not json`, `[]`, `[{"key_id":"k","public_key":"!!"}]`, `[{"key_id":"k","public_key":"AAAA"}]`} {
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newProbeSchedule(f.env(map[string]string{envScopeKeys: bad}), nil, io.Discard, quietLog()); err == nil {
			t.Errorf("keys %q accepted", content)
		}
	}
	// A single signed scope (not a list) is read too.
	f.writeScope(t, 1, nil)
	b, _ := os.ReadFile(f.scopeFile)
	var list struct{ Scopes []scope.Signed }
	_ = json.Unmarshal(b, &list)
	one, _ := json.Marshal(list.Scopes[0])
	if err := os.WriteFile(f.scopeFile, one, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readScopes(f.scopeFile)
	if err != nil || len(got) != 1 {
		t.Fatalf("single scope: %v %d", err, len(got))
	}
}

func TestPauseAndResumeEndpoints(t *testing.T) {
	f := newProbeFixture(t)
	f.writeScope(t, 1, nil)
	s, err := newProbeSchedule(f.env(nil), nil, io.Discard, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlHandler(http.NotFoundHandler(), s.run, quietLog()))
	defer srv.Close()
	post := func(path string) {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	post("/pause")
	s.tick(context.Background())
	s.wg.Wait()
	if !s.run.Paused() || f.conns.Load() != 0 {
		t.Fatalf("paused: %v, %d connections", s.run.Paused(), f.conns.Load())
	}
	post("/resume")
	s.tick(context.Background())
	s.wg.Wait()
	if s.run.Paused() || f.conns.Load() != 1 {
		t.Fatalf("resumed: %v, %d connections", s.run.Paused(), f.conns.Load())
	}
}
