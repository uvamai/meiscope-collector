package scopesync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/scope"
)

var t0 = time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)

type fixture struct {
	priv  ed25519.PrivateKey
	keys  []identity.ScopeSigningKey
	clk   *clock.Fake
	list  []scope.Signed
	err   error
	calls int
	set   *Set
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		priv: priv, clk: clock.NewFake(t0),
		keys: []identity.ScopeSigningKey{{KeyID: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)}},
	}
	tr, err := scope.LoadTracker(filepath.Join(t.TempDir(), "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(context.Context) ([]scope.Signed, error) {
		f.calls++
		return f.list, f.err
	}
	f.set = New(fetch, func() (scope.Keyring, error) { return KeyringFrom(f.keys) }, tr, f.clk, nil)
	return f
}

func payload(t *testing.T, id string, version int64, notAfter time.Time) []byte {
	t.Helper()
	sc := scope.Scope{
		ID: id, TenantID: "tenant-1", Version: version,
		Targets:       []scope.Target{{Host: "192.0.2.10", Port: 443, Protocol: scope.ProtocolTLS}},
		Policy:        scope.ScanPolicy{RatePer24: 1, Burst: 1, DryRun: true},
		Authorisation: scope.Authorisation{By: "owner@example.test", At: t0.Add(-time.Hour), Document: "TEST-1"},
		NotBefore:     t0.Add(-time.Minute), NotAfter: notAfter,
	}
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) sign(p []byte) scope.Signed {
	return scope.Signed{Payload: p, Signature: ed25519.Sign(f.priv, p), KeyID: "k1"}
}

func ids(s *Set) []string {
	var out []string
	for _, sc := range s.Scopes() {
		out = append(out, sc.ID)
	}
	return out
}

func TestRefreshVerifiesAndTracksVersions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.list = []scope.Signed{f.sign(payload(t, "a", 1, t0.Add(time.Hour))), f.sign(payload(t, "b", 1, t0.Add(time.Hour)))}
	if err := f.set.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ids(f.set); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("held %v", got)
	}
	if n := len(f.set.Signed()); n != 2 {
		t.Fatalf("signed %d", n)
	}

	// The core lists a newer version of a and no longer lists b.
	f.list = []scope.Signed{f.sign(payload(t, "a", 2, t0.Add(time.Hour)))}
	if err := f.set.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if sc := f.set.Scopes(); len(sc) != 1 || sc[0].ID != "a" || sc[0].Version != 2 {
		t.Fatalf("held %+v", sc)
	}

	// A version rollback is refused, and a is no longer held.
	f.list = []scope.Signed{f.sign(payload(t, "a", 1, t0.Add(time.Hour)))}
	if err := f.set.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.set.Status(); st.Count != 0 || st.Refused != 1 {
		t.Fatalf("status %+v", st)
	}
	// Version 2 is still accepted again afterwards.
	f.list = []scope.Signed{f.sign(payload(t, "a", 2, t0.Add(time.Hour)))}
	if err := f.set.Refresh(ctx); err != nil || len(f.set.Scopes()) != 1 {
		t.Fatalf("%v %v", ids(f.set), err)
	}
}

func TestRefreshRefusesTamperedAndUnknownKeys(t *testing.T) {
	f := newFixture(t)
	tampered := f.sign(payload(t, "a", 1, t0.Add(time.Hour)))
	tampered.Payload = []byte(string(tampered.Payload[:len(tampered.Payload)-1]) + ` ,"x":1}`)
	unknown := f.sign(payload(t, "b", 1, t0.Add(time.Hour)))
	unknown.KeyID = "k9"
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	foreign := scope.Signed{Payload: payload(t, "c", 1, t0.Add(time.Hour)), KeyID: "k1"}
	foreign.Signature = ed25519.Sign(other, foreign.Payload)
	good := f.sign(payload(t, "d", 1, t0.Add(time.Hour)))
	dup := f.sign(payload(t, "d", 2, t0.Add(time.Hour)))
	f.list = []scope.Signed{tampered, unknown, foreign, good, dup}
	if err := f.set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := f.set.Status(); st.Count != 1 || st.IDs[0] != "d" || st.Refused != 4 {
		t.Fatalf("status %+v", st)
	}
	if sc := f.set.Scopes(); sc[0].Version != 1 {
		t.Fatalf("the duplicate replaced the first entry: %+v", sc[0])
	}
}

func TestFailedFetchKeepsLastGoodSetAndExpiryDrops(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.list = []scope.Signed{f.sign(payload(t, "short", 1, t0.Add(10*time.Minute))), f.sign(payload(t, "long", 1, t0.Add(time.Hour)))}
	if err := f.set.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	f.err = errors.New("HTTP 503")
	if err := f.set.Refresh(ctx); err == nil {
		t.Fatal("a failed fetch must return its error")
	}
	st := f.set.Status()
	if st.Count != 2 || st.LastError == "" || !st.LastFetch.Equal(t0) {
		t.Fatalf("status %+v", st)
	}
	// Back-off after failures, capped at the interval.
	if w := f.set.Wait(5 * time.Minute); w != 30*time.Second {
		t.Fatalf("wait %v", w)
	}
	for range 5 {
		_ = f.set.Refresh(ctx)
	}
	if w := f.set.Wait(5 * time.Minute); w != 5*time.Minute {
		t.Fatalf("wait %v", w)
	}
	// An expired scope drops out of the kept set.
	f.clk.Advance(15 * time.Minute)
	if got := ids(f.set); len(got) != 1 || got[0] != "long" {
		t.Fatalf("held %v", got)
	}
	// A good fetch clears the error and the back-off.
	f.err = nil
	f.clk.Advance(time.Minute)
	if err := f.set.Refresh(ctx); err != nil || f.set.Status().LastError != "" || f.set.Wait(time.Minute) != time.Minute {
		t.Fatalf("%v %+v", err, f.set.Status())
	}
	// "short" is now expired at verification and refused.
	if got := ids(f.set); len(got) != 1 || got[0] != "long" {
		t.Fatalf("held %v", got)
	}
}

func TestStopEmptiesTheSetAndEndsRun(t *testing.T) {
	f := newFixture(t)
	f.list = []scope.Signed{f.sign(payload(t, "a", 1, t0.Add(time.Hour)))}
	if err := f.set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.set.Stop("certificate expired")
	if len(f.set.Signed()) != 0 || f.set.Status().Stopped == "" {
		t.Fatal("a stopped set must be empty")
	}
	calls := f.calls
	f.set.Run(context.Background(), time.Minute) // returns at once
	if err := f.set.Refresh(context.Background()); err == nil || f.calls != calls {
		t.Fatal("a stopped set must not fetch")
	}
}

func TestKeyringFromRefusesBadKeys(t *testing.T) {
	if _, err := KeyringFrom(nil); err == nil {
		t.Fatal("no keys must be refused")
	}
	if _, err := KeyringFrom([]identity.ScopeSigningKey{{KeyID: "k", PublicKey: "!!"}}); err == nil {
		t.Fatal("bad base64 must be refused")
	}
}
