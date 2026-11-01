package scope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) // a Monday

func validScope() Scope {
	return Scope{
		ID: "scope-1", TenantID: "tenant-1", Version: 1,
		Hosts: []string{"mail.example.test"}, CIDRs: []string{"192.0.2.0/28"}, Ports: []int{443, 25},
		Policy:        ScanPolicy{RatePer24: 2, Burst: 2},
		Authorisation: Authorisation{By: "ciso@example.test", At: now.Add(-24 * time.Hour), Document: "CHG-1234"},
		NotBefore:     now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
}

func sign(t *testing.T, key ed25519.PrivateKey, v any) Signed {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Payload: b, Signature: ed25519.Sign(key, b)}
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyAcceptsAndDefaults(t *testing.T) {
	pub, priv := keys(t)
	sc, err := Verify(sign(t, priv, validScope()), pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Policy.ConnectTimeoutSeconds != DefaultConnectTimeout || sc.Policy.CanaryPercent != DefaultCanaryPercent {
		t.Fatalf("defaults not applied: %+v", sc.Policy)
	}
}

func TestVerifyRefuses(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	good := sign(t, priv, validScope())

	tampered := good
	tampered.Payload = append([]byte(nil), good.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1

	mutate := func(f func(*Scope)) Signed {
		s := validScope()
		f(&s)
		return sign(t, priv, s)
	}
	unknownField := func() Signed {
		var m map[string]any
		_ = json.Unmarshal(good.Payload, &m)
		m["scan_everything"] = true
		return sign(t, priv, m)
	}()

	for name, tc := range map[string]struct {
		s   Signed
		key ed25519.PublicKey
		err error
	}{
		"no signature":           {Signed{Payload: good.Payload}, pub, ErrUnsigned},
		"other key":              {good, otherPub, ErrBadSignature},
		"short key":              {good, pub[:10], ErrBadSignature},
		"tampered payload":       {tampered, pub, ErrBadSignature},
		"expired":                {mutate(func(s *Scope) { s.NotAfter = now }), pub, ErrExpired},
		"not yet valid":          {mutate(func(s *Scope) { s.NotBefore = now.Add(time.Minute) }), pub, ErrNotYetValid},
		"no authorisation":       {mutate(func(s *Scope) { s.Authorisation.Document = " " }), pub, ErrInvalid},
		"no targets":             {mutate(func(s *Scope) { s.Hosts, s.CIDRs = nil, nil }), pub, ErrInvalid},
		"no ports":               {mutate(func(s *Scope) { s.Ports = nil }), pub, ErrInvalid},
		"bad port":               {mutate(func(s *Scope) { s.Ports = []int{70000} }), pub, ErrInvalid},
		"bad cidr":               {mutate(func(s *Scope) { s.CIDRs = []string{"10.0.0.0/33"} }), pub, ErrInvalid},
		"rate too high":          {mutate(func(s *Scope) { s.Policy.RatePer24 = MaxRatePer24 + 1 }), pub, ErrInvalid},
		"zero rate":              {mutate(func(s *Scope) { s.Policy.RatePer24 = 0 }), pub, ErrInvalid},
		"burst too high":         {mutate(func(s *Scope) { s.Policy.Burst = MaxBurst + 1 }), pub, ErrInvalid},
		"timeout too long":       {mutate(func(s *Scope) { s.Policy.ConnectTimeoutSeconds = 99 }), pub, ErrInvalid},
		"canary over 100":        {mutate(func(s *Scope) { s.Policy.CanaryPercent = 101 }), pub, ErrInvalid},
		"bad window":             {mutate(func(s *Scope) { s.Policy.Windows = []Window{{Start: "25:00", End: "01:00"}} }), pub, ErrInvalid},
		"missing ids":            {mutate(func(s *Scope) { s.ID = "" }), pub, ErrInvalid},
		"unknown field refused":  {unknownField, pub, ErrInvalid},
		"payload not json":       {Signed{Payload: []byte("not json"), Signature: ed25519.Sign(priv, []byte("not json"))}, pub, ErrInvalid},
		"bad window end refused": {mutate(func(s *Scope) { s.Policy.Windows = []Window{{Start: "01:00", End: "x"}} }), pub, ErrInvalid},
		"no version":             {mutate(func(s *Scope) { s.Version = 0 }), pub, ErrInvalid},
		"rescan too often":       {mutate(func(s *Scope) { s.RescanIntervalSeconds = 10 }), pub, ErrInvalid},
		"rescan too rare":        {mutate(func(s *Scope) { s.RescanIntervalSeconds = MaxRescanInterval + 1 }), pub, ErrInvalid},
		"names ip outside cidrs": {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"198.51.100.1": {"a.example.test"}} }), pub, ErrInvalid},
		"names key not an ip":    {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"mail.example.test": {"a.example.test"}} }), pub, ErrInvalid},
		"names empty":            {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"192.0.2.1": {}} }), pub, ErrInvalid},
		"names wildcard":         {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"192.0.2.1": {"*.example.test"}} }), pub, ErrInvalid},
		"names trailing dot":     {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"192.0.2.1": {"a.example.test."}} }), pub, ErrInvalid},
		"names long label":       {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"192.0.2.1": {strings.Repeat("a", 64) + ".test"}} }), pub, ErrInvalid},
		"names too many":         {mutate(func(s *Scope) { s.NamesByIP = map[string][]string{"192.0.2.1": manyNames(MaxNamesPerIP + 1)} }), pub, ErrInvalid},
	} {
		if _, err := Verify(tc.s, tc.key, now); !errors.Is(err, tc.err) {
			t.Errorf("%s: got %v, want %v", name, err, tc.err)
		}
	}
}

func TestInWindow(t *testing.T) {
	at := func(day time.Weekday, hh, mm int) time.Time {
		// 2026-10-25 is a Sunday.
		return time.Date(2026, 10, 25+int(day), hh, mm, 0, 0, time.UTC)
	}
	night := ScanPolicy{Windows: []Window{{Days: []time.Weekday{time.Saturday}, Start: "22:00", End: "04:00"}}}
	office := ScanPolicy{Windows: []Window{{Start: "09:00", End: "17:00"}}}
	for _, tc := range []struct {
		p    ScanPolicy
		t    time.Time
		want bool
	}{
		{ScanPolicy{}, at(time.Monday, 3, 0), true},
		{office, at(time.Monday, 9, 0), true},
		{office, at(time.Monday, 16, 59), true},
		{office, at(time.Monday, 17, 0), false},
		{office, at(time.Monday, 8, 59), false},
		{night, at(time.Saturday, 23, 0), true},
		{night, at(time.Sunday, 3, 59), true}, // after midnight, still Saturday's window
		{night, at(time.Sunday, 4, 0), false},
		{night, at(time.Sunday, 23, 0), false}, // Sunday evening is not in Saturday's window
		{night, at(time.Friday, 23, 0), false},
	} {
		if got := tc.p.InWindow(tc.t); got != tc.want {
			t.Errorf("%v at %s: got %v, want %v", tc.p.Windows, tc.t.Format("Mon 15:04"), got, tc.want)
		}
	}
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.test", i)
	}
	return out
}

func TestNewFieldsAccepted(t *testing.T) {
	pub, priv := keys(t)
	s := validScope()
	s.NamesByIP = map[string][]string{"192.0.2.5": {"www.example.test", "Portal.Example.Test", "_srv.example.test"}}
	sc, err := Verify(sign(t, priv, s), pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if sc.RescanIntervalSeconds != DefaultRescanInterval || len(sc.NamesByIP["192.0.2.5"]) != 3 {
		t.Fatalf("scope %+v", sc)
	}
	s.RescanIntervalSeconds = 300 // the demo profile
	if sc, err = Verify(sign(t, priv, s), pub, now); err != nil || sc.RescanIntervalSeconds != 300 {
		t.Fatalf("demo interval: %v %+v", err, sc)
	}
}

func signWith(t *testing.T, id string, key ed25519.PrivateKey, v any) Signed {
	t.Helper()
	s := sign(t, key, v)
	s.KeyID = id
	return s
}

// Rotation: the core pins the new key next to the old one, signs with the
// new one, then retires the old one; no re-enrolment at any step.
func TestKeyringRotation(t *testing.T) {
	oldPub, oldPriv := keys(t)
	newPub, newPriv := keys(t)
	_, strangerPriv := keys(t)
	ring, err := NewKeyring(map[string]ed25519.PublicKey{"k1": oldPub, "k2": newPub})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Signed{signWith(t, "k1", oldPriv, validScope()), signWith(t, "k2", newPriv, validScope())} {
		if _, err := VerifyKeyring(s, ring, now); err != nil {
			t.Fatalf("%s: %v", s.KeyID, err)
		}
	}
	for name, tc := range map[string]struct {
		s   Signed
		err error
	}{
		"no key id":             {sign(t, newPriv, validScope()), ErrUnknownKey},
		"unpinned key id":       {signWith(t, "k3", strangerPriv, validScope()), ErrUnknownKey},
		"key id of another key": {signWith(t, "k1", newPriv, validScope()), ErrBadSignature},
		"stranger under k2":     {signWith(t, "k2", strangerPriv, validScope()), ErrBadSignature},
		"unsigned":              {Signed{KeyID: "k1"}, ErrUnsigned},
	} {
		if _, err := VerifyKeyring(tc.s, ring, now); !errors.Is(err, tc.err) {
			t.Errorf("%s: got %v, want %v", name, err, tc.err)
		}
	}
	retired, err := NewKeyring(map[string]ed25519.PublicKey{"k2": newPub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKeyring(signWith(t, "k1", oldPriv, validScope()), retired, now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("retired key still accepted: %v", err)
	}
	thirdPub, _ := keys(t)
	for name, keys := range map[string]map[string]ed25519.PublicKey{
		"none":      {},
		"three":     {"a": oldPub, "b": newPub, "c": thirdPub},
		"no id":     {"": oldPub},
		"short key": {"a": oldPub[:5]},
	} {
		if _, err := NewKeyring(keys); err == nil {
			t.Errorf("%s: keyring accepted", name)
		}
	}
}

func TestTrackerRefusesReplay(t *testing.T) {
	_, priv := keys(t)
	path := filepath.Join(t.TempDir(), "scopes.json")
	tr, err := LoadTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	at := func(v int64, hosts ...string) (*Scope, []byte) {
		s := validScope()
		s.Version = v
		if hosts != nil {
			s.Hosts = hosts
		}
		signed := sign(t, priv, s)
		return &s, signed.Payload
	}
	v1, p1 := at(1)
	v2, p2 := at(2, "mail.example.test", "www.example.test")
	if err := tr.Accept(v1, p1); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v1, p1); err != nil {
		t.Fatalf("same payload again: %v", err)
	}
	if err := tr.Accept(v2, p2); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v1, p1); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older version: %v", err)
	}
	v2b, p2b := at(2, "other.example.test")
	if err := tr.Accept(v2b, p2b); !errors.Is(err, ErrReplayed) {
		t.Fatalf("same version, different bytes: %v", err)
	}
	// After a restart the state is still there.
	tr2, err := LoadTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr2.Accept(v1, p1); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay after restart: %v", err)
	}
	if err := tr2.Accept(v2, p2); err != nil {
		t.Fatalf("current version after restart: %v", err)
	}
	other := validScope()
	other.ID = "scope-2"
	if err := tr2.Accept(&other, []byte("x")); err != nil {
		t.Fatalf("other scope: %v", err)
	}

	mem, err := LoadTracker("")
	if err != nil || mem.Accept(v1, p1) != nil {
		t.Fatalf("memory tracker: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTracker(bad); err == nil {
		t.Fatal("corrupt state accepted")
	}
	if _, err := LoadTracker(t.TempDir()); err == nil {
		t.Fatal("directory accepted as state file")
	}
	ro := &Tracker{path: filepath.Join(bad, "x.json"), seen: map[string]seenVersion{}} // parent is a file
	if err := ro.Accept(v1, p1); err == nil {
		t.Fatal("unwritable state accepted")
	}
}
