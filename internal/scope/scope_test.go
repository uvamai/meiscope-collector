package scope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) // a Monday

func validScope() Scope {
	return Scope{
		ID: "scope-1", TenantID: "tenant-1",
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
