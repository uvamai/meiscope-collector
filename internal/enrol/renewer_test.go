package enrol_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
)

// enrolled enrols a collector with core and returns its identity and a
// renewer on clk, whose waits are not jittered.
func enrolled(t *testing.T, core *enroltest.Core, clk clock.Clock) (*identity.Store, *enrol.Renewer) {
	t.Helper()
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key)
	cl, err := enrol.New(core.URL, core.Client(), "meiscope-collector/test")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := cl.Enrol(context.Background(), "mse1_renewer", csr)
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.Save(t.TempDir(), core.URL, key, cred)
	if err != nil {
		t.Fatal(err)
	}
	mtls, err := enrol.New(core.URL, &http.Client{Timeout: 10 * time.Second, Transport: store.Transport(core.Transport())}, "meiscope-collector/test")
	if err != nil {
		t.Fatal(err)
	}
	return store, &enrol.Renewer{Store: store, Client: mtls, Clock: clk, Jitter: func(d time.Duration) time.Duration { return d }}
}

func TestRenewerRenewsAtRenewAtWithBackoff(t *testing.T) {
	core := enroltest.NewCore(t)
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	core.SetNow(clk.Now)
	store, r := enrolled(t, core, clk)
	ctx := context.Background()
	oldNotAfter := store.NotAfter()

	// Young certificate: wait until RenewAt, call nothing.
	wait, err := r.Step(ctx)
	if err != nil || !clk.Now().Add(wait).Equal(store.RenewAt()) {
		t.Fatalf("wait %v (renew at %v), %v", wait, store.RenewAt(), err)
	}
	if core.Requests(enrol.CertificatePath) != 0 {
		t.Fatal("renewed before RenewAt")
	}
	clk.Advance(wait)

	// Two failures back off 30s then 60s; the third attempt renews.
	core.FailNext(enrol.CertificatePath, http.StatusServiceUnavailable, http.StatusInternalServerError)
	for i, want := range []time.Duration{30 * time.Second, time.Minute} {
		wait, err = r.Step(ctx)
		if err != nil || wait != want {
			t.Fatalf("failure %d: wait %v, %v", i+1, wait, err)
		}
		if st := r.Status(); st.Failures != i+1 || st.LastError == "" {
			t.Fatalf("status %+v", st)
		}
		clk.Advance(wait)
	}
	wait, err = r.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !store.NotAfter().After(oldNotAfter) || !clk.Now().Add(wait).Equal(store.RenewAt()) {
		t.Fatalf("not renewed: not_after %v (was %v), wait %v", store.NotAfter(), oldNotAfter, wait)
	}
	if st := r.Status(); st.Failures != 0 || st.LastError != "" || st.LastRenewed.IsZero() {
		t.Fatalf("status %+v", st)
	}
	serials := core.SerialsFor(enrol.CertificatePath)
	if len(serials) != 3 || serials[0] == "" || serials[1] != serials[0] || serials[2] != serials[0] {
		t.Fatalf("renewal requests must present the current certificate: %v", serials)
	}

	// The next renewal is authenticated by the renewed certificate.
	clk.Advance(wait)
	if _, err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	serials = core.SerialsFor(enrol.CertificatePath)
	if len(serials) != 4 || serials[3] == serials[0] || serials[3] == "" {
		t.Fatalf("the request after renewal did not present the new certificate: %v", serials)
	}
	for _, b := range core.BodiesFor(enrol.CertificatePath) {
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatal("a private key was sent")
		}
	}
	// The renewed identity is on disk.
	if s, err := identity.Load(store.Dir()); err != nil || !s.NotAfter().Equal(store.NotAfter()) {
		t.Fatalf("stored identity: %v", err)
	}
}

func TestRenewerStopsAtExpiry(t *testing.T) {
	core := enroltest.NewCore(t)
	core.Lifetime = 3 * time.Hour
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	core.SetNow(clk.Now)
	store, r := enrolled(t, core, clk)
	core.Fail(enrol.CertificatePath, http.StatusServiceUnavailable)
	ctx := context.Background()

	var waits []time.Duration
	for i := 0; ; i++ {
		if i > 100 {
			t.Fatal("never reported the expiry")
		}
		wait, err := r.Step(ctx)
		if errors.Is(err, enrol.ErrExpired) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			waits = append(waits, wait)
		}
		clk.Advance(wait)
	}
	if !clk.Now().Equal(store.NotAfter()) {
		t.Fatalf("expiry reported at %v, certificate expired at %v", clk.Now(), store.NotAfter())
	}
	// Exponential, capped by the expiry.
	if len(waits) < 3 || waits[0] != 30*time.Second || waits[1] != time.Minute || waits[2] != 2*time.Minute {
		t.Fatalf("waits %v", waits)
	}
	attempts := core.Requests(enrol.CertificatePath)
	if !r.Status().Expired {
		t.Fatal("status must say expired")
	}
	// Run returns ErrExpired at once and calls nothing more.
	if err := r.Run(ctx); !errors.Is(err, enrol.ErrExpired) || core.Requests(enrol.CertificatePath) != attempts {
		t.Fatalf("run: %v, %d requests (was %d)", err, core.Requests(enrol.CertificatePath), attempts)
	}
}
