package enrol_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

// TestCheckRenewedValidity: NotBefore <= now < NotAfter, and NotAfter later
// than the current certificate's.
func TestCheckRenewedValidity(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	current := now.Add(10 * 24 * time.Hour)
	ca := testpki.NewRoot(t, "core CA", now)
	cred := func(notBefore, notAfter time.Time) identity.Credentials {
		tmpl := testpki.LeafTemplate("collector", notBefore, notAfter.Sub(notBefore)+time.Second)
		leaf, _ := ca.Issue(t, tmpl)
		return identity.Credentials{CertificateChain: testpki.PEM(leaf, ca.Cert)}
	}
	for name, tc := range map[string]struct {
		c    identity.Credentials
		want bool
	}{
		"valid and longer":      {cred(now.Add(-time.Minute), now.Add(30*24*time.Hour)), true},
		"starts exactly now":    {cred(now, now.Add(30*24*time.Hour)), true},
		"not yet valid":         {cred(now.Add(time.Hour), now.Add(30*24*time.Hour)), false},
		"already expired":       {cred(now.Add(-48*time.Hour), now.Add(-time.Hour)), false},
		"ends exactly now":      {cred(now.Add(-48*time.Hour), now), false},
		"shorter than current":  {cred(now.Add(-time.Minute), current.Add(-time.Hour)), false},
		"same end as current":   {cred(now.Add(-time.Minute), current), false},
		"no certificate":        {identity.Credentials{CertificateChain: ""}, false},
		"not a certificate PEM": {identity.Credentials{CertificateChain: "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n"}, false},
		"garbage certificate":   {identity.Credentials{CertificateChain: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}, false},
	} {
		err := enrol.CheckRenewedValidity(tc.c, now, current)
		if tc.want && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if !tc.want && !errors.Is(err, enrol.ErrRenewedValidity) {
			t.Errorf("%s: err %v, want ErrRenewedValidity", name, err)
		}
	}
}

// TestRenewerRefusesNotYetValidCertificate: end to end, a core whose clock
// runs two hours ahead issues a certificate that is not valid yet here; it
// is refused, the current certificate stays and renewal is retried.
func TestRenewerRefusesNotYetValidCertificate(t *testing.T) {
	core := enroltest.NewCore(t)
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	core.SetNow(clk.Now)
	store, r := enrolled(t, core, clk)
	clk.Advance(store.RenewAt().Sub(clk.Now()))
	before := store.NotAfter()
	core.SetNow(func() time.Time { return clk.Now().Add(2 * time.Hour) })

	wait, err := r.Step(context.Background())
	if err != nil || wait <= 0 {
		t.Fatalf("step: wait %v, %v", wait, err)
	}
	if core.Requests(enrol.CertificatePath) != 1 {
		t.Fatalf("renewal requests %d", core.Requests(enrol.CertificatePath))
	}
	if st := r.Status(); st.Failures != 1 || !strings.Contains(st.LastError, enrol.ErrRenewedValidity.Error()) {
		t.Fatalf("status %+v", st)
	}
	if !store.NotAfter().Equal(before) {
		t.Fatalf("the refused certificate replaced the current one: %v -> %v", before, store.NotAfter())
	}

	// With the clocks agreeing again, the retry renews.
	core.SetNow(clk.Now)
	clk.Advance(wait)
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.Failures != 0 || !store.NotAfter().After(before) {
		t.Fatalf("status %+v, not_after %v (was %v)", st, store.NotAfter(), before)
	}
}
