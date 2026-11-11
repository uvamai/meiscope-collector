package enrol_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
)

func newCSR(t *testing.T) string {
	t.Helper()
	key, err := identity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestNewRequiresHTTPS(t *testing.T) {
	core := enroltest.NewCore(t)
	for _, u := range []string{"http://core.example", "core.example", "https://", ""} {
		if _, err := enrol.New(u, core.Client(), ""); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if _, err := enrol.New(core.URL, nil, ""); err == nil {
		t.Error("accepted a nil HTTP client")
	}
}

func TestEnrolIssuesForTheCSRKey(t *testing.T) {
	core := enroltest.NewCore(t)
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key)
	cl, err := enrol.New(core.URL, core.Client(), "meiscope-collector/test")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := cl.Enrol(context.Background(), "mse1_first", csr)
	if err != nil {
		t.Fatal(err)
	}
	if cred.CollectorID != enroltest.CollectorID || len(cred.ScopeSigningKeys) != 1 || cred.NotAfter.IsZero() {
		t.Fatalf("credentials %+v", cred)
	}
	// The answer is usable as-is: it matches the key that made the CSR.
	if _, err := identity.Save(t.TempDir(), core.URL, key, cred); err != nil {
		t.Fatal(err)
	}
	// Only the token and the CSR were sent: never a private key.
	for _, b := range core.BodiesFor("/collector/v1/enrol") {
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatal("a private key was sent to the core")
		}
	}
	// A token is single use.
	csr2 := newCSR(t)
	if _, err := cl.Enrol(context.Background(), "mse1_first", csr2); !errors.Is(err, enrol.ErrTokenRefused) {
		t.Fatalf("reused token: err %v, want ErrTokenRefused", err)
	}
}

func TestEnrolRefusals(t *testing.T) {
	core := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, core.Client(), "")
	csr := newCSR(t)

	_, err := cl.Enrol(context.Background(), enroltest.TokenUsed, csr)
	if !errors.Is(err, enrol.ErrTokenRefused) {
		t.Fatalf("401: %v", err)
	}
	_, err = cl.Enrol(context.Background(), enroltest.TokenDup, csr)
	if !errors.Is(err, enrol.ErrNameTaken) {
		t.Fatalf("409: %v", err)
	}
	_, err = cl.Enrol(context.Background(), enroltest.TokenBusy, csr)
	var e *enrol.Error
	if !errors.As(err, &e) || !e.Retryable() || e.Status != 503 {
		t.Fatalf("503: %v", err)
	}
	_, err = cl.Enrol(context.Background(), "mse1_x", "not a csr")
	if !errors.As(err, &e) || e.Status != 400 || e.Retryable() {
		t.Fatalf("400: %v", err)
	}
	// The token never appears in an error.
	for _, tok := range []string{enroltest.TokenUsed, enroltest.TokenDup, enroltest.TokenBusy, "mse1_x"} {
		_, err := cl.Enrol(context.Background(), tok, csr)
		if err != nil && strings.Contains(err.Error(), tok) {
			t.Fatalf("error %q contains the token", err)
		}
	}
}

func TestEnrolRefusesUntrustedCore(t *testing.T) {
	core := enroltest.NewCore(t)
	other := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, other.Client(), "") // trusts the other core's CA only
	csr := newCSR(t)
	if _, err := cl.Enrol(context.Background(), "mse1_y", csr); err == nil {
		t.Fatal("enrolled with a core whose certificate is not trusted")
	}
	if core.Requests("/collector/v1/enrol") != 0 {
		t.Fatal("the token reached an untrusted server")
	}
}

func TestRenewNeedsTheCollectorCertificate(t *testing.T) {
	core := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, core.Client(), "") // no client certificate
	csr := newCSR(t)
	_, err := cl.Renew(context.Background(), csr)
	var e *enrol.Error
	if !errors.As(err, &e) || e.Status != 401 {
		t.Fatalf("renew without mTLS: %v, want 401", err)
	}
}
