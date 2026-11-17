package enrol_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	cred, err := cl.Enrol(context.Background(), "mse1_first", enroltest.Name, enroltest.Platform, csr)
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
	if _, err := cl.Enrol(context.Background(), "mse1_first", enroltest.Name, enroltest.Platform, csr2); !errors.Is(err, enrol.ErrTokenRefused) {
		t.Fatalf("reused token: err %v, want ErrTokenRefused", err)
	}
}

func TestEnrolRefusals(t *testing.T) {
	core := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, core.Client(), "")
	csr := newCSR(t)

	_, err := cl.Enrol(context.Background(), enroltest.TokenUsed, enroltest.Name, enroltest.Platform, csr)
	if !errors.Is(err, enrol.ErrTokenRefused) {
		t.Fatalf("401: %v", err)
	}
	_, err = cl.Enrol(context.Background(), enroltest.TokenDup, enroltest.Name, enroltest.Platform, csr)
	if !errors.Is(err, enrol.ErrNameTaken) {
		t.Fatalf("409: %v", err)
	}
	_, err = cl.Enrol(context.Background(), enroltest.TokenBusy, enroltest.Name, enroltest.Platform, csr)
	var e *enrol.Error
	if !errors.As(err, &e) || !e.Retryable() || e.Status != 503 {
		t.Fatalf("503: %v", err)
	}
	_, err = cl.Enrol(context.Background(), "mse1_x", enroltest.Name, enroltest.Platform, "not a csr")
	if !errors.As(err, &e) || e.Status != 400 || e.Retryable() {
		t.Fatalf("400: %v", err)
	}
	// The token never appears in an error.
	for _, tok := range []string{enroltest.TokenUsed, enroltest.TokenDup, enroltest.TokenBusy, "mse1_x"} {
		_, err := cl.Enrol(context.Background(), tok, enroltest.Name, enroltest.Platform, csr)
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
	if _, err := cl.Enrol(context.Background(), "mse1_y", enroltest.Name, enroltest.Platform, csr); err == nil {
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

func TestEnrolSendsNameAndPlatform(t *testing.T) {
	core := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, core.Client(), "")
	if _, err := cl.Enrol(context.Background(), "mse1_body", enroltest.Name, enroltest.Platform, newCSR(t)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Name     string
		Platform enrol.Platform
	}
	bodies := core.Bodies[enrol.EnrolPath]
	if len(bodies) != 1 {
		t.Fatalf("bodies = %d", len(bodies))
	}
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != enroltest.Name || got.Platform != enroltest.Platform {
		t.Fatalf("sent %+v", got)
	}
}

func TestEnrolRefusedWhenDeviceDiffers(t *testing.T) {
	core := enroltest.NewCore(t)
	cl, _ := enrol.New(core.URL, core.Client(), "")
	csr := newCSR(t)
	for name, mut := range map[string]func(*enrol.Platform) string{
		"name": func(*enrol.Platform) string { return "other-name" },
		"arch": func(p *enrol.Platform) string { p.Arch = "arm64"; return enroltest.Name },
		"pkg":  func(p *enrol.Platform) string { p.Package = "rpm"; return enroltest.Name },
	} {
		p := enroltest.Platform
		n := mut(&p)
		_, err := cl.Enrol(context.Background(), "mse1_403_"+name, n, p, csr)
		if !errors.Is(err, enrol.ErrEnrolmentRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Positive control: the matching device enrols with the same token.
	if _, err := cl.Enrol(context.Background(), "mse1_403_name", enroltest.Name, enroltest.Platform, csr); err != nil {
		t.Fatalf("matching device refused: %v", err)
	}
}

// AC-G3-14: a 307/308 is not followed; the second host never sees a request.
func TestEnrolDoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		var second atomic.Int32
		other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			second.Add(1)
			w.WriteHeader(http.StatusCreated)
		}))
		first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, other.URL+"/collector/v1/enrol", code)
		}))
		cl, _ := enrol.New(first.URL, first.Client(), "")
		_, err := cl.Enrol(context.Background(), "mse1_redirect", enroltest.Name, enroltest.Platform, newCSR(t))
		if !errors.Is(err, enrol.ErrRedirected) {
			t.Errorf("%d: %v", code, err)
		}
		if n := second.Load(); n != 0 {
			t.Errorf("%d: second host got %d requests", code, n)
		}
		first.Close()
		other.Close()
	}
}
