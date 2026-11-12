package receiver_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/receiver"
)

// TestUnauthenticatedRequestsDoNotUseTheRateLimit: a flood without the token
// gets 401 and leaves the bucket for the real pipeline.
func TestUnauthenticatedRequestsDoNotUseTheRateLimit(t *testing.T) {
	r, _, _ := newReceiver(t, func(c *receiver.Config) { c.RatePerSecond, c.Burst = 1, 2 })
	h := r.Handler()
	for i := 0; i < 20; i++ {
		if got := post(t, h, "wrong", event("/a.pem")); got != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request %d: %d, want 401", i, got)
		}
		if got := post(t, h, "", event("/a.pem")); got != http.StatusUnauthorized {
			t.Fatalf("anonymous request %d: %d, want 401", i, got)
		}
	}
	if a, b, c := post(t, h, token, event("/a.pem")), post(t, h, token, event("/b.pem")), post(t, h, token, event("/c.pem")); a != 204 || b != 204 || c != 429 {
		t.Fatalf("authenticated after the flood: %d %d %d, want 204 204 429", a, b, c)
	}
}

// TestSpoolCap: pushes that would take the spool past MaxSpoolBytes are
// refused with 507 and a clear message; nothing partial is written, and
// pushes are accepted again once spool files are removed.
func TestSpoolCap(t *testing.T) {
	one := int64(len(event("/a.pem")) + 1) // compact JSON line
	r, dir, _ := newReceiver(t, func(c *receiver.Config) { c.Burst, c.MaxSpoolBytes = 100, 3*one })
	h := r.Handler()
	for i := 0; i < 3; i++ {
		if got := post(t, h, token, event("/a.pem")); got != http.StatusNoContent {
			t.Fatalf("push %d: %d", i, got)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(event("/a.pem")))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInsufficientStorage || !strings.Contains(rec.Body.String(), "spool is full") || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the cap: %d %q", rec.Code, rec.Body.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "push-*.jsonl"))
	var total int64
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		total += st.Size()
	}
	if total != 3*one {
		t.Fatalf("spool holds %d bytes, want %d", total, 3*one)
	}
	// Other files in the directory do not count.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(strings.Repeat("x", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	if got := post(t, h, token, event("/a.pem")); got != http.StatusNoContent {
		t.Fatalf("after draining: %d", got)
	}
}

func TestSpoolCapConfig(t *testing.T) {
	base := map[string]string{"MEISCOPE_RECEIVER_ENABLED": "true", "MEISCOPE_RECEIVER_ADDR": "127.0.0.1:9100", "MEISCOPE_RECEIVER_DIR": "/var/spool/x", "MEISCOPE_RECEIVER_TOKEN_REF": "push_token"}
	with := func(v string) func(string) string {
		return func(k string) string {
			if k == "MEISCOPE_RECEIVER_MAX_SPOOL_BYTES" {
				return v
			}
			return base[k]
		}
	}
	for _, bad := range []string{"10", "-1", "lots", "1.5e9"} {
		if _, err := receiver.LoadConfig(with(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c, err := receiver.LoadConfig(with("2147483648"))
	if err != nil || c.MaxSpoolBytes != 2147483648 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := receiver.LoadConfig(with("")); err != nil || c.MaxSpoolBytes != 0 {
		t.Fatalf("default: %+v %v", c, err)
	}
}
