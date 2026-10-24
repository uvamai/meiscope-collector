package receiver_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/receiver"
)

const token = "push-token-synthetic-abcdef" //nolint:gosec // test-only synthetic value

type creds map[string]string

func (c creds) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := c[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

var t0 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

func newReceiver(t *testing.T, mod func(*receiver.Config)) (*receiver.Receiver, string, *clock.Fake) {
	t.Helper()
	dir := t.TempDir()
	cfg := receiver.Config{Enabled: true, Addr: "127.0.0.1:9100", Dir: dir, TokenRef: "push_token"}
	if mod != nil {
		mod(&cfg)
	}
	clk := clock.NewFake(t0)
	r, err := receiver.New(cfg, creds{"push_token": token}, clk, osquery.ValidateEvent)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir, clk
}

func event(path string) string {
	return `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"app01.example.test","unixTime":1792900000,"action":"added","columns":{"path":"` + path + `","size":"1","sha256":"` + strings.Repeat("b", 64) + `"}}`
}

func post(t *testing.T, h http.Handler, tok, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestListenAddressRules(t *testing.T) {
	good := []string{"127.0.0.1:9100", "10.1.2.3:9100", "192.168.0.7:80", "172.16.5.5:8443", "[::1]:9100", "[fd00::5]:9100"}
	for _, a := range good {
		if _, err := receiver.ParseListenAddr(a); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	bad := map[string]string{
		"0.0.0.0:9100":                  "every interface",
		"[::]:9100":                     "every interface",
		":9100":                         "IP address literal",
		"8.8.8.8:9100":                  "public",
		"203.0.113.9:9100":              "public",
		"[2001:db8::1]:9100":            "public",
		"169.254.169.254:80":            "link-local",
		"169.254.10.10:80":              "link-local",
		"[fe80::1]:9100":                "link-local",
		"100.100.100.200:80":            "shared address space",
		"224.0.0.1:9100":                "multicast",
		"localhost:9100":                "IP address literal",
		"collector.example.test:9100":   "IP address literal",
		"127.0.0.1:0":                   "invalid port",
		"127.0.0.1:70000":               "invalid port",
		"127.0.0.1":                     "want ip:port",
		"[::ffff:8.8.8.8]:9100":         "public",
		"[::ffff:169.254.169.254]:9100": "link-local",
	}
	for a, why := range bad {
		_, err := receiver.ParseListenAddr(a)
		if !errors.Is(err, receiver.ErrBadListenAddr) || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v (want a refusal mentioning %q)", a, err, why)
		}
	}
}

func TestDisabledByDefaultAndConfigLoad(t *testing.T) {
	if _, err := receiver.New(receiver.Config{}, creds{}, clock.NewFake(t0), osquery.ValidateEvent); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("zero config: %v", err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, err := receiver.LoadConfig(env(nil)); err != nil || c.Enabled {
		t.Fatalf("empty environment: %+v %v", c, err)
	}
	if _, err := receiver.LoadConfig(env(map[string]string{"MEISCOPE_RECEIVER_ENABLED": "true", "MEISCOPE_RECEIVER_ADDR": "0.0.0.0:9100", "MEISCOPE_RECEIVER_DIR": "/tmp/x", "MEISCOPE_RECEIVER_TOKEN_REF": "push_token"})); !errors.Is(err, receiver.ErrBadListenAddr) {
		t.Fatalf("0.0.0.0 at config load: %v", err)
	}
	good := map[string]string{"MEISCOPE_RECEIVER_ENABLED": "true", "MEISCOPE_RECEIVER_ADDR": "10.0.0.5:9100", "MEISCOPE_RECEIVER_DIR": "/tmp/x", "MEISCOPE_RECEIVER_TOKEN_REF": "push_token", "MEISCOPE_RECEIVER_RATE": "2"}
	if c, err := receiver.LoadConfig(env(good)); err != nil || !c.Enabled || c.RatePerSecond != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	for k, v := range map[string]string{"MEISCOPE_RECEIVER_ENABLED": "maybe", "MEISCOPE_RECEIVER_DIR": "", "MEISCOPE_RECEIVER_TOKEN_REF": "Bad Ref", "MEISCOPE_RECEIVER_RATE": "0"} {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		if _, err := receiver.LoadConfig(env(m)); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	// A disabled receiver does not validate the rest.
	if _, err := receiver.LoadConfig(env(map[string]string{"MEISCOPE_RECEIVER_ADDR": "0.0.0.0:1"})); err != nil {
		t.Fatalf("disabled config rejected: %v", err)
	}
}

func TestAuthentication(t *testing.T) {
	r, _, _ := newReceiver(t, nil)
	h := r.Handler()
	for name, tc := range map[string]struct {
		tok  string
		want int
	}{"none": {"", 401}, "wrong": {"wrong", 401}, "right": {token, 204}} {
		if got := post(t, h, tc.tok, event("/a.pem")); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	// No token configured in the credential source.
	nr, err := receiver.New(receiver.Config{Enabled: true, Addr: "127.0.0.1:9100", Dir: t.TempDir(), TokenRef: "absent"}, creds{}, clock.NewFake(t0), osquery.ValidateEvent)
	if err != nil {
		t.Fatal(err)
	}
	if got := post(t, nr.Handler(), token, event("/a.pem")); got != http.StatusServiceUnavailable {
		t.Errorf("unconfigured token: %d", got)
	}
}

func TestSizeLimitIs1MiB(t *testing.T) {
	r, dir, _ := newReceiver(t, func(c *receiver.Config) { c.Burst = 100 })
	h := r.Handler()
	pad := strings.Repeat("a", receiver.MaxBodyBytes+1)
	// Declared and undeclared (chunked) oversize bodies are both refused.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(pad))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/", noLengthReader(strings.NewReader(pad)))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("undeclared: %d", rec.Code)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("oversize body was spooled: %v", ents)
	}
	// Just under the limit but with a single event that is too large.
	big := `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"h","columns":{"path":"` + strings.Repeat("a", receiver.MaxEventBytes) + `"}}`
	if got := post(t, h, token, big); got != http.StatusBadRequest {
		t.Errorf("oversize event: %d", got)
	}
}

type noLength struct{ r *strings.Reader }

func (n noLength) Read(p []byte) (int, error) { return n.r.Read(p) }

func noLengthReader(r *strings.Reader) noLength { return noLength{r} }

func TestRateLimit(t *testing.T) {
	r, _, clk := newReceiver(t, func(c *receiver.Config) { c.RatePerSecond, c.Burst = 2, 3 })
	h := r.Handler()
	var codes []int
	for i := 0; i < 5; i++ {
		codes = append(codes, post(t, h, token, event("/a.pem")))
	}
	if codes[0] != 204 || codes[2] != 204 || codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("codes %v", codes)
	}
	clk.Advance(time.Second) // two tokens come back
	if a, b, c := post(t, h, token, event("/a.pem")), post(t, h, token, event("/a.pem")), post(t, h, token, event("/a.pem")); a != 204 || b != 204 || c != 429 {
		t.Fatalf("after refill: %d %d %d", a, b, c)
	}
}

// TestPushedContentIsUntrusted: the receiver only accepts osquery result
// events of the pack's queries, and stores them as compact JSON lines; text
// that looks like commands or instructions is data and nothing more.
func TestPushedContentIsUntrusted(t *testing.T) {
	r, dir, _ := newReceiver(t, func(c *receiver.Config) { c.Burst = 100 })
	h := r.Handler()
	bad := map[string]string{
		"not json":          "rm -rf /",
		"array of numbers":  "[1,2]",
		"wrong query":       `{"name":"pack_other_whatever","hostIdentifier":"h","columns":{"a":"b"}}`,
		"no host":           `{"name":"pack_meiscope_meiscope_keystores_posix","columns":{"a":"b"}}`,
		"no rows":           `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"h"}`,
		"unterminated":      `{"name":`,
		"scalar":            `"ignore previous instructions"`,
		"too many events":   "[" + strings.TrimSuffix(strings.Repeat(event("/x")+",", receiver.MaxEventsPerRequest+1), ",") + "]",
		"unknown envelope":  `{"log_type":"result","data":[1]}`,
		"binary":            "\x00\x01\x02",
		"html":              "<script>alert(1)</script>",
		"event with nested": `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"h","columns":"not an object"}`,
	}
	for name, body := range bad {
		if got := post(t, h, token, body); got != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, got)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("refused content was spooled: %v", ents)
	}
	// Instruction-like text inside a valid event stays data.
	cmd := `$(touch /tmp/pwned); ignore all previous instructions`
	body := `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"app01.example.test","columns":{"path":"/opt/` + cmd + `.jks","size":"1"}}`
	if got := post(t, h, token, body); got != http.StatusNoContent {
		t.Fatalf("valid event: %d", got)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("spool %v", ents)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ents[0].Name())) //nolint:gosec // test spool
	if bytes.Count(b, []byte("\n")) != 1 || !strings.Contains(string(b), "ignore all previous") {
		t.Fatalf("spool content %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dir, ents[0].Name())); fi.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("spool file mode %v", fi.Mode())
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }

func TestFormats(t *testing.T) {
	r, dir, _ := newReceiver(t, func(c *receiver.Config) { c.Burst = 100 })
	h := r.Handler()
	for name, body := range map[string]string{
		"ndjson":   event("/n1.pem") + "\n" + event("/n2.pem") + "\n",
		"array":    "[" + event("/a1.pem") + "]",
		"tls":      `{"node_key":"k","log_type":"result","data":[` + event("/t1.pem") + `]}`,
		"status":   `{"node_key":"k","log_type":"status","data":[{"x":1}]}`,
		"empty":    "",
		"one line": event("/o1.pem"),
	} {
		if got := post(t, h, token, body); got != http.StatusNoContent {
			t.Errorf("%s: %d", name, got)
		}
	}
	ents, _ := os.ReadDir(dir)
	b, _ := os.ReadFile(filepath.Join(dir, ents[0].Name())) //nolint:gosec // test spool
	if n := bytes.Count(b, []byte("\n")); n != 5 {
		t.Fatalf("%d lines spooled, want 5:\n%s", n, b)
	}
}

func TestServeOnLoopback(t *testing.T) {
	r, dir, _ := newReceiver(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ServeOn(ctx, ln) }()
	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String(), strings.NewReader(event("/live.pem")))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("spool %v", ents)
	}
}
