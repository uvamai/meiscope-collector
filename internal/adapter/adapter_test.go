package adapter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

var t0 = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

func TestParseConfig(t *testing.T) {
	good := `{"name":"fleet-prod","adapter":"osquery","settings":{"mode":"fleet","url":"https://fleet.example.test"},"credentials":{"api_token":"fleet_token"}}`
	c, err := adapter.ParseConfig([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Setting("mode", "") != "fleet" || c.Setting("missing", "def") != "def" {
		t.Fatalf("settings %+v", c.Settings)
	}
	bad := map[string]string{
		"token in settings":    strings.Replace(good, `"mode":"fleet"`, `"mode":"fleet","api_token":"abc"`, 1),
		"password in settings": strings.Replace(good, `"mode":"fleet"`, `"mode":"fleet","proxy_password":"x"`, 1),
		"bearer value":         strings.Replace(good, `"mode":"fleet"`, `"mode":"Bearer abcdefghijklmnop"`, 1),
		"key material":         strings.Replace(good, `"mode":"fleet"`, `"mode":"-----BEGIN PRIVATE KEY-----"`, 1),
		"bad reference":        strings.Replace(good, `"fleet_token"`, `"Fleet Token!"`, 1),
		"bad name":             strings.Replace(good, `"fleet-prod"`, `"Fleet Prod"`, 1),
		"no adapter":           strings.Replace(good, `"adapter":"osquery",`, ``, 1),
		"unknown field":        strings.Replace(good, `"name"`, `"token":"x","name"`, 1),
		"not json":             `{`,
	}
	for name, doc := range bad {
		_, err := adapter.ParseConfig([]byte(doc))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, leak := range []string{"abcdefghijklmnop", "BEGIN PRIVATE"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error repeats the value: %v", name, err)
			}
		}
	}
}

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

func TestCredential(t *testing.T) {
	c := adapter.Config{Name: "x", Adapter: "a", Credentials: map[string]string{"api_token": "tok"}}
	s, err := c.Credential(context.Background(), mapSource{"tok": "s3cr3t-value"}, "api_token")
	if err != nil || s.Reveal() != "s3cr3t-value" {
		t.Fatalf("%v", err)
	}
	if _, err := c.Credential(context.Background(), mapSource{}, "api_token"); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := c.Credential(context.Background(), mapSource{}, "other"); err == nil {
		t.Fatal("unconfigured purpose accepted")
	}
	if _, err := c.Credential(context.Background(), nil, "api_token"); err == nil {
		t.Fatal("nil source accepted")
	}
}

func TestPaginate(t *testing.T) {
	pages := map[string]adapter.Page[int]{"": {Items: []int{1, 2}, Next: "a"}, "a": {Items: []int{3}, Next: "b"}, "b": {Items: []int{4}}}
	fetch := func(_ context.Context, tok string) (adapter.Page[int], error) { return pages[tok], nil }
	got, err := adapter.Paginate(context.Background(), 0, fetch)
	if err != nil || !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := adapter.Paginate(context.Background(), 2, fetch); !errors.Is(err, adapter.ErrTooManyPages) {
		t.Fatalf("cap: %v", err)
	}
	loop := func(_ context.Context, _ string) (adapter.Page[int], error) {
		return adapter.Page[int]{Next: "same"}, nil
	}
	if _, err := adapter.Paginate(context.Background(), 0, loop); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("loop: %v", err)
	}
	boom := func(_ context.Context, _ string) (adapter.Page[int], error) {
		return adapter.Page[int]{}, errors.New("boom")
	}
	if _, err := adapter.Paginate(context.Background(), 0, boom); err == nil {
		t.Fatal("error swallowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Paginate(ctx, 0, fetch); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	clk := clock.NewFake(t0)
	l := adapter.NewLimiter(clk, 2)
	for i := 0; i < 3; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := clk.Sleeps(); !reflect.DeepEqual(got, []time.Duration{500 * time.Millisecond, 500 * time.Millisecond}) {
		t.Fatalf("sleeps %v", got)
	}
	var none *adapter.Limiter
	if err := none.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.NewLimiter(clk, 0).Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRedact(t *testing.T) {
	in := `GET failed: Authorization: Bearer abcdefghijklmnopqrstuvwxyz password=hunter22hunter token-xyz-123`
	out := adapter.Redact(in, "token-xyz-123")
	for _, leak := range []string{"abcdefghijklmnop", "hunter22", "token-xyz-123"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leak %q in %q", leak, out)
		}
	}
	if !adapter.LooksSecret("-----BEGIN RSA PRIVATE KEY-----") || adapter.LooksSecret("web01.example.test") {
		t.Fatal("LooksSecret")
	}
	if len(adapter.FindSecrets([]byte(`{"api_token":"abcdefgh12"}`))) == 0 {
		t.Fatal("FindSecrets")
	}
}

func TestCursors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cursors.json")
	s, err := adapter.LoadCursors(p)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := adapter.EncodeCursor(map[string]int{"off": 7})
	if err := s.Set("a", c); err != nil {
		t.Fatal(err)
	}
	s2, err := adapter.LoadCursors(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]int
	if err := adapter.DecodeCursor(s2.Get("a"), &v); err != nil || v["off"] != 7 {
		t.Fatalf("%v %v", v, err)
	}
	if err := adapter.DecodeCursor("{", &v); err == nil {
		t.Fatal("bad cursor accepted")
	}
	_ = os.WriteFile(p, []byte("{"), 0o600)
	if _, err := adapter.LoadCursors(p); err == nil {
		t.Fatal("corrupt file accepted")
	}
	mem, _ := adapter.LoadCursors("")
	if err := mem.Set("x", "1"); err != nil || mem.Get("x") != "1" {
		t.Fatal("memory store")
	}
}

// counter is a test adapter emitting one observation per sync, its cursor
// counting syncs.
type counter struct{}

func (counter) Describe() adapter.Description { return adapter.Description{Name: "counter"} }

func (counter) Validate(cfg adapter.Config) error {
	if cfg.Setting("fail", "") == "validate" {
		return errors.New("invalid")
	}
	return nil
}

func (counter) Sync(_ context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	if cfg.Setting("fail", "") == "sync" {
		return adapter.Result{}, errors.New("sync failed")
	}
	n, _ := strconv.Atoi(string(since))
	o := submit.Observation{Target: submit.Target{Kind: submit.KindFile, Host: "h.example.test", Path: "/f" + strconv.Itoa(n)}, Method: submit.MethodAdapter, ObservedAt: t0, Outcome: submit.OutcomeReached}
	return adapter.Result{Observations: []submit.Observation{o}, Cursor: adapter.Cursor(strconv.Itoa(n + 1))}, nil
}

func init() { adapter.Register("counter", func(adapter.Env) adapter.Adapter { return counter{} }) }

type sink struct {
	obs []submit.Observation
	err error
}

func (s *sink) Enqueue(_ context.Context, obs []submit.Observation) error {
	if s.err != nil {
		return s.err
	}
	s.obs = append(s.obs, obs...)
	return nil
}

func TestRunOnceAdvancesCursorOnlyAfterSink(t *testing.T) {
	cur, _ := adapter.LoadCursors("")
	cfg := adapter.Config{Name: "c1", Adapter: "counter"}
	failing := &sink{err: errors.New("buffer full")}
	if _, err := adapter.RunOnce(context.Background(), adapter.Env{}, cfg, cur, failing); err == nil {
		t.Fatal("sink error swallowed")
	}
	if cur.Get("c1") != "" {
		t.Fatalf("cursor advanced to %q despite the sink failing", cur.Get("c1"))
	}
	ok := &sink{}
	for i := 0; i < 2; i++ {
		if n, err := adapter.RunOnce(context.Background(), adapter.Env{}, cfg, cur, ok); err != nil || n.Observations != 1 {
			t.Fatalf("%+v %v", n, err)
		}
	}
	if cur.Get("c1") != "2" || ok.obs[0].Target.Path != "/f0" || ok.obs[1].Target.Path != "/f1" {
		t.Fatalf("cursor %q obs %+v", cur.Get("c1"), ok.obs)
	}
	for name, c := range map[string]adapter.Config{
		"unknown":  {Name: "x", Adapter: "nope"},
		"check":    {Name: "Bad Name", Adapter: "counter"},
		"validate": {Name: "x", Adapter: "counter", Settings: map[string]string{"fail": "validate"}},
		"sync":     {Name: "x", Adapter: "counter", Settings: map[string]string{"fail": "sync"}},
	} {
		if _, err := adapter.RunOnce(context.Background(), adapter.Env{}, c, cur, ok); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if !reflect.DeepEqual(adapter.Names()[:1], []string{"counter"}) {
		t.Fatalf("names %v", adapter.Names())
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	adapter.Register("counter", func(adapter.Env) adapter.Adapter { return counter{} })
}

func TestFixtureTransport(t *testing.T) {
	dir := t.TempDir()
	ex := `{"request":{"method":"GET","path":"/api/x","query":"b=2&a=1"},"response":{"status":200,"headers":{"Content-Type":"application/json"},"body":{"ok":true}}}`
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(ex), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := fixture.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: tr}
	resp, err := hc.Get("https://api.example.test/api/x?a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != `{"ok":true}` {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if r, err := hc.Get("https://api.example.test/api/y"); err == nil {
		_ = r.Body.Close()
		t.Fatal("unmatched request served")
	}
	if len(tr.Requests()) != 2 {
		t.Fatalf("requests %d", len(tr.Requests()))
	}
	if _, err := fixture.Load(t.TempDir()); err == nil {
		t.Fatal("empty dir accepted")
	}
	_ = os.WriteFile(filepath.Join(dir, "y.json"), []byte(ex), 0o600)
	if _, err := fixture.Load(dir); err == nil {
		t.Fatal("duplicate accepted")
	}
}
