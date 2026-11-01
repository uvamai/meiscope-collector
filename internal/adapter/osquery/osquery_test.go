package osquery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

const fleetToken = "fleet-api-token-0123456789abcdef" //nolint:gosec // test-only, synthetic value

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

func newEnv(t *testing.T, rt http.RoundTripper) (adapter.Env, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	return adapter.Env{
		HTTP:  &http.Client{Transport: rt},
		Creds: mapSource{"fleet_token": fleetToken},
		Clock: clock.NewFake(t0),
		Log:   slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		// The tests exercise the proposed shape; TestFeatureOff covers the default.
		Features: adapter.Features{LocalStoreV1: true},
	}, &logs
}

func newAdapter(env adapter.Env) adapter.Adapter {
	f, ok := adapter.Lookup(osquery.Name)
	if !ok {
		panic("osquery not registered")
	}
	return f(env)
}

func syncOK(t *testing.T, a adapter.Adapter, cfg adapter.Config, since adapter.Cursor) adapter.Result {
	t.Helper()
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), cfg, since)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// submitAll checks that the fake core (contract incl. the 0.5.0 proposal)
// accepts every observation.
func submitAll(t *testing.T, obs []submit.Observation) {
	t.Helper()
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Accepted != len(obs) || len(res.Rejected) != 0 {
		t.Fatalf("accepted %d of %d, rejected %+v", res.Accepted, len(obs), res.Rejected)
	}
}

func count(obs []submit.Observation) map[string]int {
	m := map[string]int{}
	for _, o := range obs {
		m[o.Target.Host+" "+o.Target.Kind]++
	}
	return m
}

func fleetConfig() adapter.Config {
	return adapter.Config{
		Name: "fleet", Adapter: osquery.Name,
		Settings:    map[string]string{"mode": "fleet", "url": "https://fleet.example.test", "per_page": "2", "rate_per_second": "100"},
		Credentials: map[string]string{"api_token": "fleet_token"},
	}
}

func TestFleetReplay(t *testing.T) {
	tr, err := fixture.Load(fixture.Dir("osquery", "fleet"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := newEnv(t, tr)
	a := newAdapter(env)
	res := syncOK(t, a, fleetConfig(), "")
	want := map[string]int{"web01.example.test store": 3, "web01.example.test file": 1, "dc01.example.test store": 1, "app01.example.test store": 1, "app01.example.test file": 2}
	if got := count(res.Observations); !reflect.DeepEqual(got, want) {
		t.Fatalf("observations %v, want %v", got, want)
	}
	for _, r := range tr.Requests() {
		if r.Header.Get("Authorization") != "Bearer "+fleetToken {
			t.Fatalf("request %s without the bearer token", r.URL)
		}
	}
	var user, pfx bool
	for _, o := range res.Observations {
		if o.Target.Store == "windows/Users/S-1-5-21-1000000001-1000000002-1000000003-1105/My" {
			user = true
			if c := o.Adapter.Certificate; c.SHA1 != strings.ToLower(c.SHA1) || c.NotAfter == nil || c.CA == nil || *c.CA {
				t.Fatalf("certificate %+v", c)
			}
		}
		if o.Target.Path == `C:\ProgramData\ExampleApp\tls\web01.pfx` {
			pfx = o.Adapter.File.SHA256 == strings.ToLower(o.Adapter.File.SHA256) && *o.Adapter.File.Size == 4211
		}
		if o.Method != submit.MethodAdapter || o.Adapter.Source != "osquery" {
			t.Fatalf("observation %+v", o)
		}
	}
	if !user || !pfx {
		t.Fatalf("per-user store %v, windows keystore %v", user, pfx)
	}
	submitAll(t, res.Observations)

	// Deterministic replay: the same fixtures and cursor give the same batch.
	tr2, _ := fixture.Load(fixture.Dir("osquery", "fleet"))
	env2, _ := newEnv(t, tr2)
	again := syncOK(t, newAdapter(env2), fleetConfig(), "")
	if !reflect.DeepEqual(again, res) {
		t.Fatal("fixture replay is not deterministic")
	}
	// Delta: nothing was refetched since the cursor.
	if next := syncOK(t, a, fleetConfig(), res.Cursor); len(next.Observations) != 0 {
		t.Fatalf("delta returned %d observations", len(next.Observations))
	}
}

func TestFleetErrors(t *testing.T) {
	ctx := context.Background()
	var reportStatus []int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/reports" { // an older Fleet: no reports API
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/api/v1/fleet/queries" {
			_, _ = io.WriteString(w, `{"queries":[{"id":1,"name":"meiscope_certificates_posix"}]}`)
			return
		}
		st := http.StatusNotFound
		if len(reportStatus) > 0 {
			st, reportStatus = reportStatus[0], reportStatus[1:]
		}
		if st == http.StatusOK {
			_, _ = io.WriteString(w, `{"query_id":1,"report_clipped":true,"results":[]}`)
			return
		}
		w.WriteHeader(st)
	}))
	defer srv.Close()
	env, logs := newEnv(t, srv.Client().Transport)
	a := newAdapter(env)
	cfg := fleetConfig()
	cfg.Settings["url"] = srv.URL
	cfg.Settings["queries"] = "meiscope_certificates_posix"

	_, err := a.Sync(ctx, cfg, "")
	if !errors.Is(err, osquery.ErrFleetAPI) {
		t.Fatalf("404: %v", err)
	}
	reportStatus = []int{http.StatusServiceUnavailable, http.StatusOK}
	if _, err := a.Sync(ctx, cfg, ""); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !strings.Contains(logs.String(), "clipped") {
		t.Fatal("clipped report not logged")
	}
	reportStatus = []int{http.StatusUnauthorized}
	_, err = a.Sync(ctx, cfg, "")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("401: %v", err)
	}
	cfg.Settings["queries"] = "meiscope_keystores_posix"
	if _, err := a.Sync(ctx, cfg, ""); err == nil || !strings.Contains(err.Error(), "no saved query") {
		t.Fatalf("missing query: %v", err)
	}
	noCred := fleetConfig()
	noCred.Settings["url"] = srv.URL
	noCred.Credentials["api_token"] = "absent"
	if _, err := a.Sync(ctx, noCred, ""); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("missing credential: %v", err)
	}
	if _, err := a.Sync(ctx, cfg, "{bad"); err == nil {
		t.Fatal("bad cursor accepted")
	}
	if strings.Contains(logs.String(), fleetToken) {
		t.Fatal("token in logs")
	}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name())) //nolint:gosec // test-only, synthetic value
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil { //nolint:gosec // test-only, synthetic value
			t.Fatal(err)
		}
	}
	return dst
}

func logConfig(dir string) adapter.Config {
	return adapter.Config{Name: "logs", Adapter: osquery.Name, Settings: map[string]string{"mode": "logsink", "dir": dir}}
}

// TestLogSinkRecordedLinux replays the log recorded from osquery 5.12.1 on
// Ubuntu 24.04 running the pack.
func TestLogSinkRecordedLinux(t *testing.T) {
	dir := copyDir(t, fixture.Dir("osquery", "logsink"))
	env, _ := newEnv(t, nil)
	a := newAdapter(env)
	res := syncOK(t, a, logConfig(dir), "")
	got := count(res.Observations)
	if got["app01.example.test store"] != 121 || got["app01.example.test file"] != 4 || len(got) != 2 {
		t.Fatalf("observations %v", got)
	}
	loggedTimes := unixTimesOf(t, filepath.Join(dir, "osqueryd.snapshots.log"))
	var p12, testCA bool
	for _, o := range res.Observations {
		if o.Target.Kind == submit.KindFile && o.Target.Path == "/opt/app/keystore.p12" {
			p12 = true
		}
		if strings.HasPrefix(o.Target.Path, "/opt/containerd/") || strings.HasSuffix(o.Target.Path, "too-big.pfx") {
			t.Fatalf("pack caps not applied: %s", o.Target.Path)
		}
		if c := o.Adapter.Certificate; c != nil && c.CommonName == "Meiscope Test Root CA" {
			testCA = *c.CA && o.Target.Store == "posix/system" && o.Target.Path == "/etc/ssl/certs/ca-certificates.crt"
		}
		if !loggedTimes[o.ObservedAt.Unix()] {
			t.Fatalf("observed_at %s is not the logged time", o.ObservedAt)
		}
	}
	if !p12 || !testCA {
		t.Fatalf("keystore %v, test CA %v", p12, testCA)
	}
	submitAll(t, res.Observations)
	again := syncOK(t, newAdapter(env), logConfig(dir), "")
	if !reflect.DeepEqual(again, res) {
		t.Fatal("log replay is not deterministic")
	}

	// Nothing new; then a partial line is left for later; completed, it is read.
	if r := syncOK(t, a, logConfig(dir), res.Cursor); len(r.Observations) != 0 {
		t.Fatalf("delta %d", len(r.Observations))
	}
	logFile := filepath.Join(dir, "osqueryd.snapshots.log")
	line := `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"app02.example.test","unixTime":1792900000,"action":"added","columns":{"path":"/srv/x.jks","size":"10","sha256":"` + strings.Repeat("a", 64) + `"}}`
	appendFile(t, logFile, line[:40])
	partial := syncOK(t, a, logConfig(dir), res.Cursor)
	if len(partial.Observations) != 0 {
		t.Fatal("partial line read")
	}
	appendFile(t, logFile, line[40:]+"\n")
	full := syncOK(t, a, logConfig(dir), partial.Cursor)
	if len(full.Observations) != 1 || full.Observations[0].Target.Path != "/srv/x.jks" {
		t.Fatalf("appended event: %+v", full.Observations)
	}
	// Rotation: the renamed file continues from its cursor.
	if err := os.Rename(logFile, logFile+".1"); err != nil {
		t.Fatal(err)
	}
	if r := syncOK(t, a, logConfig(dir), full.Cursor); len(r.Observations) != 0 {
		t.Fatalf("rotated file re-read: %d", len(r.Observations))
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // test-only
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func TestLogSinkWindowsAndTruncation(t *testing.T) {
	dir := copyDir(t, fixture.Dir("osquery", "logsink-windows"))
	appendFile(t, filepath.Join(dir, "notes.txt"), "ignored\n")
	appendFile(t, filepath.Join(dir, "bad.log"), "not json\n"+`{"name":"pack_meiscope_meiscope_certificates_windows","hostIdentifier":"","snapshot":[]}`+"\n")
	env, logs := newEnv(t, nil)
	a := newAdapter(env)
	res := syncOK(t, a, logConfig(dir), "")
	if got := count(res.Observations); !reflect.DeepEqual(got, map[string]int{"web01.example.test store": 3, "web01.example.test file": 1}) {
		t.Fatalf("observations %v", got)
	}
	for _, reason := range []string{"removed_event", "other_query", "bad_line"} {
		if !strings.Contains(logs.String(), reason) {
			t.Errorf("skip reason %s not logged", reason)
		}
	}
	submitAll(t, res.Observations)
	// A file truncated in place is read from the start again.
	f := filepath.Join(dir, "osqueryd.results.log")
	b, _ := os.ReadFile(f) //nolint:gosec // test-only
	first := b[:bytes.IndexByte(b, '\n')+1]
	if err := os.WriteFile(f, first, 0o600); err != nil { //nolint:gosec // test-only, synthetic value
		t.Fatal(err)
	}
	if r := syncOK(t, a, logConfig(dir), res.Cursor); len(r.Observations) != 3 {
		t.Fatalf("after truncation: %d", len(r.Observations))
	}
	// An over-long line is skipped, not fatal.
	cfg := logConfig(dir)
	cfg.Settings["max_line_bytes"] = "1024"
	if r := syncOK(t, a, cfg, ""); len(r.Observations) != 0 {
		t.Fatalf("over-long line mapped: %d", len(r.Observations))
	}
	if _, err := a.Sync(context.Background(), logConfig(filepath.Join(dir, "missing")), ""); err == nil {
		t.Fatal("missing dir accepted")
	}
}

func TestDirect(t *testing.T) {
	env, _ := newEnv(t, nil)
	a := newAdapter(env)
	files := func(dir string, names ...string) string {
		var out []string
		for _, n := range names {
			out = append(out, filepath.Join(fixture.Dir("osquery", dir), n))
		}
		return strings.Join(out, ",")
	}
	linux := adapter.Config{Name: "direct", Adapter: osquery.Name, Settings: map[string]string{
		"mode": "direct", "host": "app01.example.test",
		"files": files("direct", "direct-meiscope_certificates_posix.json", "direct-meiscope_keystores_posix.json"),
	}}
	res := syncOK(t, a, linux, "")
	if got := count(res.Observations); got["app01.example.test store"] != 121 || got["app01.example.test file"] != 4 {
		t.Fatalf("linux %v", got)
	}
	for _, o := range res.Observations {
		if !o.ObservedAt.Equal(t0) {
			t.Fatalf("observed_at %s", o.ObservedAt)
		}
	}
	submitAll(t, res.Observations)
	if r := syncOK(t, a, linux, res.Cursor); len(r.Observations) != 0 {
		t.Fatalf("unchanged files re-read: %d", len(r.Observations))
	}
	win := adapter.Config{Name: "direct-win", Adapter: osquery.Name, Settings: map[string]string{
		"mode": "direct", "host": "web01.example.test",
		"files": files("windows", "web01-meiscope_certificates_windows.json", "web01-meiscope_keystores_windows.json"),
	}}
	wr := syncOK(t, a, win, "")
	if got := count(wr.Observations); !reflect.DeepEqual(got, map[string]int{"web01.example.test store": 3, "web01.example.test file": 1}) {
		t.Fatalf("windows %v", got)
	}
	stores := map[string]bool{}
	for _, o := range wr.Observations {
		stores[o.Target.Store] = true
	}
	for _, s := range []string{"windows/LocalMachine/My", "windows/LocalMachine/CA", "windows/Users/S-1-5-21-1000000001-1000000002-1000000003-1105/My"} {
		if !stores[s] {
			t.Errorf("store %s missing from %v", s, stores)
		}
	}
	submitAll(t, wr.Observations)

	bad := filepath.Join(t.TempDir(), "x-meiscope_keystores_posix.json")
	_ = os.WriteFile(bad, []byte(`{"not":"an array"}`), 0o600)
	cfg := adapter.Config{Name: "d", Adapter: osquery.Name, Settings: map[string]string{"mode": "direct", "host": "h", "files": bad}}
	if _, err := a.Sync(context.Background(), cfg, ""); err == nil {
		t.Fatal("non-array accepted")
	}
	cfg.Settings["files"] = bad + ".missing"
	if _, err := a.Sync(context.Background(), cfg, ""); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestValidate(t *testing.T) {
	a := newAdapter(adapter.Env{})
	ok := []map[string]string{
		{"mode": "fleet", "url": "https://fleet.example.test", "team_id": "3", "per_page": "50", "rate_per_second": "1.5"},
		{"mode": "logsink", "dir": "/var/log/osquery"},
		{"mode": "direct", "host": "h", "files": "a-meiscope_certificates_posix.json"},
	}
	for _, s := range ok {
		if err := a.Validate(adapter.Config{Settings: s, Credentials: map[string]string{"api_token": "t"}}); err != nil {
			t.Errorf("%v: %v", s, err)
		}
	}
	bad := []map[string]string{
		{"mode": "scan"},
		{"mode": "fleet", "url": "http://fleet.example.test"},
		{"mode": "fleet", "url": "https://u:p@fleet.example.test"}, //nolint:gosec // test-only, synthetic value
		{"mode": "fleet", "url": "https://fleet.example.test", "queries": "select_everything"},
		{"mode": "fleet", "url": "https://fleet.example.test", "per_page": "0"},
		{"mode": "fleet", "url": "https://fleet.example.test", "team_id": "x"},
		{"mode": "fleet", "url": "https://fleet.example.test", "rate_per_second": "-1"},
		{"mode": "logsink"},
		{"mode": "logsink", "dir": "d", "max_line_bytes": "1"},
		{"mode": "direct", "host": "h"},
		{"mode": "direct", "host": "h", "files": "results.json"},
	}
	for _, s := range bad {
		if err := a.Validate(adapter.Config{Settings: s, Credentials: map[string]string{"api_token": "t"}}); err == nil {
			t.Errorf("%v: accepted", s)
		}
	}
	if err := a.Validate(adapter.Config{Settings: map[string]string{"mode": "fleet", "url": "https://f.example.test"}}); err == nil {
		t.Error("fleet without api_token accepted")
	}
	if d := a.Describe(); d.Name != "osquery" || d.Source != "osquery" {
		t.Errorf("describe %+v", d)
	}
}

// TestPack checks the deployable pack: the queries the adapter maps, the
// keystore caps and exclusions, and that the Fleet YAML carries the same SQL.
func TestPack(t *testing.T) {
	root := filepath.Join(fixture.Root(), "..", "..", "packs", "osquery")
	raw, err := os.ReadFile(filepath.Join(root, "meiscope.conf")) //nolint:gosec // test-only
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Queries map[string]struct {
			Query    string `json:"query"`
			Interval int    `json:"interval"`
			Platform string `json:"platform"`
			Snapshot bool   `json:"snapshot"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range pack.Queries {
		names = append(names, n)
	}
	fleet, err := os.ReadFile(filepath.Join(root, "fleet-queries.yml")) //nolint:gosec // test-only
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range osquery.PackQueries {
		q, ok := pack.Queries[n]
		if !ok {
			t.Fatalf("pack lacks %s (has %v)", n, names)
		}
		if q.Interval != 86400 || !q.Snapshot {
			t.Errorf("%s: interval %d snapshot %v", n, q.Interval, q.Snapshot)
		}
		wantPlat := "posix"
		if strings.HasSuffix(n, "_windows") {
			wantPlat = "windows"
		}
		if q.Platform != wantPlat {
			t.Errorf("%s: platform %s", n, q.Platform)
		}
		var sqlBuf bytes.Buffer
		enc := json.NewEncoder(&sqlBuf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(q.Query)
		sqlJSON := bytes.TrimSpace(sqlBuf.Bytes())
		if !bytes.Contains(fleet, append([]byte("query: "), sqlJSON...)) {
			t.Errorf("fleet-queries.yml does not carry the SQL of %s", n)
		}
		if strings.Contains(n, "keystores") {
			for _, must := range []string{"f.size <= 10485760", "LIMIT 1000", "h.sha256", "'%.jks'", "'%.p12'", "'%.pfx'", "'%.pem'", "'%.kdb'"} {
				if !strings.Contains(q.Query, must) {
					t.Errorf("%s lacks %s", n, must)
				}
			}
			if !strings.Contains(strings.ToLower(q.Query), "docker") || !strings.Contains(strings.ToLower(q.Query), "containerd") {
				t.Errorf("%s does not exclude container data directories", n)
			}
		}
		if strings.Contains(strings.ToLower(q.Query), "private_key") || strings.Contains(q.Query, "pem FROM") {
			t.Errorf("%s reads key material", n)
		}
	}
	if len(pack.Queries) != len(osquery.PackQueries) {
		t.Errorf("pack has extra queries: %v", names)
	}
}

// unixTimesOf returns the unixTime values of an osquery JSON log.
func unixTimesOf(t *testing.T, path string) map[int64]bool {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-only
	if err != nil {
		t.Fatal(err)
	}
	out := map[int64]bool{}
	for _, l := range bytes.Split(b, []byte("\n")) {
		var ev struct {
			UnixTime int64 `json:"unixTime"`
		}
		if json.Unmarshal(l, &ev) == nil && ev.UnixTime > 0 {
			out[ev.UnixTime] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no unixTime in the log")
	}
	return out
}

// TestFleetReplayReportsAPI: Fleet 4.93 and later serve the same data under
// /reports; the adapter prefers it and produces the same observations as
// through the older /queries endpoints.
func TestFleetReplayReportsAPI(t *testing.T) {
	oldTr, err := fixture.Load(fixture.Dir("osquery", "fleet"))
	if err != nil {
		t.Fatal(err)
	}
	newTr, err := fixture.Load(fixture.Dir("osquery", "fleet-reports"))
	if err != nil {
		t.Fatal(err)
	}
	envOld, _ := newEnv(t, oldTr)
	envNew, _ := newEnv(t, newTr)
	a := syncOK(t, newAdapter(envOld), fleetConfig(), "")
	b := syncOK(t, newAdapter(envNew), fleetConfig(), "")
	if len(a.Observations) == 0 || !reflect.DeepEqual(a, b) {
		t.Fatalf("the two Fleet API families gave different results: %d vs %d observations", len(a.Observations), len(b.Observations))
	}
	for _, r := range newTr.Requests() {
		if strings.Contains(r.URL.Path, "/fleet/queries") {
			t.Errorf("the deprecated endpoint was used: %s", r.URL.Path)
		}
	}
	for _, r := range oldTr.Requests()[1:] {
		if strings.Contains(r.URL.Path, "/fleet/reports") {
			t.Errorf("the reports endpoint was used on an older Fleet after the probe: %s", r.URL.Path)
		}
	}
}
