package osquery_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Images, pinned by digest (looked up 2026-10-25): fleetdm/fleet v4.93.2
// (the newest release tag on Docker Hub at that date), mysql 8.0.46 and
// redis 7.4.11-alpine. Pull them first: docker pull <image>@<digest>.
const (
	fleetImage = "fleetdm/fleet@sha256:7c076ea2139feeee1fe25e70fc7cf377291bbc1b0ce210b0350e69c4deae23ae"
	mysqlImage = "mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
	redisImage = "redis@sha256:57e4255cc971b1c8d6f8a6ca283ac01bc3ecdd914273ef6bfaede87aaecd6541"
	osqueryTag = "meiscope-osquery-test:5.12.1"
)

func randomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// fleetClient talks to the Fleet under test.
type fleetClient struct {
	base  string
	hc    *http.Client
	token string
}

func (f *fleetClient) do(t *testing.T, method, path string, body, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return -1
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v\n%s", method, path, err, b)
		}
	} else if resp.StatusCode >= 300 {
		t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.StatusCode
}

// TestFleetIntegration enrols a real osquery 5.12.1 host (Ubuntu 24.04) in a
// real Fleet server (MySQL and Redis behind it), creates the pack's saved
// queries from packs/osquery/fleet-queries.yml, waits for Fleet's reports,
// and runs the adapter against Fleet's real API. The observations must be
// accepted by the fake core under the proposed contract.
func TestFleetIntegration(t *testing.T) {
	dockerRequired(t)
	run := startRun(t, "fleet")
	defer run.finish()
	work := t.TempDir()

	for _, img := range []string{fleetImage, mysqlImage, redisImage} {
		if out, err := docker(t, "image", "inspect", "--format", "{{index .RepoDigests 0}}", img); err != nil {
			t.Fatalf("image %s is not present (docker pull it first): %s", img, out)
		}
	}
	mustDocker(t, "build", "-q", "-t", osqueryTag, "-f", filepath.Join(fixture.Dir("osquery"), "Dockerfile.osquery"), fixture.Dir("osquery"))

	// Network and databases.
	network := run.name("net")
	mustDocker(t, append([]string{"network", "create"}, append(run.labels(), network)...)...)
	dbPass, rootPass := randomSecret(12), randomSecret(12)
	mysql := run.name("mysql")
	mustDocker(t, append(append([]string{"run", "-d", "--name", mysql, "--network", network, "--network-alias", "mysql", "--tmpfs", "/var/lib/mysql"}, run.labels()...),
		"-e", "MYSQL_ROOT_PASSWORD="+rootPass, "-e", "MYSQL_DATABASE=fleet", "-e", "MYSQL_USER=fleet", "-e", "MYSQL_PASSWORD="+dbPass, mysqlImage)...)
	redis := run.name("redis")
	mustDocker(t, append(append([]string{"run", "-d", "--name", redis, "--network", network, "--network-alias", "redis"}, run.labels()...), redisImage)...)
	waitFor(t, "MySQL", 180*time.Second, 2*time.Second, func() bool {
		_, err := docker(t, "exec", mysql, "mysql", "-h127.0.0.1", "-ufleet", "-p"+dbPass, "-e", "select 1", "fleet")
		return err == nil
	})
	waitFor(t, "Redis", 60*time.Second, time.Second, func() bool {
		out, _ := docker(t, "exec", redis, "redis-cli", "ping")
		return strings.Contains(out, "PONG")
	})

	// TLS for Fleet: osquery only speaks TLS to its server.
	certDir := filepath.Join(work, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil { //nolint:gosec // temp dir for test certificates
		t.Fatal(err)
	}
	_, _, cert := selfSignedCert(t, certDir, []string{"fleet", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	fleetEnv := []string{
		"-e", "FLEET_MYSQL_ADDRESS=mysql:3306", "-e", "FLEET_MYSQL_DATABASE=fleet", "-e", "FLEET_MYSQL_USERNAME=fleet", "-e", "FLEET_MYSQL_PASSWORD=" + dbPass,
		"-e", "FLEET_REDIS_ADDRESS=redis:6379", "-e", "FLEET_SERVER_ADDRESS=0.0.0.0:8080",
		"-e", "FLEET_SERVER_CERT=/certs/server.crt", "-e", "FLEET_SERVER_KEY=/certs/server.key", "-e", "FLEET_LOGGING_JSON=true",
	}
	newFleet := func(name string, publish bool, cmd ...string) {
		args := []string{"create", "--name", name, "--network", network, "--network-alias", "fleet"}
		if publish {
			args = append(args, "-p", "127.0.0.1::8080")
		}
		args = append(args, run.labels()...)
		args = append(args, fleetEnv...)
		args = append(args, fleetImage)
		args = append(args, cmd...)
		mustDocker(t, args...)
		mustDocker(t, "cp", certDir, name+":/") // creates /certs
	}
	prep := run.name("fleet-prepare")
	newFleet(prep, false, "fleet", "prepare", "db", "--no-prompt")
	if out, err := docker(t, "start", "-a", prep); err != nil {
		t.Fatalf("fleet prepare db: %v\n%s", err, tailLines(out, 15))
	}
	srv := run.name("fleet")
	newFleet(srv, true, "fleet", "serve")
	mustDocker(t, "start", srv)
	port := mustDocker(t, "port", srv, "8080/tcp")
	hostPort := strings.Replace(strings.Split(port, "\n")[0], "0.0.0.0", "127.0.0.1", 1)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	fc := &fleetClient{base: "https://" + hostPort, hc: hc}
	waitFor(t, "Fleet to answer", 180*time.Second, 2*time.Second, func() bool {
		resp, err := hc.Get(fc.base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == 200
	})

	// First-run setup and login (a generated password; nothing is stored).
	adminPass := "Mq-" + randomSecret(10) + "9!"
	if st := fc.do(t, http.MethodPost, "/api/v1/setup", map[string]any{
		"admin":    map[string]any{"admin": true, "email": "admin@example.test", "name": "admin", "password": adminPass, "password_confirmation": adminPass},
		"org_info": map[string]any{"org_name": "Meiscope integration test"}, "server_url": fc.base,
	}, nil); st >= 300 {
		t.Fatalf("setup: %d", st)
	}
	var login struct {
		Token string `json:"token"`
	}
	if st := fc.do(t, http.MethodPost, "/api/v1/fleet/login", map[string]any{"email": "admin@example.test", "password": adminPass}, &login); st != 200 || login.Token == "" {
		t.Fatalf("login: %d", st)
	}
	fc.token = login.Token
	var ver struct {
		Version string `json:"version"`
	}
	fc.do(t, http.MethodGet, "/api/v1/fleet/version", nil, &ver)
	digest, _ := docker(t, "image", "inspect", "--format", "{{index .RepoDigests 0}}", fleetImage)
	t.Logf("Fleet version %s, image %s", ver.Version, digest)
	if !strings.HasPrefix(ver.Version, "4.93") {
		t.Fatalf("unexpected Fleet version %q", ver.Version)
	}

	// The saved queries, from the pack file.
	var secrets struct {
		Spec struct {
			Secrets []struct {
				Secret string `json:"secret"`
			} `json:"secrets"`
		} `json:"spec"`
	}
	fc.do(t, http.MethodGet, "/api/v1/fleet/spec/enroll_secret", nil, &secrets)
	enroll := "meiscope-test-" + randomSecret(8)
	if st := fc.do(t, http.MethodPost, "/api/v1/fleet/spec/enroll_secret", map[string]any{"spec": map[string]any{"secrets": []map[string]string{{"secret": enroll}}}}, nil); st >= 300 {
		t.Fatalf("enroll secret: %d", st)
	}
	createQueries(t, fc)
	ids0 := queryIDs(t, fc)

	// The failure injection of the hygiene proof: containers exist now.
	switch os.Getenv("MEISCOPE_FLEET_TEST_INJECT") {
	case "fail":
		t.Fatal("injected failure (hygiene proof)")
	case "panic":
		panic("injected panic (hygiene proof)")
	}

	// A real osquery host, enrolled with the secret.
	osq := run.name("osquery")
	setup := `set -e
mkdir -p /opt/app /etc/app /opt/containerd/x
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -keyout k2.pem -out /etc/app/tls.pem -days 90 -subj "/CN=app01.example.test" 2>/dev/null
openssl pkcs12 -export -in /etc/app/tls.pem -inkey k2.pem -out /opt/app/keystore.p12 -passout pass:synthetic 2>/dev/null
head -c 3000 /dev/urandom > /opt/app/trust.jks
cp /etc/app/tls.pem /opt/containerd/x/excluded.pem
head -c 20000000 /dev/zero > /opt/app/too-big.pfx
rm -f k2.pem
printf '%s' "$ENROLL" > /tmp/enroll
exec osqueryd --tls_hostname=fleet:8080 --tls_server_certs=/certs/server.crt --enroll_secret_path=/tmp/enroll \
  --enroll_tls_endpoint=/api/osquery/enroll --config_plugin=tls --config_tls_endpoint=/api/osquery/config --config_refresh=10 \
  --logger_plugin=tls --logger_tls_endpoint=/api/osquery/log --logger_tls_period=10 \
  --distributed_plugin=tls --disable_distributed=false --distributed_interval=10 \
  --distributed_tls_read_endpoint=/api/osquery/distributed/read --distributed_tls_write_endpoint=/api/osquery/distributed/write \
  --host_identifier=hostname --database_path=/tmp/db --pidfile=/tmp/pid --disable_watchdog --verbose=true`
	mustDocker(t, append(append([]string{"create", "--name", osq, "--hostname", "app01.example.test", "--network", network}, run.labels()...),
		"-e", "ENROLL="+enroll, osqueryTag, "sh", "-c", setup)...)
	mustDocker(t, "cp", certDir, osq+":/")
	mustDocker(t, "start", osq)
	defer func() { // runs before the sweep (defer order): diagnostics of a failed run
		if !t.Failed() {
			return
		}
		full, _ := docker(t, "logs", osq)
		var keep []string
		for _, l := range strings.Split(full, "\n") {
			if strings.Contains(l, "cheduled") || strings.Contains(l, "xecuting") || strings.Contains(l, "pack") || strings.Contains(l, "Error") || strings.Contains(l, "arning") {
				keep = append(keep, l)
			}
		}
		out := tailLines(strings.Join(keep, "\n"), 40)
		t.Logf("osquery container log:\n%s", out)
		out, _ = docker(t, "logs", "--tail", "15", srv)
		t.Logf("fleet log:\n%s", out)
		var hosts struct {
			Hosts []struct {
				ID       int    `json:"id"`
				Hostname string `json:"hostname"`
				Status   string `json:"status"`
			} `json:"hosts"`
		}
		fc.do(t, http.MethodGet, "/api/v1/fleet/hosts", nil, &hosts)
		t.Logf("fleet hosts: %+v", hosts.Hosts)
		for name, id := range ids0 {
			var raw json.RawMessage
			st := fc.do(t, http.MethodGet, fmt.Sprintf("/api/v1/fleet/queries/%d/report", id), nil, &raw)
			t.Logf("report %s (%d): %d %.200s", name, id, st, string(raw))
		}
		var enr struct {
			NodeKey string `json:"node_key"`
		}
		sv := &fleetClient{base: fc.base, hc: fc.hc}
		sv.do(t, http.MethodPost, "/api/osquery/enroll", map[string]any{"enroll_secret": enroll, "host_identifier": "diag-" + run.id, "platform_type": "9"}, &enr)
		var osqCfg json.RawMessage
		sv.do(t, http.MethodPost, "/api/osquery/config", map[string]any{"node_key": enr.NodeKey}, &osqCfg)
		var served map[string]json.RawMessage
		_ = json.Unmarshal(osqCfg, &served)
		for k, v := range served {
			if k == "schedule" || k == "packs" {
				t.Logf("config %s: %.900s", k, strings.Join(strings.Fields(string(v)), " "))
			} else {
				t.Logf("config key %s", k)
			}
		}
		var cfg json.RawMessage
		fc.do(t, http.MethodGet, "/api/v1/fleet/config", nil, &cfg)
		var c struct {
			ServerSettings map[string]any `json:"server_settings"`
		}
		_ = json.Unmarshal(cfg, &c)
		t.Logf("server_settings: %v", c.ServerSettings)
	}()

	// Wait for Fleet to hold the reports of the Linux queries.
	ids := queryIDs(t, fc)
	waitFor(t, "Fleet reports of the Linux pack queries", 240*time.Second, 5*time.Second, func() bool {
		for _, name := range []string{osquery.QueryCertificatesPosix, osquery.QueryKeystoresPosix, osquery.QueryKeystoreCountsPosix} {
			var rep struct {
				Results []json.RawMessage `json:"results"`
			}
			if st := fc.do(t, http.MethodGet, fmt.Sprintf("/api/v1/fleet/queries/%d/report", ids[name]), nil, &rep); st != 200 || len(rep.Results) == 0 {
				return false
			}
		}
		return true
	})

	// The adapter against Fleet's real API.
	var logs bytes.Buffer
	env := adapter.Env{
		HTTP: hc, Creds: mapSource{"fleet_token": fc.token}, Clock: clock.System{},
		Log:      slog.New(slog.NewJSONHandler(&logs, nil)),
		Features: adapter.Features{LocalStoreV1: true},
	}
	cfg := adapter.Config{
		Name: "fleet", Adapter: osquery.Name,
		Settings:    map[string]string{"mode": "fleet", "url": fc.base, "per_page": "2", "rate_per_second": "50"},
		Credentials: map[string]string{"api_token": "fleet_token"},
	}
	a := newAdapter(env)
	res := syncOK(t, a, cfg, "")
	t.Logf("adapter: %d observations from Fleet %s, stats %v", len(res.Observations), ver.Version, res.Stats)
	got := count(res.Observations)
	if got["app01.example.test store"] < 100 || got["app01.example.test file"] < 3 {
		t.Fatalf("observations %v\nlogs: %s", got, logs.String())
	}
	var p12 submit.Observation
	for _, o := range res.Observations {
		if o.Target.Path == "/opt/app/keystore.p12" {
			p12 = o
		}
		if strings.HasPrefix(o.Target.Path, "/opt/containerd/") || strings.HasSuffix(o.Target.Path, "too-big.pfx") {
			t.Errorf("the pack's limits did not apply: %s", o.Target.Path)
		}
	}
	if p12.Adapter == nil || p12.Adapter.File.StoreType != submit.StorePKCS12 || len(p12.Adapter.Findings) != 1 {
		t.Errorf("keystore.p12 as seen through Fleet: %+v", p12.Adapter)
	}
	if res.Stats["skipped_oversize"] != 1 || res.Stats["skipped_excluded"] < 1 {
		t.Errorf("stats %v (want skipped_oversize 1 and skipped_excluded > 0)", res.Stats)
	}
	submitAll(t, res.Observations)
	if again := syncOK(t, a, cfg, res.Cursor); len(again.Observations) != 0 {
		t.Errorf("the delta returned %d observations again", len(again.Observations))
	}
	if strings.Contains(logs.String(), fc.token) {
		t.Error("the Fleet token is in the adapter logs")
	}
}

// createQueries creates the pack's Fleet saved queries from
// packs/osquery/fleet-queries.yml, through the REST API.
func createQueries(t *testing.T, fc *fleetClient) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixture.Root(), "..", "..", "packs", "osquery", "fleet-queries.yml")) //nolint:gosec // repository file
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var doc struct {
			Spec struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
				Query       string `yaml:"query"`
				Interval    int    `yaml:"interval"`
				Platform    string `yaml:"platform"`
				Logging     string `yaml:"logging"`
				Discard     bool   `yaml:"discard_data"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		s := doc.Spec
		if st := fc.do(t, http.MethodPost, "/api/v1/fleet/queries", map[string]any{
			"name": s.Name, "description": s.Description, "query": s.Query, "interval": testInterval(s.Interval), "platform": s.Platform,
			"logging": s.Logging, "discard_data": s.Discard, "automations_enabled": false,
		}, nil); st >= 300 {
			t.Fatalf("create query %s: %d", s.Name, st)
		}
		n++
	}
	if n != len(osquery.PackQueries) {
		t.Fatalf("created %d queries, the pack has %d", n, len(osquery.PackQueries))
	}
}

func queryIDs(t *testing.T, fc *fleetClient) map[string]int {
	t.Helper()
	var l struct {
		Queries []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"queries"`
	}
	if st := fc.do(t, http.MethodGet, "/api/v1/fleet/queries?per_page=100", nil, &l); st != 200 {
		t.Fatalf("list queries: %d", st)
	}
	ids := map[string]int{}
	for _, q := range l.Queries {
		ids[q.Name] = q.ID
	}
	return ids
}

// tailLines keeps the last n lines of s.
func tailLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// testInterval replaces the pack's daily interval by 10 seconds. osqueryd
// starts its scheduler counter at the current Unix time, so a query with
// interval 86400 first runs at about 00:00 UTC; the test cannot wait for
// that. Everything else of the saved query is exactly the pack's.
func testInterval(packInterval int) int {
	if packInterval == 86400 {
		return 10
	}
	return packInterval
}
