package osquery_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// TestOsqueryPackLinuxIntegration runs the generated pack on a real osquery
// 5.12.1 (Ubuntu 24.04, Docker) over a few synthetic files, once through
// osqueryi (direct output) and once through osqueryd's filesystem logger
// (log sink), and ingests both: store and file bindings, the encrypted
// store finding, and the skip counts, accepted by the fake core.
func TestOsqueryPackLinuxIntegration(t *testing.T) {
	dockerRequired(t)
	run := startRun(t, "osquery")
	defer run.finish()
	dir := t.TempDir()
	mustDocker(t, "build", "-q", "-t", osqueryTag, "-f", filepath.Join(fixture.Dir("osquery"), "Dockerfile.osquery"), fixture.Dir("osquery"))

	packDir := filepath.Join(dir, "pack")
	if err := os.MkdirAll(packDir, 0o755); err != nil { //nolint:gosec // temp dir
		t.Fatal(err)
	}
	conf, err := osquery.PackConf(osquery.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(packDir, name), b, 0o644); err != nil { //nolint:gosec // temp dir
			t.Fatal(err)
		}
	}
	write("meiscope.conf", conf)
	qs, _ := osquery.Pack(osquery.DefaultLimits())
	for _, q := range qs {
		if q.Platform == "posix" {
			write(q.Name+".sql", []byte(q.SQL))
		}
	}
	inner, err := os.ReadFile(filepath.Join(fixture.Dir("osquery"), "record-inner.sh")) //nolint:gosec // repository file
	if err != nil {
		t.Fatal(err)
	}
	write("record-inner.sh", inner)

	name := run.name("osquery")
	mustDocker(t, append(append([]string{"create", "--name", name, "--hostname", "app01.example.test"}, run.labels()...), osqueryTag, "sh", "/pack/record-inner.sh")...)
	mustDocker(t, "cp", packDir, name+":/")
	if out, err := docker(t, "start", "-a", name); err != nil {
		t.Fatalf("osquery run: %v\n%s", err, tailLines(out, 15))
	}
	out := filepath.Join(dir, "out")
	mustDocker(t, "cp", name+":/out", out)

	env, _ := newEnv(t, nil)
	a := newAdapter(env)
	f := func(n string) string { return filepath.Join(out, n) }
	direct := adapter.Config{Name: "direct", Adapter: osquery.Name, Settings: map[string]string{
		"mode": "direct", "host": "app01.example.test",
		"files": strings.Join([]string{f("direct-meiscope_certificates_posix.json"), f("direct-meiscope_keystores_posix.json"), f("direct-meiscope_keystore_counts_posix.json")}, ","),
	}}
	res := syncOK(t, a, direct, "")
	logs := syncOK(t, a, logConfig(f("log")), "")
	for name, r := range map[string]adapter.Result{"osqueryi": res, "osqueryd log": logs} {
		got := count(r.Observations)
		if got["app01.example.test store"] < 100 || got["app01.example.test file"] != 4 {
			t.Errorf("%s: observations %v", name, got)
		}
		var p12, jks, big bool
		for _, o := range r.Observations {
			switch o.Target.Path {
			case "/opt/app/keystore.p12":
				p12 = len(o.Adapter.Findings) == 1 && o.Adapter.File.StoreType == submit.StorePKCS12
			case "/opt/app/trust.jks":
				jks = len(o.Adapter.Findings) == 1
			case "/opt/app/too-big.pfx":
				big = true
			}
		}
		if !p12 || !jks || big {
			t.Errorf("%s: p12 finding %v, jks finding %v, oversize file reported %v", name, p12, jks, big)
		}
		submitAll(t, r.Observations)
	}
	if res.Stats["skipped_oversize"] != 1 || res.Stats["skipped_excluded"] < 1 {
		t.Errorf("stats %v", res.Stats)
	}
	t.Logf("osquery 5.12.1 on Ubuntu 24.04: %d observations via osqueryi, %d via the osqueryd log; stats %v", len(res.Observations), len(logs.Observations), res.Stats)
}
