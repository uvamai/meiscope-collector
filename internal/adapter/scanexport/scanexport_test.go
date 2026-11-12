package scanexport_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/scanexport"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var (
	t0    = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	mtime = time.Date(2026, 11, 10, 3, 4, 5, 0, time.UTC)
)

func newAdapter(t *testing.T, name string, f adapter.Features) (adapter.Adapter, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	fac, ok := adapter.Lookup(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return fac(adapter.Env{Clock: clock.NewFake(t0), Log: slog.New(slog.NewJSONHandler(&logs, nil)), Features: f}), &logs
}

var on = adapter.Features{AdapterEvidenceV2: true}

// copyFixtures copies the named exports to a temporary directory with a
// fixed modification time and returns their paths.
func copyFixtures(t *testing.T, name string, files ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(fixture.Dir(name, f))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func config(name string, files []string) adapter.Config {
	return adapter.Config{Name: name + "-exports", Adapter: name, Settings: map[string]string{"files": strings.Join(files, ",")}}
}

func run(t *testing.T, a adapter.Adapter, cfg adapter.Config, since adapter.Cursor) adapter.Result {
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

func checkStats(t *testing.T, got map[string]int, want map[string]int) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("stat %s = %d, want %d (%v)", k, got[k], v, got)
		}
	}
}

func submitTo(t *testing.T, spec string, obs []submit.Observation) error {
	t.Helper()
	core, err := submittest.NewCoreWithSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), obs)
	if err == nil && (res.Accepted != len(obs) || len(res.Rejected) != 0) {
		t.Fatalf("%s: %+v", spec, res)
	}
	return err
}

func TestTenable(t *testing.T) {
	files := copyFixtures(t, "tenable", "nessus-export.csv", "tenable-sc-export.csv")
	a, logs := newAdapter(t, scanexport.TenableName, on)
	res := run(t, a, config("tenable", files), "")
	checkStats(t, res.Stats, map[string]int{
		scanexport.StatFiles: 2, scanexport.StatRows: 8, scanexport.StatOtherChecks: 1, scanexport.StatMalformedRow: 1,
		scanexport.StatNoHost: 1, scanexport.StatBadPort: 1, scanexport.StatUnparsedOutput: 1, scanexport.StatNoIdentity: 1,
		scanexport.StatDuplicate: 1, scanexport.StatSkippedFeatureDisabled: 0,
	})
	if len(res.Observations) != 3 {
		t.Fatalf("%d observations", len(res.Observations))
	}
	byHost := map[string]submit.Observation{}
	for _, o := range res.Observations {
		byHost[o.Target.Host] = o
		if o.Target.Kind != submit.KindHostPortSNI || o.Target.SNI != "" || o.Method != submit.MethodAdapter ||
			o.Outcome != submit.OutcomeCertSeen || !o.ObservedAt.Equal(mtime) || o.Adapter.Source != "tenable" || o.Adapter.Scanner.Check != "10863" {
			t.Errorf("observation %+v", o)
		}
	}
	www := byHost["192.0.2.10"]
	c := www.Adapter.Certificate
	if www.Target.Port != 443 || c.SHA1 != "89433b4ac105d42a60364a3ec00366430801cfb8" || c.Serial != "2a01" || c.CommonName != "www.example.test" ||
		c.Issuer != "CN=Synthetic Test CA,O=Synthetic Test" || c.NotAfter.Format(time.RFC3339) != "2026-11-30T00:00:00Z" ||
		c.NotBefore.Format(time.RFC3339) != "2026-09-01T00:00:00Z" || c.KeyStrength != "256" || c.SelfSigned != nil || len(c.SHA256) != 64 ||
		!reflect.DeepEqual(c.DNSNames, []string{"www.example.test", "example.test"}) || www.Adapter.Scanner.File != "nessus-export.csv" {
		t.Errorf("www %+v %+v", www.Target, c)
	}
	legacy := byHost["192.0.2.11"].Adapter.Certificate
	if legacy.SelfSigned == nil || !*legacy.SelfSigned || legacy.KeyStrength != "2048" || legacy.SHA1 != "940d948a0b3a4338bbb35976a604ee5c6a3eb139" {
		t.Errorf("legacy %+v", legacy)
	}
	api := byHost["192.0.2.12"]
	if api.Target.Port != 636 || api.Adapter.Scanner.DNSName != "api.example.test" || api.Adapter.Certificate.SHA1 != "bc33e1a2cdde40760329367decb6e5952277588b" {
		t.Errorf("api %+v %+v", api.Target, api.Adapter)
	}
	if !strings.Contains(logs.String(), scanexport.StatMalformedRow) {
		t.Error("skipped rows are not logged")
	}
	if err := submitTo(t, submittest.Proposed010SpecPath(), res.Observations); err != nil {
		t.Fatal(err)
	}

	// Delta: unchanged files are not read again; a changed file is.
	again := run(t, a, config("tenable", files), res.Cursor)
	if len(again.Observations) != 0 || again.Stats[scanexport.StatFilesUnchanged] != 2 {
		t.Fatalf("second run %d observations, %v", len(again.Observations), again.Stats)
	}
	f, err := os.OpenFile(files[1], os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n")
	_ = f.Close()
	third := run(t, a, config("tenable", files), res.Cursor)
	if len(third.Observations) != 1 || third.Stats[scanexport.StatFilesUnchanged] != 1 {
		t.Fatalf("third run %d observations, %v", len(third.Observations), third.Stats)
	}
}

func TestQualys(t *testing.T) {
	files := copyFixtures(t, "qualys", "vm-scan-report.csv")
	a, _ := newAdapter(t, scanexport.QualysName, on)
	res := run(t, a, config("qualys", files), "")
	checkStats(t, res.Stats, map[string]int{
		scanexport.StatFiles: 1, scanexport.StatRows: 3, scanexport.StatOtherChecks: 1, scanexport.StatMalformedRow: 1,
		scanexport.StatBadPort: 1, scanexport.StatNoIdentity: 1, scanexport.StatUnparsedOutput: 0,
	})
	if len(res.Observations) != 2 {
		t.Fatalf("%d observations", len(res.Observations))
	}
	www, api := res.Observations[0], res.Observations[1]
	c := www.Adapter.Certificate
	if www.Target.Host != "192.0.2.10" || www.Target.Port != 443 || c.SHA1 != "" || c.Serial != "2a01" ||
		c.Issuer != "CN=Synthetic Test CA,O=Synthetic Test" || c.Subject != "CN=www.example.test,O=Synthetic Test" ||
		c.NotAfter.Format(time.RFC3339) != "2026-11-30T00:00:00Z" || c.NotBefore.Format(time.RFC3339) != "2026-09-01T00:00:00Z" ||
		c.KeyStrength != "256" || c.KeyAlgorithm != "id-ecPublicKey" || !reflect.DeepEqual(c.DNSNames, []string{"www.example.test", "example.test"}) ||
		www.Adapter.Scanner.Check != "86002" || www.Adapter.Scanner.DNSName != "www.example.test" || www.Adapter.Source != "qualys" {
		t.Errorf("www %+v %+v %+v", www.Target, c, www.Adapter.Scanner)
	}
	if api.Target.Port != 636 || api.Adapter.Certificate.Serial != "2a02" || api.Adapter.Certificate.CommonName != "api.example.test" {
		t.Errorf("api %+v %+v", api.Target, api.Adapter.Certificate)
	}
	// Identity by issuer and serial: the proposal accepts it, 0.9.0 does not.
	if err := submitTo(t, submittest.Proposed010SpecPath(), res.Observations); err != nil {
		t.Fatal(err)
	}
	if err := submitTo(t, submittest.VendoredSpecPath(), res.Observations); err == nil {
		t.Fatal("the 0.9.0 contract accepted certificates without sha1")
	}
}

func TestFeatureOff(t *testing.T) {
	files := copyFixtures(t, "qualys", "vm-scan-report.csv")
	a, logs := newAdapter(t, scanexport.QualysName, adapter.Features{LocalStoreV1: true})
	res := run(t, a, config("qualys", files), `{}`)
	if len(res.Observations) != 0 || res.Cursor != `{}` || res.Stats[scanexport.StatSkippedFeatureDisabled] != 2 {
		t.Fatalf("%v %q %v", res.Observations, res.Cursor, res.Stats)
	}
	if !strings.Contains(logs.String(), adapter.EnvAdapterEvidenceV2) {
		t.Error("warning does not name the switch")
	}
}

func TestWrongFormat(t *testing.T) {
	// A Tenable export given to the Qualys adapter has no Qualys header.
	files := copyFixtures(t, "tenable", "nessus-export.csv")
	a, _ := newAdapter(t, scanexport.QualysName, on)
	if _, err := a.Sync(context.Background(), config("qualys", files), ""); err == nil || !strings.Contains(err.Error(), "no header row") {
		t.Fatalf("error %v", err)
	}
	b := config("qualys", files)
	b.Settings["max_file_bytes"] = "1024"
	if _, err := a.Sync(context.Background(), b, ""); err == nil || !strings.Contains(err.Error(), "max_file_bytes") {
		t.Fatalf("size limit: %v", err)
	}
	if _, err := a.Sync(context.Background(), config("qualys", []string{"/nonexistent/export.csv"}), ""); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestValidate(t *testing.T) {
	a, _ := newAdapter(t, scanexport.TenableName, on)
	for name, files := range map[string]string{"none": "", "relative": "exports/a.csv", "glob": "/exports/*.csv"} {
		if err := a.Validate(adapter.Config{Name: "x", Adapter: "tenable", Settings: map[string]string{"files": files}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := a.Validate(adapter.Config{Name: "x", Adapter: "tenable", Settings: map[string]string{"files": "/exports/a.csv", "max_file_bytes": "1"}}); err == nil {
		t.Error("tiny max_file_bytes accepted")
	}
}
