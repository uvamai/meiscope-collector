package osquery_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// TestWindowsPackRun checks real osqueryi output of the pack's Windows
// queries. It is driven by .github/workflows/windows-osquery.yml, which sets:
//
//	MEISCOPE_WINDOWS_OSQUERY_DIR      directory with web01-<query>.json outputs
//	MEISCOPE_WINDOWS_CERT_THUMBPRINT  SHA-1 of the test certificate (hex)
//	MEISCOPE_WINDOWS_PFX_PATH         path of the test .pfx
//	MEISCOPE_WINDOWS_PFX_PASSWORD     its password (must appear nowhere)
//
// Without them the test is skipped.
func TestWindowsPackRun(t *testing.T) {
	dir := os.Getenv("MEISCOPE_WINDOWS_OSQUERY_DIR")
	if dir == "" {
		t.Skip("MEISCOPE_WINDOWS_OSQUERY_DIR is not set; this test runs in the Windows CI job")
	}
	thumb := strings.ToLower(os.Getenv("MEISCOPE_WINDOWS_CERT_THUMBPRINT"))
	pfx := os.Getenv("MEISCOPE_WINDOWS_PFX_PATH")
	password := os.Getenv("MEISCOPE_WINDOWS_PFX_PASSWORD")
	if thumb == "" || pfx == "" || password == "" {
		t.Fatal("the thumbprint, the pfx path and the pfx password must be set")
	}
	// Every Windows query of the pack wrote web01-<query>.json: the certificate
	// stores, and a keystore and a counts query for each root.
	files, err := filepath.Glob(filepath.Join(dir, "web01-meiscope_*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no web01-meiscope_*.json outputs in %s (%v)", dir, err)
	}
	env, _ := newEnv(t, nil)
	cfg := adapter.Config{Name: "win", Adapter: osquery.Name, Settings: map[string]string{
		"mode": "direct", "host": "web01.example.test", "files": strings.Join(files, ","),
	}}
	res := syncOK(t, newAdapter(env), cfg, "")

	var cert, keystore bool
	for _, o := range res.Observations {
		switch o.Target.Kind {
		case submit.KindStore:
			if o.Target.Store == "windows/LocalMachine/My" && o.Adapter.Certificate.SHA1 == thumb {
				cert = o.Adapter.Certificate.CommonName == "web01.example.test"
			}
		case submit.KindFile:
			if strings.EqualFold(o.Target.Path, pfx) {
				st, err := os.Stat(pfx) //nolint:gosec // the CI job passes the path of the file it created
				keystore = err == nil && o.Adapter.File.Size != nil && *o.Adapter.File.Size == st.Size() &&
					o.Adapter.File.StoreType == submit.StorePKCS12 && len(o.Adapter.Findings) == 1 &&
					o.Adapter.Findings[0].Code == submit.FindingKeystoreNotParsed
			}
		}
	}
	if !cert {
		t.Errorf("the LocalMachine\\My test certificate %s was not reported (%d observations)", thumb, len(res.Observations))
	}
	if !keystore {
		t.Errorf("the test keystore %s was not reported as an encrypted store with its size", pfx)
	}
	// Decoys below the depth limit and outside every root must not appear.
	for _, decoy := range strings.Split(os.Getenv("MEISCOPE_WINDOWS_DECOYS"), ",") {
		for _, o := range res.Observations {
			if decoy != "" && strings.EqualFold(o.Target.Path, decoy) {
				t.Errorf("%s was reported, but it is outside the targeted roots or deeper than %d levels", decoy, osquery.MaxWindowsRootDepth)
			}
		}
	}
	for _, k := range []string{"skipped_oversize", "skipped_excluded", "skipped_limit"} {
		if _, ok := res.Stats[k]; !ok {
			t.Errorf("stat %s missing", k)
		}
	}
	b, _ := json.Marshal(res.Observations)
	if strings.Contains(string(b), password) {
		t.Error("the PFX password is in the observations")
	}
	t.Logf("Windows run: %d observations, stats %v", len(res.Observations), res.Stats)
	submitAll(t, res.Observations)
}
