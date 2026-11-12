package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

type staticCreds map[string]string

func (s staticCreds) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := s[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

func adapterTestDeps(creds staticCreds) adapterDeps {
	return adapterDeps{
		clk:   clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)),
		creds: func(func(string) string) credential.Source { return creds },
	}
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func repoFile(elem ...string) string {
	return filepath.Join(append([]string{"..", ".."}, elem...)...)
}

// writeConfig writes an adapter configuration for the recorded Linux direct output.
func writeConfig(t *testing.T) string {
	t.Helper()
	files := []string{
		repoFile("testdata", "adapters", "osquery", "direct", "direct-meiscope_certificates_posix.json"),
		repoFile("testdata", "adapters", "osquery", "direct", "direct-meiscope_keystores_posix.json"),
		repoFile("testdata", "adapters", "osquery", "direct", "direct-meiscope_keystore_counts_posix.json"),
	}
	cfg := []adapter.Config{{
		Name: "osq", Adapter: "osquery",
		Settings: map[string]string{"mode": "direct", "host": "app01.example.test", "files": strings.Join(files, ",")},
	}}
	b, _ := json.Marshal(cfg)
	p := filepath.Join(t.TempDir(), "adapters.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdapterList(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"adapter", "list"}, &out, &errb, envOf(nil))
	if code != 0 || !strings.Contains(out.String(), "osquery") || !strings.Contains(out.String(), "credential: api_token") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	for _, name := range []string{"kubernetes\t", "x509-certificate-exporter\t", "qualys\t", "tenable\t"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("adapter list lacks %q", name)
		}
	}
	for _, args := range [][]string{{"adapter"}, {"adapter", "nope"}, {"adapter", "run"}, {"adapter", "run", "--config", "/missing.json"}} {
		out.Reset()
		errb.Reset()
		if code := run(context.Background(), args, &out, &errb, envOf(nil)); code == 0 {
			t.Errorf("%v: exit 0", args)
		}
	}
	out.Reset()
	if code := run(context.Background(), []string{"adapter", "help"}, &out, &errb, envOf(nil)); code != 0 || !strings.Contains(out.String(), "run --config") {
		t.Fatalf("help: %d", code)
	}
}

func TestAdapterRunDryRunWritesValidBatch(t *testing.T) {
	var out, errb bytes.Buffer
	err := adapterCmd(context.Background(), []string{"run", "--config", writeConfig(t)}, &out, &errb, envOf(map[string]string{"MEISCOPE_LOG_FORMAT": "text", "MEISCOPE_FEATURE_LOCAL_STORE_V1": "true"}), adapterTestDeps(nil))
	if err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	spec, err := submittest.LoadSpec(submittest.ProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate("ObservationBatch", out.Bytes()); err != nil {
		t.Fatalf("dry-run output is not a valid batch: %v", err)
	}
	if !strings.Contains(errb.String(), "MEISCOPE_CORE_URL is not set") {
		t.Fatalf("no dry-run warning: %s", errb.String())
	}
}

func TestLoadAdapterConfigs(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		_ = os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	good := `[{"name":"a","adapter":"osquery","settings":{"mode":"logsink","dir":"/var/log/osquery"}},{"name":"b","adapter":"osquery","settings":{"mode":"logsink","dir":"/var/log/osquery"}}]`
	if got, err := loadAdapterConfigs(write(good), []string{"b"}); err != nil || len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("%v %v", got, err)
	}
	for name, doc := range map[string]string{ //nolint:gosec // test-only, synthetic value
		"not an array": `{}`,
		"duplicate":    `[{"name":"a","adapter":"x"},{"name":"a","adapter":"x"}]`,
		"secret":       `[{"name":"a","adapter":"x","settings":{"api_token":"abcdef123456"}}]`,
	} {
		if _, err := loadAdapterConfigs(write(doc), nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "abcdef123456") {
			t.Errorf("%s: value in error: %v", name, err)
		}
	}
	if _, err := loadAdapterConfigs(write(good), []string{"zzz"}); err == nil {
		t.Error("unknown instance accepted")
	}
}

// TestAdapterRunBuffersWhileCoreIsDownAndReplays runs the command twice: the
// core is down during the first run (observations stay in the buffer), up
// during the second (they arrive, once).
func TestAdapterRunBuffersWhileCoreIsDownAndReplays(t *testing.T) {
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pemCert(core.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	state := t.TempDir()
	env := map[string]string{
		"MEISCOPE_CORE_URL":               core.URL,
		"MEISCOPE_CA_BUNDLE":              ca,
		"MEISCOPE_BUFFER_DIR":             filepath.Join(state, "buffer"),
		"MEISCOPE_ADAPTER_STATE_FILE":     filepath.Join(state, "cursors.json"),
		"MEISCOPE_LOG_FORMAT":             "text",
		"MEISCOPE_FEATURE_LOCAL_STORE_V1": "true",
	}
	deps := adapterTestDeps(staticCreds{"buffer_key": key})
	cfg := writeConfig(t)

	failures := make([]int, 40)
	for i := range failures {
		failures[i] = http.StatusServiceUnavailable
	}
	core.FailNext(failures...)
	var out, errb bytes.Buffer
	if err := adapterCmd(context.Background(), []string{"run", "--config", cfg}, &out, &errb, envOf(env), deps); err == nil {
		t.Fatal("run succeeded while the core was down")
	}
	if len(core.Batches()) != 0 {
		t.Fatal("batches reached a failing core")
	}
	if !strings.Contains(errb.String(), "buffer_depth=125") {
		t.Fatalf("heartbeat does not report the buffer depth:\n%s", errb.String())
	}
	if _, err := os.Stat(filepath.Join(state, "cursors.json")); err != nil {
		t.Fatalf("cursor not saved after the observations were buffered: %v", err)
	}

	core.FailNext() // the queued failures are consumed or cleared by the next request; reset by draining
	errb.Reset()
	drain(core)
	if err := adapterCmd(context.Background(), []string{"run", "--config", cfg}, &out, &errb, envOf(env), deps); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	total := 0
	for _, raw := range core.Batches() {
		total += strings.Count(string(raw), `"method":"adapter"`)
	}
	if total != 125 || len(core.Rejected()) != 0 {
		t.Fatalf("core holds %d observations (want 125 exactly once), rejected %v", total, core.Rejected())
	}
	if !strings.Contains(errb.String(), "buffer_depth=0") {
		t.Fatalf("heartbeat after recovery:\n%s", errb.String())
	}
	// The unchanged outputs are not read again: nothing new is submitted.
	errb.Reset()
	if err := adapterCmd(context.Background(), []string{"run", "--config", cfg}, &out, &errb, envOf(env), deps); err != nil {
		t.Fatal(err)
	}
	if n := len(core.Batches()); n != 1 {
		t.Fatalf("third run changed the batch count to %d", n)
	}
}

// drain consumes any forced failures left in the fake core.
func drain(core *submittest.Core) {
	cl, _ := submit.New(core.URL, core.Client(), submit.WithRetry(submitNoRetry))
	for i := 0; i < 50; i++ {
		_, err := cl.OwnedDomains(context.Background())
		if err == nil {
			return
		}
	}
}

func TestBufferKeyProblemsNameNoValue(t *testing.T) {
	core, _ := submittest.NewProposedCore()
	defer core.Close()
	env := map[string]string{"MEISCOPE_CORE_URL": core.URL, "MEISCOPE_BUFFER_DIR": t.TempDir(), "MEISCOPE_LOG_FORMAT": "text"}
	cfg := writeConfig(t)
	var out, errb bytes.Buffer
	for name, creds := range map[string]staticCreds{"missing": {}, "short": {"buffer_key": "c2VjcmV0LXNob3J0LXZhbHVl"}, "not base64": {"buffer_key": "!!secret-key-material!!"}} {
		err := adapterCmd(context.Background(), []string{"run", "--config", cfg}, &out, &errb, envOf(env), adapterTestDeps(creds))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, leak := range []string{"secret-key-material", "c2VjcmV0LXNob3J0LXZhbHVl", "secret-short-value"} {
			if strings.Contains(err.Error(), leak) || strings.Contains(errb.String(), leak) {
				t.Errorf("%s: key material in output", name)
			}
		}
	}
}

// TestFixturesHoldNoSecrets is the credential leak test (WP1.1): no
// fixture, pack or configuration example under the adapter test data
// contains key material or tokens.
func TestFixturesHoldNoSecrets(t *testing.T) {
	roots := []string{repoFile("testdata", "adapters"), repoFile("packs")}
	n := 0
	for _, root := range roots {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, err := os.ReadFile(filepath.Clean(p)) //nolint:gosec // test walks the repository fixtures
			if err != nil {
				return err
			}
			n++
			if hits := adapter.FindSecrets(b); len(hits) > 0 {
				t.Errorf("%s matches secret patterns %v", p, hits)
			}
			if bytes.Contains(b, []byte("-----BEGIN")) {
				t.Errorf("%s contains PEM armour", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 15 {
		t.Fatalf("only %d files scanned; paths wrong?", n)
	}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var submitNoRetry = retry.Policy{Attempts: 0}
