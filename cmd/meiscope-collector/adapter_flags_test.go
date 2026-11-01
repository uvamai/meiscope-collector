package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
)

func TestAdapterRunFlagOffSendsNothingAndSaysSo(t *testing.T) {
	var out, errb bytes.Buffer
	err := adapterCmd(context.Background(), []string{"run", "--config", writeConfig(t)}, &out, &errb, envOf(map[string]string{"MEISCOPE_LOG_FORMAT": "text"}), adapterTestDeps(nil))
	if err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("observations were written with the feature off:\n%s", out.String())
	}
	log := errb.String()
	for _, want := range []string{"MEISCOPE_FEATURE_LOCAL_STORE_V1 is off", "skipped_feature_disabled=125", "skipped_excluded=122", "skipped_oversize=1", "skipped_limit=0"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	var bad bytes.Buffer
	if err := adapterCmd(context.Background(), []string{"run", "--config", writeConfig(t)}, &out, &bad, envOf(map[string]string{"MEISCOPE_FEATURE_LOCAL_STORE_V1": "maybe"}), adapterTestDeps(nil)); err == nil {
		t.Fatal("a bad feature flag was accepted")
	}
}

func TestLimitsAboveCeilingsAreRejectedAtConfigLoad(t *testing.T) {
	for _, tc := range []struct{ key, val string }{{"keystore_max_bytes", "104857601"}, {"keystore_max_files", "10001"}} {
		cfg := []adapter.Config{{Name: "osq", Adapter: "osquery", Settings: map[string]string{"mode": "logsink", "dir": "/var/log/osquery", tc.key: tc.val}}}
		b, _ := json.Marshal(cfg)
		p := filepath.Join(t.TempDir(), "c.json")
		_ = os.WriteFile(p, b, 0o600)
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"adapter", "run", "--config", p}, &out, &errb, envOf(nil))
		if code != 1 || !strings.Contains(errb.String(), "ceiling") || !strings.Contains(errb.String(), tc.key) {
			t.Errorf("%s=%s: exit %d, %s", tc.key, tc.val, code, errb.String())
		}
	}
}

func TestAdapterPackCommand(t *testing.T) {
	var out, errb bytes.Buffer
	deps := adapterTestDeps(nil)
	if err := adapterCmd(context.Background(), []string{"pack"}, &out, &errb, envOf(nil), deps); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(repoFile("packs", "osquery", "meiscope.conf"))
	if err != nil || !bytes.Equal(out.Bytes(), disk) {
		t.Fatalf("`adapter pack` differs from packs/osquery/meiscope.conf (%v)", err)
	}
	out.Reset()
	if err := adapterCmd(context.Background(), []string{"pack", "--format", "fleet", "--max-files", "10000", "--max-file-bytes", "104857600"}, &out, &errb, envOf(nil), deps); err != nil || !strings.Contains(out.String(), "LIMIT 10000") {
		t.Fatalf("fleet at the ceilings: %v", err)
	}
	out.Reset()
	if err := adapterCmd(context.Background(), []string{"pack", "--query", "meiscope_keystores_posix"}, &out, &errb, envOf(nil), deps); err != nil || !strings.HasPrefix(out.String(), "SELECT f.path") {
		t.Fatalf("--query: %v %q", err, out.String())
	}
	for _, args := range [][]string{{"pack", "--max-files", "10001"}, {"pack", "--max-file-bytes", "104857601"}, {"pack", "--format", "xml"}, {"pack", "--query", "nope"}, {"pack", "extra"}} {
		if err := adapterCmd(context.Background(), args, &out, &errb, envOf(nil), deps); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
