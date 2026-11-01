package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary builds the collector with the given tags into a temp dir. An
// empty tags string is the release build (default tags).
func buildBinary(t *testing.T, tags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "collector.exe")
	args := []string{"build", "-trimpath"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "-o", out, ".")
	cmd := exec.Command("go", args...) //nolint:gosec // test builds the package under test
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func runBinary(t *testing.T, bin string, env []string, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...) //nolint:gosec // the binary was built by this test
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), env...)
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return o.String(), e.String(), code
}

// TestReleaseBuildRefusesDevCredentials proves that a build with default
// tags has no environment credential source: with a development variable
// set, every working command refuses to start and says why, and the value
// never appears.
func TestReleaseBuildRefusesDevCredentials(t *testing.T) {
	bin := buildBinary(t, "")
	env := []string{"MEISCOPE_DEV_CREDENTIAL_CERTSPOTTER_API_KEY=synthetic-dev-secret-value"}
	for _, args := range [][]string{{"ct-poll"}, {"adapter", "list"}, {"run"}} {
		out, errOut, code := runBinary(t, bin, env, "", args...)
		if code != 1 || !strings.Contains(errOut, "no development credential source") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
		if strings.Contains(out+errOut, "synthetic-dev-secret-value") {
			t.Errorf("%v: the value is in the output", args)
		}
	}
	if out, _, code := runBinary(t, bin, env, "", "version"); code != 0 || !strings.Contains(out, "meiscope-collector") {
		t.Errorf("version: exit %d %q", code, out)
	}
	if _, errOut, code := runBinary(t, bin, nil, "", "adapter", "list"); code != 0 {
		t.Errorf("adapter list without the variable: exit %d %s", code, errOut)
	}
}

// TestDevBuildAcceptsDevCredentials is the counterpart: the devcredentials
// tag turns the guard off.
func TestDevBuildAcceptsDevCredentials(t *testing.T) {
	bin := buildBinary(t, "devcredentials")
	env := []string{"MEISCOPE_DEV_CREDENTIAL_CERTSPOTTER_API_KEY=synthetic-dev-secret-value"}
	if _, errOut, code := runBinary(t, bin, env, "", "adapter", "list"); code != 0 {
		t.Errorf("dev build refused: exit %d %s", code, errOut)
	}
}

// TestCredentialCommandInReleaseBuild: the encrypted file source works in
// the release build, end to end through the command, with the value only
// on stdin.
func TestCredentialCommandInReleaseBuild(t *testing.T) {
	bin := buildBinary(t, "")
	dir := t.TempDir()
	env := []string{"MEISCOPE_CREDENTIAL_FILE=" + filepath.Join(dir, "c.age"), "MEISCOPE_CREDENTIAL_KEY_FILE=" + filepath.Join(dir, "id.txt")}
	if _, e, code := runBinary(t, bin, env, "", "credential", "init"); code != 0 {
		t.Fatalf("init: %d %s", code, e)
	}
	o, e, code := runBinary(t, bin, env, "synthetic-fleet-token\n", "credential", "set", "fleet_api_token")
	if code != 0 || strings.Contains(o+e, "synthetic-fleet-token") {
		t.Fatalf("set: %d %s %s", code, o, e)
	}
	out, _, code := runBinary(t, bin, env, "", "credential", "list")
	if code != 0 || strings.TrimSpace(out) != "fleet_api_token" {
		t.Fatalf("list: %d %q", code, out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "c.age")) //nolint:gosec // test-only
	if bytes.Contains(raw, []byte("synthetic-fleet-token")) {
		t.Fatal("plaintext in the credential file")
	}
	if _, e, code := runBinary(t, bin, nil, "", "credential", "list"); code == 0 || !strings.Contains(e, "MEISCOPE_CREDENTIAL_FILE") {
		t.Fatalf("unconfigured: %d %s", code, e)
	}
}
