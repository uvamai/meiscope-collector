package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
)

func enrolEnv(core *enroltest.Core, dir string) func(string) string {
	env := map[string]string{
		"MEISCOPE_CORE_URL":  core.URL,
		"MEISCOPE_CA_BUNDLE": core.CAFile(dir),
		envStateDir:          filepath.Join(dir, "state"),
		envCollectorName:     enroltest.Name,
	}
	return func(k string) string { return env[k] }
}

func runEnrol(t *testing.T, getenv func(string) string, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	deps := defaultEnrolDeps()
	deps.stdin = strings.NewReader(stdin)
	deps.platform = func() enrol.Platform { return enroltest.Platform }
	err = enrolCmd(context.Background(), args, &out, &errb, getenv, deps)
	return out.String(), errb.String(), err
}

func TestEnrolCommandEndToEnd(t *testing.T) {
	core := enroltest.NewCore(t)
	dir := t.TempDir()
	getenv := enrolEnv(core, dir)
	const token = "mse1_cmd_secret_token" //nolint:gosec // a fake token for the fake core

	out, errOut, err := runEnrol(t, getenv, token+"\n", "--token-file", "-")
	if err != nil {
		t.Fatalf("enrol: %v (stderr %q)", err, errOut)
	}
	if !strings.Contains(out, "enrolled as collector "+enroltest.CollectorID) {
		t.Fatalf("stdout %q", out)
	}
	if strings.Contains(out+errOut, token) {
		t.Fatal("the token was printed")
	}
	s, err := identity.Load(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if s.CollectorID() != enroltest.CollectorID || s.CoreURL() != core.URL {
		t.Fatalf("stored identity %s at %s", s.CollectorID(), s.CoreURL())
	}

	// A second enrolment into the same directory is refused, before any
	// token is spent.
	before := core.Requests("/collector/v1/enrol")
	_, _, err = runEnrol(t, getenv, "", "--token", "mse1_another")
	if err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("second enrol: %v", err)
	}
	if core.Requests("/collector/v1/enrol") != before {
		t.Fatal("a token was sent although the collector is already enrolled")
	}
}

func TestEnrolCommandErrors(t *testing.T) {
	core := enroltest.NewCore(t)
	dir := t.TempDir()
	getenv := enrolEnv(core, dir)

	_, _, err := runEnrol(t, getenv, "", "--token", enroltest.TokenUsed)
	if err == nil || !strings.Contains(err.Error(), "invalid, expired or already used") {
		t.Fatalf("used token: %v", err)
	}
	_, _, err = runEnrol(t, getenv, "", "--token", "a", "--token-file", "-")
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both token flags: %v", err)
	}
	noCore := func(k string) string {
		if k == "MEISCOPE_CORE_URL" {
			return ""
		}
		return getenv(k)
	}
	_, _, err = runEnrol(t, noCore, "", "--token", "mse1_z")
	if err == nil || !strings.Contains(err.Error(), "MEISCOPE_CORE_URL") {
		t.Fatalf("no core URL: %v", err)
	}
	// Without the core's CA the first contact fails: the token is not sent
	// to a server the collector cannot verify.
	noCA := func(k string) string {
		if k == "MEISCOPE_CA_BUNDLE" {
			return ""
		}
		return getenv(k)
	}
	before := core.Requests("/collector/v1/enrol")
	if _, _, err = runEnrol(t, noCA, "", "--token", "mse1_w"); err == nil {
		t.Fatal("enrolled without trusting the core")
	}
	if core.Requests("/collector/v1/enrol") != before {
		t.Fatal("the token reached a core the collector could not verify")
	}
}

// AC-G3-13: a token file that group or others can read is refused before any
// request; a 0600 file works and is gone after a successful enrolment.
func TestEnrolTokenFileModeAndWipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	core := enroltest.NewCore(t)
	dir := t.TempDir()
	getenv := enrolEnv(core, dir)
	tokPath := filepath.Join(dir, "token")
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if err := os.WriteFile(tokPath, []byte("mse1_filemode\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(tokPath, mode); err != nil {
			t.Fatal(err)
		}
		before := core.Requests("/collector/v1/enrol")
		_, _, err := runEnrol(t, getenv, "", "--token-file", tokPath)
		if err == nil || !strings.Contains(err.Error(), "readable by group or others") {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		if strings.Contains(err.Error(), "mse1_filemode") {
			t.Fatal("error shows the token")
		}
		if core.Requests("/collector/v1/enrol") != before {
			t.Fatalf("mode %04o: a request was sent", mode)
		}
		if _, serr := os.Stat(tokPath); serr != nil {
			t.Fatalf("a refused file was removed: %v", serr)
		}
	}
	// Positive control: the same file at 0600 enrols, and is gone.
	if err := os.Chmod(tokPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, err := runEnrol(t, getenv, "", "--token-file", tokPath); err != nil {
		t.Fatalf("0600: %v (%s)", err, errOut)
	}
	if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
		t.Fatalf("token file still there: %v", err)
	}
}

func TestEnrolKeepsTokenFileWhenRefused(t *testing.T) {
	core := enroltest.NewCore(t)
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte(enroltest.TokenUsed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runEnrol(t, enrolEnv(core, dir), "", "--token-file", tokPath); err == nil {
		t.Fatal("enrolled with a refused token")
	}
	if _, err := os.Stat(tokPath); err != nil {
		t.Fatalf("file removed after a failed enrolment: %v", err)
	}
}

func TestWipeFileZeroesThenRemoves(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t")
	if err := os.WriteFile(p, []byte("secret-code"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep a handle so the zeroed content can be observed before removal.
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if runtime.GOOS == "windows" {
		t.Skip("cannot remove an open file")
	}
	if err := wipeFile(p); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	if len(b) != len("secret-code") || bytes.Trim(b, "\x00") != nil && len(bytes.Trim(b, "\x00")) != 0 {
		t.Fatalf("content after wipe: %q", b)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
}

// AC-G3-14: a core whose certificate comes from a CA the system trusts but
// the bundle does not is refused at the handshake; no code is sent.
func TestEnrolPinsTheBundleNotTheSystemRoots(t *testing.T) {
	core := enroltest.NewCore(t)
	other := enroltest.NewCore(t) // a second CA: stands in for a system-trusted one
	dir := t.TempDir()
	getenv := enrolEnv(core, dir)
	wrongBundle := other.CAFile(t.TempDir())
	env := func(k string) string {
		if k == "MEISCOPE_CA_BUNDLE" {
			return wrongBundle
		}
		return getenv(k)
	}
	before := core.Requests("/collector/v1/enrol")
	if _, _, err := runEnrol(t, env, "", "--token", "mse1_pin"); err == nil {
		t.Fatal("enrolled against a CA outside the bundle")
	}
	if core.Requests("/collector/v1/enrol") != before {
		t.Fatal("the token reached a core outside the bundle")
	}
}

func TestEnrolRefusesBadNameOrPackage(t *testing.T) {
	core := enroltest.NewCore(t)
	dir := t.TempDir()
	getenv := enrolEnv(core, dir)
	for _, name := range []string{"", "Bad Name", "-lead", strings.Repeat("a", 64)} {
		env := func(k string) string {
			if k == envCollectorName {
				return name
			}
			return getenv(k)
		}
		if _, _, err := runEnrol(t, env, "", "--token", "mse1_n"); err == nil || !strings.Contains(err.Error(), "collector name") {
			t.Errorf("name %q: %v", name, err)
		}
	}
	// A hand-built binary has no package and cannot enrol.
	var out, errb bytes.Buffer
	deps := defaultEnrolDeps()
	deps.platform = func() enrol.Platform { return enrol.Platform{OS: "linux", Arch: "amd64", Version: "dev"} }
	err := enrolCmd(context.Background(), []string{"--token", "mse1_p"}, &out, &errb, getenv, deps)
	if err == nil || !strings.Contains(err.Error(), "not built as a Meiscope package") {
		t.Fatalf("no package: %v", err)
	}
	if core.Requests("/collector/v1/enrol") != 0 {
		t.Fatal("a request was sent")
	}
}
