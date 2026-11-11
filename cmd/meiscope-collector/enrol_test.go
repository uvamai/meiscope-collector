package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
)

func enrolEnv(core *enroltest.Core, dir string) func(string) string {
	env := map[string]string{
		"MEISCOPE_CORE_URL":  core.URL,
		"MEISCOPE_CA_BUNDLE": core.CAFile(dir),
		envStateDir:          filepath.Join(dir, "state"),
	}
	return func(k string) string { return env[k] }
}

func runEnrol(t *testing.T, getenv func(string) string, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	deps := defaultEnrolDeps()
	deps.stdin = strings.NewReader(stdin)
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
