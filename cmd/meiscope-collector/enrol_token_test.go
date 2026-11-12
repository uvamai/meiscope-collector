package main

import (
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
)

// TestTokenFlagIsDeprecated: --token still enrols (compatibility) but warns
// and points at --token-file; --token-file does not warn.
func TestTokenFlagIsDeprecated(t *testing.T) {
	const tok = "mse1_deprecated_flag_synthetic" //nolint:gosec // a fake token for the fake core
	core := enroltest.NewCore(t)
	_, errOut, err := runEnrol(t, enrolEnv(core, t.TempDir()), "", "--token", tok)
	if err != nil {
		t.Fatalf("--token: %v", err)
	}
	if !strings.Contains(errOut, "--token is deprecated") || !strings.Contains(errOut, "--token-file") || strings.Contains(errOut, tok) {
		t.Fatalf("stderr %q", errOut)
	}

	core = enroltest.NewCore(t)
	_, errOut, err = runEnrol(t, enrolEnv(core, t.TempDir()), tok+"\n", "--token-file", "-")
	if err != nil {
		t.Fatalf("--token-file: %v", err)
	}
	if strings.Contains(errOut, "deprecated") {
		t.Fatalf("--token-file warned: %q", errOut)
	}
}
