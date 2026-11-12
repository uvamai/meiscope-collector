package identity_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/enrol/enroltest"
	"github.com/uvamai/meiscope-collector/internal/identity"
)

// TestSaveWritesOwnerOnlyFiles: every file of the identity is 0600.
func TestSaveWritesOwnerOnlyFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	_, dir := enrolled(t, enroltest.NewCore(t))
	for _, name := range []string{"identity.pem", "ca.pem", "scope-keys.json", "identity.json"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600", name, st.Mode().Perm())
		}
	}
}

// TestLoadRefusesTrustFilesWritableByOthers: the pinned CA, the scope keys,
// the metadata (core URL) and the directory must not be writable by group or
// world; read access alone (0644, as older versions wrote) is accepted.
func TestLoadRefusesTrustFilesWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	for _, name := range []string{"ca.pem", "scope-keys.json", "identity.json"} {
		for _, mode := range []fs.FileMode{0o664, 0o646, 0o666} {
			_, dir := enrolled(t, enroltest.NewCore(t)) // a fresh core: the fake token is single use
			p := filepath.Join(dir, name)
			if err := os.Chmod(p, mode); err != nil { //nolint:gosec // the test loosens the mode on purpose
				t.Fatal(err)
			}
			if _, err := identity.Load(dir); err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "other users") {
				t.Errorf("%s %v: err %v, want a refusal naming the file", name, mode, err)
			}
			if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // readable by others is accepted for public data
				t.Fatal(err)
			}
			if _, err := identity.Load(dir); err != nil {
				t.Errorf("%s 0644: %v", name, err)
			}
		}
	}
	for _, mode := range []fs.FileMode{0o770, 0o707, 0o777} {
		_, dir := enrolled(t, enroltest.NewCore(t)) // a fresh core: the fake token is single use
		if err := os.Chmod(dir, mode); err != nil { //nolint:gosec // the test loosens the mode on purpose
			t.Fatal(err)
		}
		if _, err := identity.Load(dir); err == nil || !strings.Contains(err.Error(), "0700") {
			t.Errorf("dir %v: err %v, want a refusal naming 0700", mode, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs x; 0700 is owner-only
			t.Fatal(err)
		}
	}
	// identity.pem keeps the stricter rule: no access at all by others.
	_, dir := enrolled(t, enroltest.NewCore(t))                                 // a fresh core: the fake token is single use
	if err := os.Chmod(filepath.Join(dir, "identity.pem"), 0o640); err != nil { //nolint:gosec // the test loosens the mode on purpose
		t.Fatal(err)
	}
	if _, err := identity.Load(dir); err == nil {
		t.Fatal("identity.pem readable by the group was accepted")
	}
}

// TestLoadRefusesFilesOwnedByAnotherUser needs root to hand a file to
// another uid.
func TestLoadRefusesFilesOwnedByAnotherUser(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on a POSIX system to chown")
	}
	_, dir := enrolled(t, enroltest.NewCore(t))
	if err := os.Chown(filepath.Join(dir, "ca.pem"), 54321, 54321); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(dir); err == nil || !strings.Contains(err.Error(), "uid 54321") {
		t.Fatalf("err %v, want a refusal naming the owner", err)
	}
}
