package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "f.json")
	for _, s := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(s)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p) //nolint:gosec // test-only, synthetic value
		if err != nil || string(b) != s {
			t.Fatalf("read %q, %v", b, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

func TestWriteFileAtomicErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent "directory" is a file.
	if err := WriteFileAtomic(filepath.Join(file, "child"), []byte("y")); err == nil {
		t.Fatal("wrote below a file")
	}
	// The target is a directory: the rename fails and no temporary file is left.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "inner"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("z")); err == nil {
		t.Fatal("replaced a non-empty directory")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".target-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestWriteFileAtomicInjectedFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := WriteFileAtomic(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	oldSync, oldCreate := syncFile, createTemp
	defer func() { syncFile, createTemp = oldSync, oldCreate }()

	syncFile = func(*os.File) error { return os.ErrInvalid }
	if err := WriteFileAtomic(path, []byte("new")); err == nil {
		t.Fatal("a failed sync was ignored")
	}
	syncFile = oldSync
	createTemp = func(string, string) (*os.File, error) { return nil, os.ErrPermission }
	if err := WriteFileAtomic(path, []byte("new")); err == nil {
		t.Fatal("a failed temp file was ignored")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" { //nolint:gosec // test file
		t.Fatalf("the old content was lost: %q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}
