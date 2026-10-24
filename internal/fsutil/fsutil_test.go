package fsutil

import (
	"os"
	"path/filepath"
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
