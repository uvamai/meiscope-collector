// Package fsutil holds small durable-file helpers.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Seams for the tests, which inject failures that cannot be provoked portably.
var (
	createTemp = os.CreateTemp
	syncFile   = func(f *os.File) error { return f.Sync() }
)

// WriteFileAtomic writes b to path durably: a temporary file in the same
// directory is written, synced and renamed over path, so a crash leaves
// either the old or the new content, never a torn file.
func WriteFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := createTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, werr := tmp.Write(b)
	serr := syncFile(tmp)
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
