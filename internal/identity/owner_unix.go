//go:build !windows

package identity

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the uid owning the file, when the platform reports it.
func fileOwner(st fs.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), true //nolint:gosec // a uid is a uint32 and fits in int on every supported platform (64-bit)
	}
	return 0, false
}
