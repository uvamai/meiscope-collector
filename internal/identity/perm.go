package identity

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// checkPerm refuses path, on systems with POSIX permissions, when it is not
// owned by the user running the collector (or root), or when its mode has
// any of the bits in deny. Windows is skipped: its ACLs are not mode bits
// (finding M10, deferred).
//
// Load uses it so that another local user cannot plant a CA bundle, scope
// keys or a core URL that the collector would then trust: every file in the
// state directory must not be group- or world-writable, identity.pem must
// not be readable by them either, and the directory must not be writable by
// them (they could otherwise swap files by rename).
func checkPerm(path string, deny fs.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if m := st.Mode().Perm(); m&deny != 0 {
		return fmt.Errorf("%s has mode %v, which lets other users change it; run chmod %s (0700 for the directory, 0600 for its files)", path, m, wantMode(st))
	}
	if uid, ok := fileOwner(st); ok && uid != os.Geteuid() && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not by the collector's user (uid %d) or root; refusing to trust it", path, uid, os.Geteuid())
	}
	return nil
}

func wantMode(st fs.FileInfo) string {
	if st.IsDir() {
		return "0700"
	}
	return "0600"
}

// Modes refused by Load.
const (
	denyOthersWrite = fs.FileMode(0o022) // group or world writable
	denyOthersAny   = fs.FileMode(0o077) // any access by group or world
)
