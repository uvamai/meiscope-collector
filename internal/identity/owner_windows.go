//go:build windows

package identity

import "io/fs"

// fileOwner is not used on Windows (checkPerm skips it).
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
