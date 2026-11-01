package osquery

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxWindowsRootDepth is how many directory levels below a Windows root are
// searched. A file directly in the root is at depth 1.
const MaxWindowsRootDepth = 4

// MaxExtraWindowsRoots caps the customer-configured Windows roots.
const MaxExtraWindowsRoots = 10

// windowsRoot is one targeted folder of the Windows keystore search. base is
// an osquery path pattern for the folder itself: % stands for one directory
// name (or, as in OpenSSL%, a name prefix).
type windowsRoot struct {
	id   string
	base string
}

// defaultWindowsRoots are the common application folders searched on every
// Windows host. There is deliberately no whole-drive or whole-Program-Files
// walk: osquery lists a directory tree before it applies NOT LIKE, so a wide
// root costs minutes on a real server.
var defaultWindowsRoots = []windowsRoot{
	{"inetpub", `C:\inetpub`},
	{"java_security", `C:\Program Files\Java\%\lib\security`},
	{"adoptium_security", `C:\Program Files\Eclipse Adoptium\%\lib\security`},
	{"apache_conf", `C:\Program Files\Apache Software Foundation\%\conf`},
	{"programdata_ssl", `C:\ProgramData\ssl`},
	{"openssl", `C:\OpenSSL%`},
}

// windowsRoots returns the default roots followed by the extra ones, which
// are named extra1, extra2, ... in the order given.
func windowsRoots(extra []string) []windowsRoot {
	out := append([]windowsRoot(nil), defaultWindowsRoots...)
	for i, p := range extra {
		out = append(out, windowsRoot{id: "extra" + strconv.Itoa(i+1), base: strings.TrimRight(p, `\`)})
	}
	return out
}

// patterns expands a root to one pattern per depth, 1 to MaxWindowsRootDepth.
func (r windowsRoot) patterns() []string {
	out := make([]string, MaxWindowsRootDepth)
	p := r.base
	for i := range out {
		p += `\%`
		out[i] = p
	}
	return out
}

// Windows query names: the prefix plus the root id.
const (
	windowsKeystoresPrefix = "meiscope_keystores_windows_"
	windowsCountsPrefix    = "meiscope_keystore_counts_windows_"
)

// WindowsKeystoreQuery is the name of the keystore query of a Windows root.
func WindowsKeystoreQuery(rootID string) string { return windowsKeystoresPrefix + rootID }

// WindowsCountsQuery is the name of the counts query of a Windows root.
func WindowsCountsQuery(rootID string) string { return windowsCountsPrefix + rootID }

// WindowsRootIDs lists the ids of the default roots.
func WindowsRootIDs() []string {
	out := make([]string, len(defaultWindowsRoots))
	for i, r := range defaultWindowsRoots {
		out[i] = r.id
	}
	return out
}

// windowsQueryKind splits a Windows keystore or counts query name into its
// kind and root id. ok is false for any other name.
func windowsQueryKind(name string) (counts bool, rootID string, ok bool) {
	switch {
	case strings.HasPrefix(name, windowsKeystoresPrefix):
		rootID = strings.TrimPrefix(name, windowsKeystoresPrefix)
	case strings.HasPrefix(name, windowsCountsPrefix):
		counts, rootID = true, strings.TrimPrefix(name, windowsCountsPrefix)
	default:
		return false, "", false
	}
	return counts, rootID, rootIDPattern.MatchString(rootID)
}

var rootIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

var (
	windowsRootPath = regexp.MustCompile(`^[A-Za-z]:(\\[A-Za-z0-9 _.()+-]+)+$`)
	// blockedRootParts are folder names that hold private keys, credentials
	// or the operating system's own key stores.
	blockedRootParts = map[string]bool{
		".ssh": true, ".gnupg": true, ".aws": true, ".azure": true, ".kube": true,
		"crypto": true, "systemcertificates": true, "protect": true, "credentials": true,
		"vault": true, "machinekeys": true,
	}
	// blockedRootPaths are folders whose whole tree is too wide or too
	// sensitive to search, matched without the drive letter.
	blockedRootPaths = []string{`\users`, `\windows`, `\program files`, `\program files (x86)`, `\programdata`}
)

// ValidateWindowsRoot checks a customer-configured Windows root. It must be
// an absolute path with a drive letter and plain folder names (no wildcards,
// quotes or separators other than a backslash). It must not be a drive root,
// a whole profile folder, the Windows, Program Files or ProgramData tree, or
// a folder that holds private keys (.ssh, .gnupg, Crypto, Protect, ...).
func ValidateWindowsRoot(p string) error {
	q := strings.TrimRight(p, `\`)
	if len(q) > 240 {
		return fmt.Errorf("%q is longer than 240 characters", p)
	}
	if len(q) == 0 || (len(q) == 2 && q[1] == ':') {
		return fmt.Errorf("%q is a drive root; name a folder", p)
	}
	if !windowsRootPath.MatchString(q) {
		return fmt.Errorf(`%q must be an absolute path such as D:\Apps\tls using plain folder names (letters, digits, space and _ . ( ) + -)`, p)
	}
	parts := strings.Split(q[3:], `\`)
	low := make([]string, len(parts))
	for i, c := range parts {
		low[i] = strings.ToLower(c)
		if c == "." || c == ".." || c != strings.TrimSpace(c) || strings.HasSuffix(c, ".") {
			return fmt.Errorf("%q has an invalid folder name %q", p, c)
		}
		if blockedRootParts[low[i]] {
			return fmt.Errorf("%q is not allowed: %s holds private keys or credentials", p, c)
		}
	}
	rest := `\` + strings.Join(low, `\`)
	for _, b := range blockedRootPaths {
		if rest == b {
			return fmt.Errorf("%q is too wide to search; name a folder inside it", p)
		}
	}
	if low[0] == "users" && len(low) <= 2 {
		return fmt.Errorf("%q is a user profile; name an application folder instead", p)
	}
	if low[0] == "windows" {
		return fmt.Errorf("%q is inside the Windows folder, which is not searched", p)
	}
	return nil
}
