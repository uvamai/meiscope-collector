package osquery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Keystore limits (decision D3). The defaults apply to every scan scope;
// a scope may raise them, never beyond the hard ceilings.
const (
	DefaultMaxFileBytes int64 = 10 << 20
	DefaultMaxFiles           = 1000
	CeilingMaxFileBytes int64 = 100 << 20
	CeilingMaxFiles           = 10000
)

// Limits are the keystore crawl limits and the extra Windows roots of one
// scan scope.
type Limits struct {
	MaxFileBytes int64
	MaxFiles     int
	// ExtraWindowsRoots are customer-configured folders searched in addition
	// to the default Windows roots; see ValidateWindowsRoot.
	ExtraWindowsRoots []string
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{MaxFileBytes: DefaultMaxFileBytes, MaxFiles: DefaultMaxFiles}
}

// Validate rejects values that are not positive or are above the ceilings,
// with an error that names the setting and the ceiling.
func (l Limits) Validate() error {
	if l.MaxFileBytes < 1 || l.MaxFileBytes > CeilingMaxFileBytes {
		return fmt.Errorf("keystore_max_bytes %d is outside 1..%d (the hard ceiling is 100 MiB; the default is 10 MiB)", l.MaxFileBytes, CeilingMaxFileBytes)
	}
	if l.MaxFiles < 1 || l.MaxFiles > CeilingMaxFiles {
		return fmt.Errorf("keystore_max_files %d is outside 1..%d (the hard ceiling is %d; the default is %d)", l.MaxFiles, CeilingMaxFiles, CeilingMaxFiles, DefaultMaxFiles)
	}
	if len(l.ExtraWindowsRoots) > MaxExtraWindowsRoots {
		return fmt.Errorf("windows_extra_roots has %d folders; at most %d are allowed", len(l.ExtraWindowsRoots), MaxExtraWindowsRoots)
	}
	for _, r := range l.ExtraWindowsRoots {
		if err := ValidateWindowsRoot(r); err != nil {
			return fmt.Errorf("windows_extra_roots: %w", err)
		}
	}
	return nil
}

// keystoreExtensions are the file name endings the pack looks for.
var keystoreExtensions = []string{"jks", "p12", "pfx", "pem", "kdb"}

// Roots searched for keystore files, and the directories excluded from
// them: system trust stores (read by the certificates query already) and
// container data directories (no container root-filesystem scanning).
var (
	posixRoots    = []string{"/etc/%%", "/opt/%%", "/srv/%%", "/usr/local/%%"}
	posixExcluded = []string{
		"/etc/ssl/certs/%", "/etc/pki/ca-trust/extracted/%",
		"/var/lib/docker/%", "/var/lib/containerd/%", "/var/lib/containers/%",
		"/var/lib/kubelet/pods/%", "/run/containerd/%", "/opt/containerd/%",
	}
	windowsExcluded = []string{
		`C:\ProgramData\Docker\%`, `C:\ProgramData\containerd\%`, `C:\ProgramData\Microsoft\%`,
	}
)

const certColumns = "common_name, subject, issuer, ca, self_signed, not_valid_before, not_valid_after, signing_algorithm, key_algorithm, key_strength, subject_key_id, authority_key_id, sha1, path, serial"

func likeAny(col string, pats []string) string {
	parts := make([]string, len(pats))
	for i, p := range pats {
		parts[i] = col + " LIKE '" + p + "'"
	}
	return strings.Join(parts, " OR ")
}

func extCondition() string {
	parts := make([]string, len(keystoreExtensions))
	for i, e := range keystoreExtensions {
		parts[i] = "f.filename LIKE '%." + e + "'"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func keystoreQuery(roots, excluded []string, l Limits) string {
	notExcluded := make([]string, len(excluded))
	for i, p := range excluded {
		notExcluded[i] = "f.path NOT LIKE '" + p + "'"
	}
	return "SELECT f.path, f.size, f.mtime, f.uid, f.mode, h.sha256 FROM file f JOIN hash h ON h.path = f.path WHERE (" +
		likeAny("f.path", roots) + ") AND " + strings.Join(notExcluded, " AND ") +
		" AND f.type = 'regular' AND " + extCondition() +
		" AND f.size <= " + strconv.FormatInt(l.MaxFileBytes, 10) +
		" ORDER BY f.path LIMIT " + strconv.Itoa(l.MaxFiles) + ";"
}

// countsQuery counts, without hashing anything, the files the keystore query
// leaves out, so every run can report them: excluded (in an excluded
// directory), oversize (above the size limit) and eligible (within it; more
// than the file limit means the rest were skipped by the limit).
func countsQuery(roots, excluded []string, l Limits) string {
	ex := "(" + likeAny("f.path", excluded) + ")"
	limit := strconv.FormatInt(l.MaxFileBytes, 10)
	return "SELECT COALESCE(SUM(CASE WHEN " + ex + " THEN 1 ELSE 0 END), 0) AS excluded, " +
		"COALESCE(SUM(CASE WHEN NOT " + ex + " AND f.size > " + limit + " THEN 1 ELSE 0 END), 0) AS oversize, " +
		"COALESCE(SUM(CASE WHEN NOT " + ex + " AND f.size <= " + limit + " THEN 1 ELSE 0 END), 0) AS eligible " +
		"FROM file f WHERE (" + likeAny("f.path", roots) + ") AND f.type = 'regular' AND " + extCondition() + ";"
}

// PackQuery is one query of the pack.
type PackQuery struct {
	Name        string
	Platform    string // "posix" or "windows"
	SQL         string
	Description string
}

// Pack returns the pack's queries for the limits, in a fixed order.
func Pack(l Limits) ([]PackQuery, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	mib := strconv.FormatInt(l.MaxFileBytes, 10)
	caps := " Files up to " + mib + " bytes, at most " + strconv.Itoa(l.MaxFiles) + " files; never their contents."
	qs := []PackQuery{
		{
			QueryCertificatesWindows, "windows", "SELECT " + certColumns + ", sid, store_location, store, username, store_id FROM certificates;",
			"Meiscope: certificate metadata from every Windows store, including per-user stores (no private keys, no certificate bodies).",
		},
		{
			QueryCertificatesPosix, "posix", "SELECT " + certColumns + " FROM certificates;",
			"Meiscope: certificate metadata from the system trust stores and keychains (no private keys, no certificate bodies).",
		},
	}
	// One keystore query and one counts query per Windows root, so each root
	// is reported (and timed) on its own.
	depth := "to " + strconv.Itoa(MaxWindowsRootDepth) + " folder levels deep"
	for _, r := range windowsRoots(l.ExtraWindowsRoots) {
		pats := r.patterns()
		qs = append(qs,
			PackQuery{
				WindowsKeystoreQuery(r.id), "windows", keystoreQuery(pats, windowsExcluded, l),
				"Meiscope: path, size, mtime, owner, mode and SHA-256 of keystore files (*.jks, *.p12, *.pfx, *.pem, *.kdb) in " + r.base + ", " + depth + "." + caps + " Container data directories excluded.",
			},
			PackQuery{
				WindowsCountsQuery(r.id), "windows", countsQuery(pats, windowsExcluded, l),
				"Meiscope: counts of keystore files in " + r.base + " left out of the keystores query (excluded directories, over the size limit, over the file limit), so every run can report them.",
			},
		)
	}
	return append(qs,
		PackQuery{
			QueryKeystoresPosix, "posix", keystoreQuery(posixRoots, posixExcluded, l),
			"Meiscope: path, size, mtime, owner, mode and SHA-256 of keystore files (*.jks, *.p12, *.pfx, *.pem, *.kdb)." + caps + " System trust-store directories (read by the certificates query) and container root filesystems excluded.",
		},
		PackQuery{
			QueryKeystoreCountsPosix, "posix", countsQuery(posixRoots, posixExcluded, l),
			"Meiscope: counts of keystore files left out of the keystores query (excluded directories, over the size limit, over the file limit), so every run can report them.",
		},
	), nil
}

// osqueryInterval is the daily snapshot interval of every pack query.
const osqueryInterval = 86400

// PackConf renders the pack as an osquery pack file.
func PackConf(l Limits) ([]byte, error) {
	qs, err := Pack(l)
	if err != nil {
		return nil, err
	}
	type q struct {
		Query       string `json:"query"`
		Interval    int    `json:"interval"`
		Platform    string `json:"platform"`
		Snapshot    bool   `json:"snapshot"`
		Description string `json:"description"`
	}
	doc := struct {
		Version   string       `json:"version"`
		Discovery []string     `json:"discovery"`
		Queries   map[string]q `json:"queries"`
	}{Version: "5.0.0", Discovery: []string{}, Queries: map[string]q{}}
	for _, p := range qs {
		doc.Queries[p.Name] = q{p.SQL, osqueryInterval, p.Platform, true, p.Description}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(buf.String())
}

// FleetYAML renders the pack as Fleet saved queries (fleetctl apply -f).
func FleetYAML(l Limits) ([]byte, error) {
	qs, err := Pack(l)
	if err != nil {
		return nil, err
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].Name < qs[j].Name })
	var b strings.Builder
	for _, p := range qs {
		plat := "windows"
		if p.Platform == "posix" {
			plat = "darwin,linux"
		}
		b.WriteString("---\napiVersion: v1\nkind: query\nspec:\n")
		fmt.Fprintf(&b, "  name: %s\n  description: %s\n  query: %s\n  interval: %d\n  platform: %s\n", p.Name, jsonString(p.Description), jsonString(p.SQL), osqueryInterval, plat)
		b.WriteString("  automations_enabled: false\n  logging: snapshot\n  discard_data: false\n")
	}
	return []byte(b.String()), nil
}
