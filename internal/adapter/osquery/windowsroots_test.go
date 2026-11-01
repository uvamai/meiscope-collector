package osquery_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
)

// windowsBases are the default Windows roots, written out here on purpose:
// they are the product's promise about where it looks, so a change to them
// must change this test.
var windowsBases = []string{
	`C:\inetpub`,
	`C:\Program Files\Java\%\lib\security`,
	`C:\Program Files\Eclipse Adoptium\%\lib\security`,
	`C:\Program Files\Apache Software Foundation\%\conf`,
	`C:\ProgramData\ssl`,
	`C:\OpenSSL%`,
}

var pathLike = regexp.MustCompile(`f\.path LIKE '([^']*)'`)

func windowsFileQueries(t *testing.T, l osquery.Limits) []osquery.PackQuery {
	t.Helper()
	qs, err := osquery.Pack(l)
	if err != nil {
		t.Fatal(err)
	}
	var out []osquery.PackQuery
	for _, q := range qs {
		if q.Platform == "windows" && q.Name != osquery.QueryCertificatesWindows {
			out = append(out, q)
		}
	}
	return out
}

// TestWindowsQueriesAreTargeted: no Windows file query walks a tree. Every
// path pattern is one of the default roots with one to four single-level
// wildcards, never a recursive %%, a drive, Program Files or ProgramData.
func TestWindowsQueriesAreTargeted(t *testing.T) {
	qs := windowsFileQueries(t, osquery.DefaultLimits())
	if len(qs) != 2*len(windowsBases) {
		t.Fatalf("%d Windows file queries, want a keystore and a counts query for each of %d roots", len(qs), len(windowsBases))
	}
	for _, q := range qs {
		if strings.Contains(q.SQL, "%%") {
			t.Errorf("%s uses a recursive %%%% pattern", q.Name)
		}
		var pats [][]string
		for _, m := range pathLike.FindAllStringSubmatch(q.SQL, -1) {
			// The counts query also uses LIKE for its excluded directories.
			if !strings.HasPrefix(m[1], `C:\ProgramData\Docker\`) && !strings.HasPrefix(m[1], `C:\ProgramData\containerd\`) &&
				!strings.HasPrefix(m[1], `C:\ProgramData\Microsoft\`) {
				pats = append(pats, m)
			}
		}
		if len(pats) != osquery.MaxWindowsRootDepth {
			t.Errorf("%s has %d path patterns, want one per depth (%d)", q.Name, len(pats), osquery.MaxWindowsRootDepth)
		}
		for _, p := range pats {
			ok := false
			for _, base := range windowsBases {
				rest, found := strings.CutPrefix(p[1], base)
				if found && strings.Trim(rest, `\%`) == "" && strings.Count(rest, "%") >= 1 && strings.Count(rest, "%") <= osquery.MaxWindowsRootDepth && !strings.Contains(rest, `%%`) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: pattern %q is not a default root with 1..%d single-level wildcards", q.Name, p[1], osquery.MaxWindowsRootDepth)
			}
		}
	}
	ids := osquery.WindowsRootIDs()
	if len(ids) != len(windowsBases) {
		t.Fatalf("root ids %v", ids)
	}
	names := map[string]bool{}
	for _, q := range qs {
		names[q.Name] = true
	}
	for _, id := range ids {
		if !names[osquery.WindowsKeystoreQuery(id)] || !names[osquery.WindowsCountsQuery(id)] {
			t.Errorf("missing queries for root %s", id)
		}
	}
}

func TestExtraWindowsRootsAddQueries(t *testing.T) {
	l := osquery.DefaultLimits()
	l.ExtraWindowsRoots = []string{`D:\Apps\tls`, `E:\Data\certs\`}
	qs := windowsFileQueries(t, l)
	if len(qs) != 2*(len(windowsBases)+2) {
		t.Fatalf("%d Windows file queries with two extra roots", len(qs))
	}
	got := map[string]string{}
	for _, q := range qs {
		got[q.Name] = q.SQL
	}
	if sql := got[osquery.WindowsKeystoreQuery("extra1")]; !strings.Contains(sql, `f.path LIKE 'D:\Apps\tls\%\%\%\%'`) || strings.Contains(sql, "%%") {
		t.Errorf("extra1: %s", sql)
	}
	if sql := got[osquery.WindowsKeystoreQuery("extra2")]; !strings.Contains(sql, `f.path LIKE 'E:\Data\certs\%'`) || strings.Contains(sql, `certs\\`) {
		t.Errorf("extra2 (trailing backslash must be trimmed): %s", sql)
	}
	names := osquery.QueryNames(l)
	if len(names) != len(qs)+4 { // plus two certificate queries and two posix queries
		t.Errorf("QueryNames has %d names for %d Windows file queries", len(names), len(qs))
	}
	conf, err := osquery.PackConf(l)
	if err != nil || !strings.Contains(string(conf), osquery.WindowsKeystoreQuery("extra2")) {
		t.Errorf("the pack file lacks the extra roots (%v)", err)
	}
}

func TestValidateWindowsRoot(t *testing.T) {
	good := []string{
		`D:\Apps\tls`, `D:\Apps\tls\`, `E:\Data\My App (x)\certs_2026`, `C:\Program Files\Contoso\ssl`,
		`C:\ProgramData\Contoso`, `C:\Users\svc-app\tls`, `F:\a`,
	}
	for _, p := range good {
		if err := osquery.ValidateWindowsRoot(p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	bad := map[string]string{
		`C:\`:                 "drive root",
		`C:`:                  "drive root",
		``:                    "empty",
		`D:/Apps/tls`:         "forward slash",
		`Apps\tls`:            "no drive",
		`\\server\share\tls`:  "UNC path",
		`D:\Apps\*`:           "wildcard",
		`D:\Apps\tl%s`:        "SQL wildcard",
		`D:\Apps\o'brien`:     "quote",
		`D:\Apps\..\Windows`:  "parent folder",
		`D:\Apps\.\tls`:       "dot folder",
		`D:\Apps\tls;DROP`:    "semicolon",
		`D:\Apps\tls,E:\x`:    "comma",
		"D:\\Apps\\tls\x00":   "control character",
		`C:\Users`:            "whole users folder",
		`C:\Users\alice`:      "whole profile",
		`C:\Users\alice\.ssh`: "ssh keys",
		`C:\Users\alice\.gnupg\private-keys-v1.d`:                                     "gnupg keys",
		`C:\Users\alice\AppData\Roaming\Microsoft\Crypto\RSA`:                         "user private keys",
		`C:\Users\alice\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates`: "user certificate store",
		`C:\ProgramData\Microsoft\Crypto\Keys`:                                        "machine private keys",
		`C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys`:                             "machine keys",
		`C:\Windows`:                     "windows folder",
		`C:\Windows\System32\config`:     "windows folder",
		`C:\Program Files`:               "whole program files",
		`c:\program files (x86)`:         "whole program files x86",
		`C:\ProgramData`:                 "whole programdata",
		`C:\Users\alice\Protect`:         "dpapi master keys",
		`D:\Apps\tls `:                   "trailing space",
		`D:\ Apps\tls`:                   "leading space",
		`D:\` + strings.Repeat("a", 250): "too long",
	}
	for p, why := range bad {
		if err := osquery.ValidateWindowsRoot(p); err == nil {
			t.Errorf("%q accepted (%s)", p, why)
		}
	}
}

func TestExtraRootsAreValidatedByTheAdapter(t *testing.T) {
	env, _ := newEnv(t, nil)
	a := newAdapter(env)
	base := map[string]string{"mode": "direct", "host": "web01.example.test", "files": "web01-meiscope_certificates_windows.json"}
	with := func(roots string) adapter.Config {
		s := map[string]string{"windows_extra_roots": roots}
		for k, v := range base {
			s[k] = v
		}
		return adapter.Config{Name: "win", Adapter: osquery.Name, Settings: s}
	}
	if err := a.Validate(with(`D:\Apps\tls, E:\Data\certs`)); err != nil {
		t.Errorf("valid roots rejected: %v", err)
	}
	for _, roots := range []string{`C:\`, `C:\Users\alice\.ssh`, `D:\a,D:\b,D:\c,D:\d,D:\e,D:\f,D:\g,D:\h,D:\i,D:\j,D:\k`} {
		if err := a.Validate(with(roots)); err == nil {
			t.Errorf("roots %q accepted", roots)
		}
	}
}

// TestPerRootStatistics: a run reports, for each root, the files seen and
// skipped, and the file limit is applied to each root on its own.
func TestPerRootStatistics(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := []string{
		write("web01-"+osquery.WindowsCountsQuery("inetpub")+".json", `[{"excluded":"1","oversize":"2","eligible":"1500"}]`),
		write("web01-"+osquery.WindowsCountsQuery("openssl")+".json", `[{"excluded":"0","oversize":"0","eligible":"3"}]`),
		write("web01-"+osquery.WindowsCountsQuery("extra1")+".json", `[{"excluded":"0","oversize":"4","eligible":"900"}]`),
	}
	env, logs := newEnv(t, nil)
	cfg := adapter.Config{Name: "win", Adapter: osquery.Name, Settings: map[string]string{
		"mode": "direct", "host": "web01.example.test", "files": strings.Join(files, ","),
		"windows_extra_roots": `D:\Apps\tls`,
	}}
	res := syncOK(t, newAdapter(env), cfg, "")
	want := map[string]int{
		"root.inetpub.files_seen":          1503,
		"root.inetpub.skipped_excluded":    1,
		"root.inetpub.skipped_oversize":    2,
		"root.inetpub.skipped_limit":       500,
		"root.openssl.files_seen":          3,
		"root.openssl.skipped_limit":       0,
		"root.extra1.files_seen":           904,
		"root.extra1.skipped_oversize":     4,
		osquery.StatSkippedExcluded:        1,
		osquery.StatSkippedOversize:        6,
		osquery.StatSkippedLimit:           500,
		osquery.StatSkippedFeatureDisabled: 0,
	}
	for k, v := range want {
		if got := res.Stats[k]; got != v {
			t.Errorf("stat %s = %d, want %d (stats %v)", k, got, v, res.Stats)
		}
	}
	for k := range res.Stats {
		if strings.HasPrefix(k, "eligible_keystore_files") {
			t.Errorf("internal counter %q leaked into the stats", k)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"osquery keystore root"`) || !strings.Contains(logs.String(), `"root":"inetpub"`) {
		t.Error("the run did not log the per-root statistics")
	}
	if strings.Contains(logs.String(), `"reason":"root.`) {
		t.Error("per-root statistics were logged as skipped rows")
	}
}
