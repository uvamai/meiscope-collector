package osquery_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/buffer"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

func packFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixture.Root(), "..", "..", "packs", "osquery", name)) //nolint:gosec // repository files
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPackFilesAreGenerated: the committed pack files are exactly what
// "adapter pack" prints for the default limits, so the pack cannot drift
// from the limits in code.
func TestPackFilesAreGenerated(t *testing.T) {
	conf, err := osquery.PackConf(osquery.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conf, packFile(t, "meiscope.conf")) {
		t.Error("packs/osquery/meiscope.conf differs from `adapter pack`; regenerate it")
	}
	fl, err := osquery.FleetYAML(osquery.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fl, packFile(t, "fleet-queries.yml")) {
		t.Error("packs/osquery/fleet-queries.yml differs from `adapter pack --format fleet`; regenerate it")
	}
}

func TestLimitsCeilingsAndDefaults(t *testing.T) {
	if d := osquery.DefaultLimits(); d.MaxFileBytes != 10<<20 || d.MaxFiles != 1000 {
		t.Fatalf("defaults %+v", d)
	}
	if err := (osquery.Limits{MaxFileBytes: 100 << 20, MaxFiles: 10000}).Validate(); err != nil {
		t.Fatalf("the ceilings themselves must be allowed: %v", err)
	}
	for name, l := range map[string]osquery.Limits{
		"bytes over":  {MaxFileBytes: 100<<20 + 1, MaxFiles: 1000},
		"files over":  {MaxFileBytes: 10 << 20, MaxFiles: 10001},
		"bytes zero":  {MaxFileBytes: 0, MaxFiles: 1000},
		"files zero":  {MaxFileBytes: 10 << 20, MaxFiles: 0},
		"bytes minus": {MaxFileBytes: -1, MaxFiles: 1000},
	} {
		err := l.Validate()
		if err == nil || !strings.Contains(err.Error(), "ceiling") && !strings.Contains(err.Error(), "outside") {
			t.Errorf("%s: %v", name, err)
		}
		if _, perr := osquery.PackConf(l); perr == nil {
			t.Errorf("%s: a pack was generated", name)
		}
	}
	conf, err := osquery.PackConf(osquery.Limits{MaxFileBytes: 50 << 20, MaxFiles: 5000})
	if err != nil || !strings.Contains(string(conf), "f.size <= 52428800") || !strings.Contains(string(conf), "LIMIT 5000") {
		t.Fatalf("custom limits not in the pack: %v", err)
	}
	a := newAdapter(adapter.Env{})
	base := map[string]string{"mode": "direct", "host": "h", "files": "a-meiscope_certificates_posix.json"}
	with := func(k, v string) adapter.Config {
		s := map[string]string{}
		for a, b := range base {
			s[a] = b
		}
		s[k] = v
		return adapter.Config{Name: "x", Adapter: osquery.Name, Settings: s}
	}
	for k, v := range map[string]string{"keystore_max_bytes": "104857601", "keystore_max_files": "10001"} {
		if err := a.Validate(with(k, v)); err == nil || !strings.Contains(err.Error(), "ceiling") {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
	for _, kv := range [][2]string{{"keystore_max_bytes", "big"}, {"keystore_max_files", "1.5"}, {"keystore_max_files", "0"}} {
		if err := a.Validate(with(kv[0], kv[1])); err == nil {
			t.Errorf("%s=%s accepted", kv[0], kv[1])
		}
	}
	for k, v := range map[string]string{"keystore_max_bytes": "104857600", "keystore_max_files": "10000"} {
		if err := a.Validate(with(k, v)); err != nil {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}

func directLinux(extra map[string]string) adapter.Config {
	f := func(n string) string { return filepath.Join(fixture.Dir("osquery", "direct"), n) }
	s := map[string]string{
		"mode": "direct", "host": "app01.example.test",
		"files": strings.Join([]string{f("direct-meiscope_certificates_posix.json"), f("direct-meiscope_keystores_posix.json"), f("direct-meiscope_keystore_counts_posix.json")}, ","),
	}
	for k, v := range extra {
		s[k] = v
	}
	return adapter.Config{Name: "direct", Adapter: osquery.Name, Settings: s}
}

// TestRunReportsSkippedCounts: every run reports skipped_oversize,
// skipped_excluded and skipped_limit (zero when nothing was skipped).
func TestRunReportsSkippedCounts(t *testing.T) {
	env, logs := newEnv(t, nil)
	a := newAdapter(env)
	res := syncOK(t, a, directLinux(nil), "")
	want := map[string]int{"skipped_excluded": 122, "skipped_oversize": 1, "skipped_limit": 0, "skipped_feature_disabled": 0}
	for k, v := range want {
		got, present := res.Stats[k]
		if !present || got != v {
			t.Errorf("%s = %d (present %v), want %d", k, got, present, v)
		}
	}
	if !strings.Contains(logs.String(), "skipped_excluded") {
		t.Errorf("skipped counts are not logged:\n%s", logs.String())
	}
	// A tighter file limit: the counts query says 4 files were eligible.
	tight := syncOK(t, a, directLinux(map[string]string{"keystore_max_files": "2"}), "")
	files := 0
	for _, o := range tight.Observations {
		if o.Target.Kind == submit.KindFile {
			files++
		}
	}
	if files != 2 || tight.Stats["skipped_limit"] != 2 {
		t.Errorf("limit 2: %d files, skipped_limit %d", files, tight.Stats["skipped_limit"])
	}
	// A lower size limit than the pack used: rows above it are skipped here.
	small := syncOK(t, a, directLinux(map[string]string{"keystore_max_bytes": "2000"}), "")
	if small.Stats["skipped_oversize"] != 1+3 {
		t.Errorf("size limit 2000: skipped_oversize %d, want the pack's 1 plus 3 rows", small.Stats["skipped_oversize"])
	}
	// Rows from a customised pipeline inside an excluded directory are dropped and counted.
	dir := t.TempDir()
	row := `[{"path":"/var/lib/docker/overlay2/x/etc/app.pfx","size":"10","mtime":"1","uid":"0","mode":"0600","sha256":"` + strings.Repeat("c", 64) + `"},{"path":"C:\\ProgramData\\Docker\\x.pfx","size":"10","sha256":"` + strings.Repeat("d", 64) + `"},{"path":"/opt/ok/a.pfx","size":"10","sha256":"` + strings.Repeat("e", 64) + `"}]`
	f := filepath.Join(dir, "h-meiscope_keystores_posix.json")
	if err := os.WriteFile(f, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := adapter.Config{Name: "d", Adapter: osquery.Name, Settings: map[string]string{"mode": "direct", "host": "h.example.test", "files": f}}
	r := syncOK(t, a, cfg, "")
	if len(r.Observations) != 1 || r.Stats["skipped_excluded"] != 2 {
		t.Errorf("excluded rows: %d observations, skipped_excluded %d", len(r.Observations), r.Stats["skipped_excluded"])
	}
}

func TestFileMetadataAndEncryptedStoreFinding(t *testing.T) {
	env, _ := newEnv(t, nil)
	res := syncOK(t, newAdapter(env), directLinux(nil), "")
	got := map[string]submit.Observation{}
	for _, o := range res.Observations {
		if o.Target.Kind == submit.KindFile {
			got[o.Target.Path] = o
		}
	}
	p12 := got["/opt/app/keystore.p12"]
	if p12.Adapter == nil {
		t.Fatal("keystore.p12 not mapped")
	}
	f := p12.Adapter.File
	if f.StoreType != submit.StorePKCS12 || f.Owner != "0" || f.Permissions != "0600" || f.MTime == nil || f.Size == nil || *f.Size != 2547 {
		t.Errorf("file metadata %+v", f)
	}
	if len(p12.Adapter.Findings) != 1 || p12.Adapter.Findings[0].Code != submit.FindingKeystoreNotParsed {
		t.Errorf("findings %+v", p12.Adapter.Findings)
	}
	if jks := got["/opt/app/trust.jks"]; jks.Adapter == nil || jks.Adapter.File.StoreType != submit.StoreJKS || len(jks.Adapter.Findings) != 1 {
		t.Errorf("jks %+v", jks.Adapter)
	}
	if pem := got["/etc/app/tls.pem"]; pem.Adapter == nil || pem.Adapter.File.StoreType != submit.StorePEM || len(pem.Adapter.Findings) != 0 {
		t.Errorf("pem %+v", pem.Adapter)
	}
	// The finding names the file and its size only: nothing else in the observation can identify the key store's content.
	b, _ := json.Marshal(p12)
	for _, banned := range []string{"password", "alias", "private", "passphrase"} {
		if strings.Contains(strings.ToLower(string(b)), banned) {
			t.Errorf("observation mentions %q: %s", banned, b)
		}
	}
	submitAll(t, res.Observations)
}

// TestFeatureFlag runs the adapter with MEISCOPE_FEATURE_LOCAL_STORE_V1 off
// and on against the fake core configured with each contract. Off is the
// default: the adapter emits nothing the core's current contract would
// reject, and says what it skipped. On emits the proposed shape, which the
// proposed contract accepts and the current one refuses.
func TestFeatureFlag(t *testing.T) {
	vendored, err := submittest.NewCoreWithSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	defer vendored.Close()
	proposed, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer proposed.Close()

	for _, on := range []bool{false, true} {
		env, logs := newEnv(t, nil)
		env.Features = adapter.Features{LocalStoreV1: on}
		res := syncOK(t, newAdapter(env), directLinux(nil), "")
		for _, tc := range []struct {
			name string
			core *submittest.Core
		}{{"current contract 0.8.1", vendored}, {"proposed contract 0.5.0", proposed}} {
			cl, _ := submit.New(tc.core.URL, tc.core.Client(), submit.WithRetry(retry.Policy{Attempts: 0}))
			var accepted int
			var serr error
			if len(res.Observations) > 0 {
				var r submit.Result
				r, serr = cl.Submit(context.Background(), res.Observations)
				accepted = r.Accepted
			}
			switch {
			case !on:
				if len(res.Observations) != 0 || serr != nil {
					t.Errorf("flag off, %s: %d observations, %v", tc.name, len(res.Observations), serr)
				}
			case tc.core == proposed:
				if serr != nil || accepted != len(res.Observations) || len(res.Observations) == 0 {
					t.Errorf("flag on, %s: accepted %d of %d, %v", tc.name, accepted, len(res.Observations), serr)
				}
			default:
				if !submit.IsPermanent(serr) {
					t.Errorf("flag on, %s: want the current core to refuse the proposed shape, got %v", tc.name, serr)
				}
			}
		}
		if !on {
			if res.Stats[osquery.StatSkippedFeatureDisabled] != 125 {
				t.Errorf("skipped_feature_disabled = %d, want 125 (121 certificates + 4 keystore files)", res.Stats[osquery.StatSkippedFeatureDisabled])
			}
			if !strings.Contains(logs.String(), adapter.EnvLocalStoreV1) || !strings.Contains(logs.String(), "skipped_feature_disabled") {
				t.Errorf("the skip is not logged:\n%s", logs.String())
			}
			if res.Cursor != "" {
				t.Errorf("the cursor advanced with the feature off: %q", res.Cursor)
			}
		} else if res.Stats[osquery.StatSkippedFeatureDisabled] != 0 {
			t.Errorf("skipped_feature_disabled = %d with the flag on", res.Stats[osquery.StatSkippedFeatureDisabled])
		}
	}
}

// TestFlagOffKeepsFleetDeltaForLater: with the feature off the Fleet cursor
// stays where it was, so nothing is lost for the day it is turned on.
func TestFlagOffKeepsFleetDeltaForLater(t *testing.T) {
	tr, err := fixture.Load(fixture.Dir("osquery", "fleet"))
	if err != nil {
		t.Fatal(err)
	}
	off, _ := newEnv(t, tr)
	off.Features = adapter.Features{}
	r1 := syncOK(t, newAdapter(off), fleetConfig(), "")
	if len(r1.Observations) != 0 || r1.Cursor != "" || r1.Stats[osquery.StatSkippedFeatureDisabled] == 0 {
		t.Fatalf("flag off: %d observations, cursor %q, stats %v", len(r1.Observations), r1.Cursor, r1.Stats)
	}
	on, _ := newEnv(t, tr)
	r2 := syncOK(t, newAdapter(on), fleetConfig(), r1.Cursor)
	if len(r2.Observations) == 0 {
		t.Fatal("the delta was lost while the feature was off")
	}
}

func TestLoadFeatures(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == adapter.EnvLocalStoreV1 {
				return v
			}
			return ""
		}
	}
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		f, err := adapter.LoadFeatures(env(v))
		if err != nil || f.LocalStoreV1 != want {
			t.Errorf("%q: %+v %v", v, f, err)
		}
	}
	if _, err := adapter.LoadFeatures(env("yes please")); err == nil {
		t.Error("garbage accepted")
	}
}

// opensslOrSkip returns the openssl binary, skipping the test when the
// machine has none (CI images have it).
func opensslOrSkip(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed; this test generates a real PKCS#12 with it")
	}
	return p
}

// TestNoKeyMaterialFromARealPKCS12 generates, at test time, a PKCS#12 file
// that really contains a private key, protected by a random password, and
// feeds it through the osquery file path: osquery reports the file's path,
// size, times, mode and SHA-256. The key (DER, PEM, base64), the file bytes
// and the password must appear nowhere: not in the observation JSON, not in
// the logs, not in the on-disk buffer, not in what the core receives. The
// store is reported as keystore_not_parsed. No key is committed.
func TestNoKeyMaterialFromARealPKCS12(t *testing.T) {
	ossl := opensslOrSkip(t)
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command(ossl, args...).CombinedOutput() //nolint:gosec // fixed openssl arguments
		if err != nil {
			t.Fatalf("openssl %s: %v\n%s", args[0], err, out)
		}
	}
	keyPath, certPath, p12Path := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "web01.p12")
	run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "2", "-subj", "/CN=web01.example.test")
	pwRaw := make([]byte, 18)
	if _, err := rand.Read(pwRaw); err != nil {
		t.Fatal(err)
	}
	password := base64.RawStdEncoding.EncodeToString(pwRaw)
	run("pkcs12", "-export", "-in", certPath, "-inkey", keyPath, "-out", p12Path, "-passout", "pass:"+password)

	keyPEM, _ := os.ReadFile(keyPath) //nolint:gosec // test-generated file
	p12, _ := os.ReadFile(p12Path)    //nolint:gosec // test-generated file
	blk, _ := pem.Decode(keyPEM)
	if blk == nil || len(p12) < 500 {
		t.Fatal("test key or PKCS#12 not generated")
	}
	needles := map[string][]byte{
		"password":              []byte(password),
		"p12 bytes":             p12[:64],
		"p12 base64":            []byte(base64.StdEncoding.EncodeToString(p12)),
		"p12 base64 prefix":     []byte(base64.StdEncoding.EncodeToString(p12)[:48]),
		"key DER":               blk.Bytes[:48],
		"key DER base64":        []byte(base64.StdEncoding.EncodeToString(blk.Bytes)[:48]),
		"key DER hex":           []byte(hex.EncodeToString(blk.Bytes)[:48]),
		"key PEM armour":        []byte("PRIVATE KEY"),
		"key PEM first line":    []byte(strings.Split(string(keyPEM), "\n")[1]),
		"p12 password argument": []byte("pass:"),
	}

	// What osquery reports for the file: stats and the SHA-256, never content.
	sum := sha256.Sum256(p12)
	fi, _ := os.Stat(p12Path)
	rows := []map[string]string{{
		"path": p12Path, "size": strconv.FormatInt(fi.Size(), 10), "mtime": strconv.FormatInt(fi.ModTime().Unix(), 10),
		"uid": "1000", "mode": "0600", "sha256": hex.EncodeToString(sum[:]),
	}}
	rb, _ := json.Marshal(rows)
	out := filepath.Join(dir, "web01-meiscope_keystores_posix.json")
	if err := os.WriteFile(out, rb, 0o600); err != nil {
		t.Fatal(err)
	}

	env, logs := newEnv(t, nil)
	a := newAdapter(env)
	cfg := adapter.Config{Name: "d", Adapter: osquery.Name, Settings: map[string]string{"mode": "direct", "host": "web01.example.test", "files": out}}
	// The file path is absolute on the test machine; on Windows it is a drive path, which the mapping accepts too.
	res := syncOK(t, a, cfg, "")
	if len(res.Observations) != 1 {
		t.Fatalf("%d observations (%v)", len(res.Observations), res.Stats)
	}
	o := res.Observations[0]
	if o.Adapter.File.StoreType != submit.StorePKCS12 || len(o.Adapter.Findings) != 1 || o.Adapter.Findings[0].Code != submit.FindingKeystoreNotParsed {
		t.Fatalf("not reported as an encrypted store: %+v", o.Adapter)
	}
	obsJSON, _ := json.Marshal(res.Observations)

	// Through the encrypted on-disk buffer to the fake core.
	bufDir := t.TempDir()
	key := bytes.Repeat([]byte{9}, buffer.KeySize)
	buf, err := buffer.Open(buffer.Options{Dir: bufDir, Key: key, Clock: env.Clock, Log: env.Log})
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Enqueue(context.Background(), res.Observations); err != nil {
		t.Fatal(err)
	}
	_ = buf.Close()
	var disk []byte
	files, _ := filepath.Glob(filepath.Join(bufDir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f) //nolint:gosec // test buffer directory
		disk = append(disk, b...)
	}
	buf, err = buffer.Open(buffer.Options{Dir: bufDir, Key: key, Clock: env.Clock, Log: env.Log})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = buf.Close() }()
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	if r, err := buf.Flush(context.Background(), cl, 10); err != nil || r.Accepted != 1 {
		t.Fatalf("flush %+v %v %v", r, err, core.Errors())
	}
	var received []byte
	for _, b := range core.Batches() {
		received = append(received, b...)
	}

	for where, haystack := range map[string][]byte{
		"the observation JSON": obsJSON, "the logs": logs.Bytes(), "the on-disk buffer": disk, "what the core received": received,
	} {
		if len(haystack) == 0 {
			t.Errorf("%s is empty; the test would prove nothing", where)
		}
		for what, needle := range needles {
			if what == "key PEM armour" || what == "p12 password argument" {
				if where != "the on-disk buffer" && bytes.Contains(haystack, needle) {
					t.Errorf("%s contains %s", where, what)
				}
				continue
			}
			if bytes.Contains(haystack, needle) {
				t.Errorf("%s contains %s", where, what)
			}
		}
	}
}
