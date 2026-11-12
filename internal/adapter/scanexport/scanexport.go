// Package scanexport holds the Qualys and Tenable export adapters
// (FR-DISC-029). Each reads certificate rows from CSV exports the customer's
// scanner already produced (files given by path) and maps every certificate
// a scanner saw on host:port to a host_port_sni observation with method
// adapter (proposed contract 0.10.0, behind
// MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2). They only read local files: they
// never contact the scanner, its API or the scanned hosts.
package scanexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Run statistics keys (Result.Stats). Rows of other checks are not
// certificate rows and are counted, not mapped.
const (
	StatFiles                  = "files"
	StatFilesUnchanged         = "files_unchanged"
	StatRows                   = "certificate_rows"
	StatOtherChecks            = "ignored_other_checks"
	StatMalformedRow           = "skipped_malformed_row"
	StatNoHost                 = "skipped_no_host"
	StatBadPort                = "skipped_bad_port"
	StatUnparsedOutput         = "skipped_unparsed_output"
	StatNoIdentity             = "skipped_no_identity"
	StatDuplicate              = "skipped_duplicate"
	StatSkippedFeatureDisabled = "skipped_feature_disabled"
)

// DefaultMaxFileBytes bounds an export file (setting max_file_bytes).
const DefaultMaxFileBytes = 256 << 20

// maxPreamble is how many rows before the header row are tolerated (Qualys
// reports start with a title block).
const maxPreamble = 100

// format is one scanner's export format.
type format struct {
	name, source, summary string
	// header reports whether a row is the header row.
	header func(cols map[string]int) bool
	// row maps one data row to a certificate, or returns a skip reason.
	row func(get func(...string) string) (rowResult, string)
}

// rowResult is a certificate row of an export.
type rowResult struct {
	host, dnsName, check string
	port                 int
	cert                 certFields
}

// Adapter is a scanner export adapter.
type Adapter struct {
	env adapter.Env
	f   format
}

func register(f format) {
	adapter.Register(f.name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env, f: f} })
}

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    a.f.name,
		Source:  a.f.source,
		Summary: a.f.summary,
		Settings: []string{
			"files (comma-separated absolute paths of CSV exports)",
			"max_file_bytes (default 268435456)",
		},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	files := splitList(cfg.Setting("files", ""))
	if len(files) == 0 || len(files) > 100 {
		return fmt.Errorf("%s: files must name 1 to 100 CSV exports", a.f.name)
	}
	for _, f := range files {
		if !filepath.IsAbs(f) || strings.ContainsAny(f, "*?[") {
			return fmt.Errorf("%s: %q must be an absolute path without wildcards", a.f.name, f)
		}
	}
	if v := cfg.Setting("max_file_bytes", ""); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err != nil || n < 1024 || n > 4<<30 {
			return fmt.Errorf("%s: max_file_bytes must be an integer in [1024, 4294967296]", a.f.name)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Sync reads every configured export whose content changed since the cursor.
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := map[string]string{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	limit := int64(DefaultMaxFileBytes)
	if n, err := strconv.ParseInt(cfg.Setting("max_file_bytes", ""), 10, 64); err == nil {
		limit = n
	}
	st := map[string]int{
		StatFiles: 0, StatFilesUnchanged: 0, StatRows: 0, StatOtherChecks: 0, StatMalformedRow: 0, StatNoHost: 0,
		StatBadPort: 0, StatUnparsedOutput: 0, StatNoIdentity: 0, StatDuplicate: 0, StatSkippedFeatureDisabled: 0,
	}
	now := a.env.Clock.Now()
	next := map[string]string{}
	var out []submit.Observation
	for _, path := range splitList(cfg.Setting("files", "")) {
		if err := ctx.Err(); err != nil {
			return adapter.Result{}, err
		}
		path = filepath.Clean(path)
		b, mtime, err := readFile(path, limit)
		if err != nil {
			return adapter.Result{}, fmt.Errorf("%s: %w", a.f.name, err)
		}
		st[StatFiles]++
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		next[path] = digest
		if cur[path] == digest {
			st[StatFilesUnchanged]++
			continue
		}
		at := adapter.ObservedAt(mtime)
		if at.After(now) {
			at = adapter.ObservedAt(now)
		}
		obs, err := a.parse(b, filepath.Base(path), at, st)
		if err != nil {
			return adapter.Result{}, fmt.Errorf("%s: %s: %w", a.f.name, filepath.Base(path), err)
		}
		out = append(out, obs...)
	}
	nc, err := adapter.EncodeCursor(next)
	if err != nil {
		return adapter.Result{}, err
	}
	if !a.env.Features.AdapterEvidenceV2 {
		st[StatSkippedFeatureDisabled] = len(out)
		if a.env.Log != nil {
			a.env.Log.Warn(a.f.name+" observations were not sent: host_port_sni observations with adapter evidence need "+adapter.EnvAdapterEvidenceV2+" (proposed contract 0.10.0); the cursor was not advanced",
				"skipped_feature_disabled", len(out))
		}
		out, nc = nil, since
	}
	if a.env.Log != nil {
		for k, v := range st {
			if v > 0 && strings.HasPrefix(k, "skipped_") {
				a.env.Log.Warn(a.f.name+" rows skipped", "reason", k, "rows", v)
			}
		}
		a.env.Log.Info(a.f.name+" sync", "instance", cfg.Name, "observations", len(out), "files", st[StatFiles], "rows", st[StatRows])
	}
	return adapter.Result{Observations: out, Cursor: nc, Stats: st}, nil
}

func readFile(path string, limit int64) ([]byte, time.Time, error) {
	f, err := os.Open(path) //nolint:gosec // an export path from the operator's configuration
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, time.Time{}, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if int64(len(b)) > limit {
		return nil, time.Time{}, fmt.Errorf("%s is larger than max_file_bytes (%d)", path, limit)
	}
	return b, fi.ModTime(), nil
}

// ErrNoHeader is returned when an export has no recognisable header row.
var ErrNoHeader = errors.New("no header row of this export format was found")

func (a *Adapter) parse(b []byte, file string, at time.Time, st map[string]int) ([]submit.Observation, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	var cols map[string]int
	width := 0
	seen := map[string]bool{}
	var out []submit.Observation
	for row := 0; ; row++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if cols != nil {
				st[StatMalformedRow]++
			}
			continue
		}
		if cols == nil {
			c := map[string]int{}
			for i, h := range rec {
				c[strings.ToLower(strings.TrimSpace(h))] = i
			}
			if a.f.header(c) {
				cols, width = c, len(rec)
			} else if row >= maxPreamble {
				return nil, ErrNoHeader
			}
			continue
		}
		if len(rec) != width {
			st[StatMalformedRow]++
			continue
		}
		get := func(names ...string) string {
			for _, n := range names {
				if i, ok := cols[strings.ToLower(n)]; ok {
					return strings.TrimSpace(rec[i])
				}
			}
			return ""
		}
		res, reason := a.f.row(get)
		if reason != "" {
			st[reason]++
			continue
		}
		st[StatRows]++
		o, reason := a.observation(res, file, at)
		if reason != "" {
			st[reason]++
			continue
		}
		k := adapter.Fingerprint(o)
		if seen[k] {
			st[StatDuplicate]++
			continue
		}
		seen[k] = true
		out = append(out, o)
	}
	if cols == nil {
		return nil, ErrNoHeader
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i].Target, out[j].Target
		if x.Host != y.Host {
			return x.Host < y.Host
		}
		return x.Port < y.Port
	})
	return out, nil
}

func validHost(h string) bool {
	return h != "" && len(h) <= 253 && !strings.ContainsAny(h, " \t/\\@")
}

func (a *Adapter) observation(r rowResult, file string, at time.Time) (submit.Observation, string) {
	if !validHost(r.host) {
		return submit.Observation{}, StatNoHost
	}
	if r.port < 1 || r.port > 65535 {
		return submit.Observation{}, StatBadPort
	}
	m := r.cert.metadata()
	if m == nil {
		return submit.Observation{}, StatUnparsedOutput
	}
	if m.SHA1 == "" && (m.Issuer == "" || m.Serial == "") {
		return submit.Observation{}, StatNoIdentity
	}
	ev := &submit.AdapterEvidence{Source: a.f.source, Certificate: m, Scanner: &submit.ScannerEvidence{Check: r.check, File: adapter.Clip(file, 255)}}
	if d := strings.ToLower(r.dnsName); validHost(d) && d != strings.ToLower(r.host) {
		ev.Scanner.DNSName = d
	}
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindHostPortSNI, Host: strings.ToLower(r.host), Port: r.port},
		Method:     submit.MethodAdapter,
		ObservedAt: at,
		Outcome:    submit.OutcomeCertSeen,
		Adapter:    ev,
	}, ""
}

// certFields are certificate fields as a scanner prints them.
type certFields struct {
	subject, issuer     map[string]string
	serial, sigAlg      string
	notBefore, notAfter *time.Time
	keyAlg, keyBits     string
	sha1, sha256        string
	dnsNames            []string
	seen                bool
}

func newCertFields() certFields {
	return certFields{subject: map[string]string{}, issuer: map[string]string{}}
}

// metadata returns the contract form, or nil when nothing was parsed.
func (c certFields) metadata() *submit.CertificateMetadata {
	if !c.seen {
		return nil
	}
	m := &submit.CertificateMetadata{
		SHA1:             c.sha1,
		SHA256:           c.sha256,
		Serial:           c.serial,
		Subject:          adapter.Clip(dn(c.subject), 4096),
		Issuer:           adapter.Clip(dn(c.issuer), 4096),
		CommonName:       adapter.Clip(c.subject["CN"], 1024),
		NotBefore:        c.notBefore,
		NotAfter:         c.notAfter,
		KeyAlgorithm:     adapter.Clip(c.keyAlg, 64),
		KeyStrength:      adapter.Clip(c.keyBits, 64),
		SigningAlgorithm: adapter.Clip(c.sigAlg, 64),
	}
	if m.Issuer != "" && m.Subject == m.Issuer {
		self := true
		m.SelfSigned = &self
	}
	for i, n := range c.dnsNames {
		if i == 256 {
			break
		}
		m.DNSNames = append(m.DNSNames, adapter.Clip(n, 253))
	}
	return m
}

// dn builds an RFC 4514-style name, most specific attribute first.
func dn(attrs map[string]string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `+`, `\+`, `"`, `\"`, `<`, `\<`, `>`, `\>`, `;`, `\;`)
	var parts []string
	for _, k := range []string{"CN", "OU", "O", "L", "ST", "C"} {
		if v := strings.TrimSpace(attrs[k]); v != "" {
			parts = append(parts, k+"="+r.Replace(v))
		}
	}
	return strings.Join(parts, ",")
}

// timeLayouts are the date formats scanners print (OpenSSL style).
var timeLayouts = []string{
	"Jan 2 15:04:05 2006 MST",
	"Jan 02 15:04:05 2006 MST",
	"2006-01-02 15:04:05",
	time.RFC3339,
}

func parseTime(s string) *time.Time {
	s = strings.Join(strings.Fields(s), " ")
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// keyLength extracts the number from "2048 bits" or "(256 bit)".
func keyLength(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "()")
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	if n, err := strconv.Atoi(f[0]); err == nil && n > 0 && n <= 65536 {
		return strconv.Itoa(n)
	}
	return ""
}

func splitDNSNames(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if v, ok := strings.CutPrefix(p, "DNS:"); ok && v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out
}
