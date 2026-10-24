package osquery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Source is the AdapterEvidence.source of osquery observations.
const Source = "osquery"

// The pack's queries (packs/osquery/meiscope.conf).
const (
	QueryCertificatesWindows = "meiscope_certificates_windows"
	QueryCertificatesPosix   = "meiscope_certificates_posix"
	QueryKeystoresWindows    = "meiscope_keystores_windows"
	QueryKeystoresPosix      = "meiscope_keystores_posix"
)

// PackQueries lists the pack's query names.
var PackQueries = []string{QueryCertificatesWindows, QueryCertificatesPosix, QueryKeystoresWindows, QueryKeystoresPosix}

// queryOf maps a logged or saved query name to a pack query: osquery logs
// pack queries as "pack_<pack>_<query>", Fleet keeps the plain name.
func queryOf(name string) (string, bool) {
	for _, q := range PackQueries {
		if name == q || strings.HasSuffix(name, "_"+q) {
			return q, true
		}
	}
	return "", false
}

// row is one result row; osquery reports every column as a string, but
// some loggers emit numbers ("numerics"), so values are normalised.
type row map[string]string

func toRow(m map[string]any) row {
	r := make(row, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case string:
			r[k] = x
		case float64:
			r[k] = strconv.FormatFloat(x, 'f', -1, 64)
		case json.Number:
			r[k] = x.String()
		case bool:
			r[k] = strconv.FormatBool(x)
		case nil:
		default:
			r[k] = fmt.Sprint(x)
		}
	}
	return r
}

var (
	hex40  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	winAbs = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// stats counts rows the mapping skipped, by reason.
type stats map[string]int

// mapRow maps one row of a pack query to an observation.
func mapRow(query, host string, at time.Time, r row, st stats) (submit.Observation, bool) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 {
		st["no_host"]++
		return submit.Observation{}, false
	}
	obs := submit.Observation{Method: submit.MethodAdapter, ObservedAt: at.UTC().Truncate(time.Second)}
	switch query {
	case QueryCertificatesWindows, QueryCertificatesPosix:
		sha1 := strings.ToLower(strings.TrimSpace(r["sha1"]))
		if !hex40.MatchString(sha1) {
			st["bad_sha1"]++
			return submit.Observation{}, false
		}
		obs.Target = submit.Target{Kind: submit.KindStore, Host: host, Store: storeLocator(query, r)}
		if p := r["path"]; isAbs(p) {
			obs.Target.Path = clip(p, 4096)
		}
		obs.Outcome = submit.OutcomeCertSeen
		obs.Adapter = &submit.AdapterEvidence{
			Source: Source,
			Certificate: &submit.CertificateMetadata{
				SHA1:             sha1,
				Serial:           clip(r["serial"], 128),
				Subject:          clip(r["subject"], 4096),
				Issuer:           clip(r["issuer"], 4096),
				CommonName:       clip(r["common_name"], 1024),
				NotBefore:        epoch(r["not_valid_before"]),
				NotAfter:         epoch(r["not_valid_after"]),
				CA:               flag(r["ca"]),
				SelfSigned:       flag(r["self_signed"]),
				KeyAlgorithm:     clip(r["key_algorithm"], 64),
				KeyStrength:      clip(r["key_strength"], 64),
				SigningAlgorithm: clip(r["signing_algorithm"], 64),
				SubjectKeyID:     clip(r["subject_key_id"], 128),
				AuthorityKeyID:   clip(r["authority_key_id"], 128),
			},
			// The osquery certificates table (5.x) exposes no private-key or
			// exportability column on any platform.
			Custody: &submit.Custody{PrivateKey: submit.KeyUnknown},
		}
	case QueryKeystoresWindows, QueryKeystoresPosix:
		p := r["path"]
		sum := strings.ToLower(strings.TrimSpace(r["sha256"]))
		if !isAbs(p) || len(p) > 4096 {
			st["bad_path"]++
			return submit.Observation{}, false
		}
		if !hex64.MatchString(sum) {
			st["bad_sha256"]++
			return submit.Observation{}, false
		}
		fd := &submit.FileDigest{SHA256: sum}
		if n, err := strconv.ParseInt(r["size"], 10, 64); err == nil && n >= 0 {
			fd.Size = &n
		}
		obs.Target = submit.Target{Kind: submit.KindFile, Host: host, Path: p}
		obs.Outcome = submit.OutcomeReached
		obs.Adapter = &submit.AdapterEvidence{Source: Source, File: fd}
	default:
		st["unknown_query"]++
		return submit.Observation{}, false
	}
	return obs, true
}

// storeLocator builds "<platform>/<location>[/<sid>]/<store>".
func storeLocator(query string, r row) string {
	if query == QueryCertificatesPosix {
		return "posix/system"
	}
	loc := component(r["store_location"])
	store := component(r["store"])
	sid := component(r["sid"])
	switch {
	case sid != "unknown" && loc != "LocalMachine":
		return clip("windows/"+loc+"/"+sid+"/"+store, 512)
	default:
		return clip("windows/"+loc+"/"+store, 512)
	}
}

func component(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "/", "_"))
	if s == "" {
		return "unknown"
	}
	return s
}

func isAbs(p string) bool {
	return strings.HasPrefix(p, "/") || winAbs.MatchString(p)
}

func epoch(s string) *time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	t := time.Unix(n, 0).UTC()
	return &t
}

func flag(s string) *bool {
	var b bool
	switch strings.TrimSpace(s) {
	case "1", "true":
		b = true
	case "0", "false":
		b = false
	default:
		return nil
	}
	return &b
}

// clip shortens s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// sortObservations orders observations deterministically.
func sortObservations(obs []submit.Observation) {
	k := func(o submit.Observation) string {
		id := ""
		if o.Adapter != nil && o.Adapter.Certificate != nil {
			id = o.Adapter.Certificate.SHA1
		}
		if o.Adapter != nil && o.Adapter.File != nil {
			id = o.Adapter.File.SHA256
		}
		return strings.Join([]string{o.Target.Host, o.Target.Kind, o.Target.Store, o.Target.Path, id, o.ObservedAt.Format(time.RFC3339)}, "\x00")
	}
	sort.SliceStable(obs, func(i, j int) bool { return k(obs[i]) < k(obs[j]) })
}
