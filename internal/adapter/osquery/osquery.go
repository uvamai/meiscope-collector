// Package osquery is the osquery adapter (FR-DISC-023). It ingests the
// results of the Meiscope query pack (packs/osquery) from systems the
// customer already runs: Fleet's API, an osquery log sink (a JSONL
// directory, filled by osquery's filesystem logger or by PushHandler), or
// direct osqueryi --json output. It maps certificate rows to store targets
// and keystore rows to file targets, with method adapter and source osquery.
// It only reads; it never runs queries on hosts or connects to them.
package osquery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Name is the adapter's registry name.
const Name = "osquery"

// Ingestion modes (setting "mode").
const (
	ModeFleet   = "fleet"
	ModeLogSink = "logsink"
	ModeDirect  = "direct"
)

func init() {
	adapter.Register(Name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env} })
}

// Adapter is the osquery adapter.
type Adapter struct {
	env adapter.Env
}

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    Name,
		Source:  Source,
		Summary: "osquery query pack results from Fleet, a log sink or osqueryi output",
		Settings: []string{
			"mode (fleet | logsink | direct)",
			"keystore_max_bytes (default 10485760, ceiling 104857600), keystore_max_files (default 1000, ceiling 10000)",
			"windows_extra_roots (comma-separated Windows folders searched in addition to the default application folders; at most 10, never a drive root or a private-key folder)",
			"fleet: url, team_id, queries, per_page, rate_per_second",
			"logsink: dir, max_line_bytes",
			"direct: files (comma-separated osqueryi --json outputs named <query>.json), host",
		},
		Credentials: []string{"api_token (fleet)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	if l, err := parseLimits(cfg); err != nil {
		return err
	} else if err := l.Validate(); err != nil {
		return err
	}
	switch m := cfg.Setting("mode", ""); m {
	case ModeFleet:
		u, err := url.Parse(cfg.Setting("url", ""))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("fleet: url must be an absolute https URL without user information")
		}
		if _, ok := cfg.Credentials["api_token"]; !ok {
			return errors.New("fleet: credentials.api_token (a credential reference) is required")
		}
		for _, q := range fleetQueries(cfg) {
			if _, ok := queryOf(q); !ok {
				return fmt.Errorf("fleet: %q is not a query of the Meiscope pack", q)
			}
		}
		if err := positiveInt(cfg, "per_page", 1, 1000); err != nil {
			return err
		}
		if v := cfg.Setting("team_id", ""); v != "" {
			if err := positiveInt(cfg, "team_id", 1, 1<<31-1); err != nil {
				return err
			}
		}
		if v := cfg.Setting("rate_per_second", ""); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err != nil || f <= 0 {
				return errors.New("fleet: rate_per_second must be a positive number")
			}
		}
	case ModeLogSink:
		if cfg.Setting("dir", "") == "" {
			return errors.New("logsink: dir is required")
		}
		if err := positiveInt(cfg, "max_line_bytes", 1024, 256<<20); err != nil {
			return err
		}
	case ModeDirect:
		if cfg.Setting("files", "") == "" || cfg.Setting("host", "") == "" {
			return errors.New("direct: files and host are required")
		}
		for _, f := range splitList(cfg.Setting("files", "")) {
			if _, err := directQuery(f); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("mode must be %s, %s or %s, got %q", ModeFleet, ModeLogSink, ModeDirect, m)
	}
	return nil
}

// Sync reads the configured source from the cursor on.
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	switch cfg.Setting("mode", "") {
	case ModeFleet:
		return a.syncFleet(ctx, cfg, since)
	case ModeLogSink:
		return a.syncLogSink(ctx, cfg, since)
	case ModeDirect:
		return a.syncDirect(ctx, cfg, since)
	default:
		return adapter.Result{}, errors.New("invalid mode")
	}
}

func (a *Adapter) logStats(mode string, st stats) {
	if a.env.Log == nil {
		return
	}
	for reason, n := range st {
		if n > 0 && !strings.HasPrefix(reason, statRootPrefix) {
			a.env.Log.Warn("osquery rows skipped", "mode", mode, "reason", reason, "rows", n)
		}
	}
	for _, id := range rootIDs(st) {
		a.env.Log.Info("osquery keystore root", "mode", mode, "root", id,
			"files_seen", st[statRootKey(id, "files_seen")],
			StatSkippedOversize, st[statRootKey(id, StatSkippedOversize)],
			StatSkippedExcluded, st[statRootKey(id, StatSkippedExcluded)],
			StatSkippedLimit, st[statRootKey(id, StatSkippedLimit)])
	}
	if st[StatSkippedFeatureDisabled] > 0 {
		a.env.Log.Warn("osquery observations were not sent because "+adapter.EnvLocalStoreV1+" is off; the core has not adopted store and file observations yet, and the cursor was not advanced",
			"mode", mode, "skipped_feature_disabled", st[StatSkippedFeatureDisabled])
	}
}

// rootIDs lists, sorted, the roots a run has per-root statistics for.
func rootIDs(st stats) []string {
	seen := map[string]bool{}
	for k := range st {
		if rest, ok := strings.CutPrefix(k, statRootPrefix); ok {
			if id, _, ok := strings.Cut(rest, "."); ok {
				seen[id] = true
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// limitsOf reads the keystore limits of a validated configuration.
func limitsOf(cfg adapter.Config) Limits {
	l := DefaultLimits()
	if n, err := strconv.ParseInt(cfg.Setting("keystore_max_bytes", ""), 10, 64); err == nil {
		l.MaxFileBytes = n
	}
	if n, err := strconv.Atoi(cfg.Setting("keystore_max_files", "")); err == nil {
		l.MaxFiles = n
	}
	l.ExtraWindowsRoots = splitList(cfg.Setting("windows_extra_roots", ""))
	return l
}

// result finishes a sync: it applies the rules of finalize, and when the
// local-store feature is off keeps the old cursor so nothing is lost for the
// day the feature is turned on.
func (a *Adapter) result(mode string, cfg adapter.Config, obs []submit.Observation, st stats, next, since adapter.Cursor) (adapter.Result, error) {
	out := finalize(obs, st, limitsOf(cfg), a.env.Features.LocalStoreV1)
	cursor := next
	if !a.env.Features.LocalStoreV1 {
		cursor = since
	}
	a.logStats(mode, st)
	if a.env.Log != nil {
		a.env.Log.Info("osquery sync", "instance", cfg.Name, "mode", mode, "observations", len(out),
			StatSkippedOversize, st[StatSkippedOversize], StatSkippedExcluded, st[StatSkippedExcluded],
			StatSkippedLimit, st[StatSkippedLimit], StatSkippedFeatureDisabled, st[StatSkippedFeatureDisabled])
	}
	return adapter.Result{Observations: out, Cursor: cursor, Stats: map[string]int(st)}, nil
}

// parseLimits reads keystore_max_bytes and keystore_max_files; values that
// are not numbers are errors, ranges are checked by Limits.Validate.
func parseLimits(cfg adapter.Config) (Limits, error) {
	l := DefaultLimits()
	if v := cfg.Setting("keystore_max_bytes", ""); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return l, errors.New("keystore_max_bytes must be an integer number of bytes")
		}
		l.MaxFileBytes = n
	}
	if v := cfg.Setting("keystore_max_files", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return l, errors.New("keystore_max_files must be an integer")
		}
		l.MaxFiles = n
	}
	l.ExtraWindowsRoots = splitList(cfg.Setting("windows_extra_roots", ""))
	return l, nil
}

func positiveInt(cfg adapter.Config, name string, lo, hi int) error {
	v := cfg.Setting(name, "")
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return fmt.Errorf("%s must be an integer in [%d, %d]", name, lo, hi)
	}
	return nil
}

func intSetting(cfg adapter.Config, name string, def int) int {
	n, err := strconv.Atoi(cfg.Setting(name, ""))
	if err != nil {
		return def
	}
	return n
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
