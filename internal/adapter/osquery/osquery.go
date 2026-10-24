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
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
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
			"fleet: url, team_id, queries, per_page, rate_per_second",
			"logsink: dir, max_line_bytes",
			"direct: files (comma-separated osqueryi --json outputs named <query>.json), host",
		},
		Credentials: []string{"api_token (fleet)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
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
		a.env.Log.Warn("osquery rows skipped", "mode", mode, "reason", reason, "rows", n)
	}
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
