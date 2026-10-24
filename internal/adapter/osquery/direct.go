package osquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// maxDirectBytes caps one osqueryi output file.
const maxDirectBytes = 256 << 20

// directCursor remembers the digest of each output file already read, so
// an unchanged file is not read again.
type directCursor struct {
	Files map[string]string `json:"files"`
}

// directQuery names the pack query of an output file: its base name, less
// the extension, ends with the query name (e.g. "web01-meiscope_keystores_posix.json").
func directQuery(file string) (string, error) {
	base := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	for _, q := range PackQueries {
		if strings.HasSuffix(base, q) {
			return q, nil
		}
	}
	return "", fmt.Errorf("direct: %s: the file name must end with a pack query name (%s)", filepath.Base(file), strings.Join(PackQueries, ", "))
}

// syncDirect reads osqueryi --json outputs (a JSON array of rows) for one
// host. osqueryi records no time, so observed_at is the collector's clock.
func (a *Adapter) syncDirect(_ context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := directCursor{Files: map[string]string{}}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	next := directCursor{Files: map[string]string{}}
	host := cfg.Setting("host", "")
	now := a.env.Clock.Now()
	st := stats{}
	var obs []submit.Observation
	for _, f := range splitList(cfg.Setting("files", "")) {
		q, err := directQuery(f)
		if err != nil {
			return adapter.Result{}, err
		}
		b, err := readCapped(f, maxDirectBytes)
		if err != nil {
			return adapter.Result{}, fmt.Errorf("direct: %w", err)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		next.Files[f] = digest
		if cur.Files[f] == digest {
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal(b, &rows); err != nil {
			return adapter.Result{}, fmt.Errorf("direct: %s: want osqueryi --json output (a JSON array of rows): %w", filepath.Base(f), err)
		}
		for _, r := range rows {
			if o, ok := mapRow(q, host, now, toRow(r), st); ok {
				obs = append(obs, o)
			}
		}
	}
	a.logStats(ModeDirect, st)
	sortObservations(obs)
	c, err := adapter.EncodeCursor(next)
	return adapter.Result{Observations: obs, Cursor: c}, err
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && fi.Size() > 0 {
		return nil, err
	}
	return b, nil
}
