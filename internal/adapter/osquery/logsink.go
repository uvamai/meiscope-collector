package osquery

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// DefaultMaxLineBytes caps one log line (a snapshot of every certificate on
// a host is one line).
const DefaultMaxLineBytes = 64 << 20

// logCursor remembers, per log file, how far it was read. Files are keyed
// by a digest of their first line, not their name, so a file renamed by
// log rotation (osqueryd.results.log -> .1) continues where it was.
type logCursor struct {
	Files map[string]int64 `json:"files"`
}

// logEvent is one line of osquery's filesystem (or any JSON) logger:
// either a differential event with columns or a snapshot with rows.
type logEvent struct {
	Name           string           `json:"name"`
	HostIdentifier string           `json:"hostIdentifier"`
	UnixTime       json.Number      `json:"unixTime"`
	Action         string           `json:"action"`
	Columns        map[string]any   `json:"columns"`
	Snapshot       []map[string]any `json:"snapshot"`
}

// syncLogSink reads complete new lines of every *.log, *.json and *.jsonl
// file in dir (not recursively), in name order. A partial last line is left
// for the next sync. Within one sync only the latest snapshot per host and
// query is mapped; "removed" differential events are skipped (the core
// infers disappearance from later snapshots).
func (a *Adapter) syncLogSink(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := logCursor{Files: map[string]int64{}}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	dir := cfg.Setting("dir", "")
	maxLine := intSetting(cfg, "max_line_bytes", DefaultMaxLineBytes)
	files, err := logFiles(dir)
	if err != nil {
		return adapter.Result{}, err
	}
	next := logCursor{Files: map[string]int64{}}
	st := stats{}
	type key struct{ host, query string }
	snapshots := map[key][]submit.Observation{}
	var events []submit.Observation
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return adapter.Result{}, err
		}
		id, ok, err := fileID(f, maxLine)
		if err != nil {
			return adapter.Result{}, err
		}
		if !ok {
			continue // no complete line yet
		}
		off := cur.Files[id]
		end, err := readLines(f, off, maxLine, func(line []byte) {
			var ev logEvent
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.UseNumber()
			if err := dec.Decode(&ev); err != nil {
				st["bad_line"]++
				return
			}
			q, ok := queryOf(ev.Name)
			if !ok {
				st["other_query"]++
				return
			}
			at := a.env.Clock.Now()
			if n, err := ev.UnixTime.Int64(); err == nil && n > 0 {
				at = time.Unix(n, 0)
			}
			switch {
			case ev.Snapshot != nil:
				var obs []submit.Observation
				for _, r := range ev.Snapshot {
					if o, ok := mapRow(q, ev.HostIdentifier, at, toRow(r), st); ok {
						obs = append(obs, o)
					}
				}
				snapshots[key{ev.HostIdentifier, q}] = obs
			case ev.Action == "removed":
				st["removed_event"]++
			case ev.Columns != nil:
				if o, ok := mapRow(q, ev.HostIdentifier, at, toRow(ev.Columns), st); ok {
					events = append(events, o)
				}
			default:
				st["no_rows"]++
			}
		})
		if err != nil {
			return adapter.Result{}, err
		}
		next.Files[id] = end
	}
	obs := events
	for _, s := range snapshots {
		obs = append(obs, s...)
	}
	a.logStats(ModeLogSink, st)
	sortObservations(obs)
	c, err := adapter.EncodeCursor(next)
	return adapter.Result{Observations: obs, Cursor: c}, err
}

func logFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("logsink: %w", err)
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(n, ".") {
			continue
		}
		base := strings.TrimRight(n, ".0123456789") // rotated: x.log.1
		switch filepath.Ext(base) {
		case ".log", ".json", ".jsonl":
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out, nil
}

// fileID is a digest of the file's first complete line.
func fileID(path string, maxLine int) (string, bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", false, fmt.Errorf("logsink: %w", err)
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(io.LimitReader(f, int64(maxLine)+1))
	line, err := r.ReadBytes('\n')
	if errors.Is(err, io.EOF) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("logsink: %w", err)
	}
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:16]), true, nil
}

// readLines calls fn for each complete line from offset off and returns the
// offset after the last complete line. A file shorter than off was
// truncated in place and is read from the start.
func readLines(path string, off int64, maxLine int, fn func([]byte)) (int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return off, fmt.Errorf("logsink: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return off, fmt.Errorf("logsink: %w", err)
	}
	if fi.Size() < off {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off, fmt.Errorf("logsink: %w", err)
	}
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, n, err := readLine(r, maxLine)
		if errors.Is(err, io.EOF) {
			return off, nil
		}
		if err != nil && !errors.Is(err, errLineTooLong) {
			return off, fmt.Errorf("logsink: %w", err)
		}
		off += int64(n)
		if t := bytes.TrimSpace(line); len(t) > 0 || err != nil {
			fn(t) // a line over the cap arrives empty and counts as bad
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine returns one line and the bytes it consumed, including the
// newline. A partial last line returns io.EOF and counts as unconsumed; a
// line over maxLine is skipped with errLineTooLong.
func readLine(r *bufio.Reader, maxLine int) ([]byte, int, error) {
	var buf []byte
	n := 0
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		n += len(chunk)
		if !tooLong {
			if len(buf)+len(chunk) > maxLine {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case err == nil && tooLong:
			return nil, n, errLineTooLong
		case err == nil:
			return buf, n, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, 0, err
		}
	}
}
