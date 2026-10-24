package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/uvamai/meiscope-collector/internal/fsutil"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// CursorStore persists each adapter instance's cursor in one JSON file.
// An empty path keeps cursors in memory only.
type CursorStore struct {
	path string
	mu   sync.Mutex
	m    map[string]Cursor
}

// LoadCursors opens the cursor file at path (missing: empty store).
func LoadCursors(path string) (*CursorStore, error) {
	s := &CursorStore{path: path, m: map[string]Cursor{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("adapter cursors: %w", err)
	}
	if err := json.Unmarshal(b, &s.m); err != nil {
		return nil, fmt.Errorf("adapter cursors %s: %w", path, err)
	}
	return s, nil
}

// Get returns the stored cursor of an instance.
func (s *CursorStore) Get(name string) Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[name]
}

// Set stores an instance's cursor durably.
func (s *CursorStore) Set(name string, c Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[name] = c
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", " ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, b)
}

// Sink takes observations durably (the buffer) or delivers them (submit).
type Sink interface {
	Enqueue(ctx context.Context, obs []submit.Observation) error
}

// RunOnce syncs one adapter instance from its stored cursor, hands the
// observations to the sink and only then advances the cursor, so a failure
// anywhere before that repeats the same delta next time instead of losing it.
func RunOnce(ctx context.Context, env Env, cfg Config, cursors *CursorStore, sink Sink) (int, error) {
	f, ok := Lookup(cfg.Adapter)
	if !ok {
		return 0, fmt.Errorf("unknown adapter %q (known: %v)", cfg.Adapter, Names())
	}
	if err := cfg.Check(); err != nil {
		return 0, err
	}
	a := f(env)
	if err := a.Validate(cfg); err != nil {
		return 0, fmt.Errorf("adapter %s: %w", cfg.Name, err)
	}
	res, err := a.Sync(ctx, cfg, cursors.Get(cfg.Name))
	if err != nil {
		return 0, fmt.Errorf("adapter %s: %w", cfg.Name, err)
	}
	if len(res.Observations) > 0 {
		if err := sink.Enqueue(ctx, res.Observations); err != nil {
			return 0, fmt.Errorf("adapter %s: %w", cfg.Name, err)
		}
	}
	if err := cursors.Set(cfg.Name, res.Cursor); err != nil {
		return len(res.Observations), fmt.Errorf("adapter %s: observations buffered but cursor not saved (they will be read again): %w", cfg.Name, err)
	}
	return len(res.Observations), nil
}
