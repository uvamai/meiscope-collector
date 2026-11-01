package ct

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// seenRetention is how long a fingerprint stays in the dedupe set: longer
// than the longest publicly trusted validity (398 days).
const seenRetention = 400 * 24 * time.Hour

// State is the poller's progress between cycles: Cert Spotter cursors, the
// next index per log, and the fingerprints (and serials) already submitted.
// It holds public CT data only, never credentials.
type State struct {
	CertSpotterAfter map[string]string    `json:"certspotter_after"`
	LogNext          map[string]uint64    `json:"log_next"`
	Seen             map[string]time.Time `json:"seen"`
	SeenSerials      map[string]time.Time `json:"seen_serials"`
}

// NewState returns an empty state.
func NewState() *State {
	return &State{
		CertSpotterAfter: map[string]string{},
		LogNext:          map[string]uint64{},
		Seen:             map[string]time.Time{},
		SeenSerials:      map[string]time.Time{},
	}
}

// LoadState reads a state file; a missing file is an empty state.
func LoadState(path string) (*State, error) {
	st := NewState()
	b, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read CT state: %w", err)
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse CT state %s: %w", path, err)
	}
	if st.CertSpotterAfter == nil {
		st.CertSpotterAfter = map[string]string{}
	}
	if st.LogNext == nil {
		st.LogNext = map[string]uint64{}
	}
	if st.Seen == nil {
		st.Seen = map[string]time.Time{}
	}
	if st.SeenSerials == nil {
		st.SeenSerials = map[string]time.Time{}
	}
	return st, nil
}

// Save writes the state atomically (temporary file, then rename).
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("CT state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".ct-state-*")
	if err != nil {
		return fmt.Errorf("write CT state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write CT state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write CT state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write CT state: %w", err)
	}
	return nil
}

// prune drops dedupe entries older than seenRetention.
func (s *State) prune(now time.Time) {
	for k, t := range s.Seen {
		if now.Sub(t) > seenRetention {
			delete(s.Seen, k)
		}
	}
	for k, t := range s.SeenSerials {
		if now.Sub(t) > seenRetention {
			delete(s.SeenSerials, k)
		}
	}
}
