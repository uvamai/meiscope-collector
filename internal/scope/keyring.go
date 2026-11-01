package scope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/fsutil"
)

// Keyring is the set of scope-signing public keys the collector pinned at
// enrolment, by key ID. Up to MaxActiveKeys are active at once, so the core
// can rotate its signing key without re-enrolling collectors: it pins the new
// key alongside the old one, signs with the new one, then retires the old.
type Keyring map[string]ed25519.PublicKey

// NewKeyring validates keys.
func NewKeyring(keys map[string]ed25519.PublicKey) (Keyring, error) {
	if len(keys) == 0 || len(keys) > MaxActiveKeys {
		return nil, fmt.Errorf("scope: 1..%d signing keys must be pinned, got %d", MaxActiveKeys, len(keys))
	}
	for id, k := range keys {
		if id == "" || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("scope: signing key %q is not an Ed25519 public key with an id", id)
		}
	}
	return Keyring(keys), nil
}

// VerifyKeyring verifies s with the pinned key named by s.KeyID, then
// validates the scope as Verify does. A signature without a key ID, or with
// one that is not pinned, is refused.
func VerifyKeyring(s Signed, ring Keyring, now time.Time) (*Scope, error) {
	if len(s.Signature) == 0 || len(s.Payload) == 0 {
		return nil, ErrUnsigned
	}
	k, ok := ring[s.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	return Verify(s, k, now)
}

// ErrReplayed refuses a scope older than, or conflicting with, one already
// accepted for the same scope ID.
var ErrReplayed = errors.New("scope: older or replayed version")

// Tracker remembers the highest version accepted per scope ID, and the hash
// of its payload, so an attacker who captured an older signed scope (still
// inside its validity window) cannot make the collector run it again. With a
// path it survives restarts.
type Tracker struct {
	mu   sync.Mutex
	path string
	seen map[string]seenVersion
}

type seenVersion struct {
	Version int64    `json:"version"`
	SHA256  [32]byte `json:"sha256"`
}

// LoadTracker reads the tracker state from path (empty path: memory only;
// a missing file: empty state).
func LoadTracker(path string) (*Tracker, error) {
	t := &Tracker{path: path, seen: map[string]seenVersion{}}
	if path == "" {
		return t, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path is the operator-configured state file
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scope tracker: %w", err)
	}
	if err := json.Unmarshal(b, &t.seen); err != nil {
		return nil, fmt.Errorf("scope tracker %s: %w", path, err)
	}
	return t, nil
}

// Accept records sc (verified from payload) or refuses it: a lower version
// than the last accepted, or the same version with different bytes, is
// ErrReplayed. Accepting the same payload again is fine.
func (t *Tracker) Accept(sc *Scope, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := sha256.Sum256(payload)
	if last, ok := t.seen[sc.ID]; ok {
		if sc.Version < last.Version || (sc.Version == last.Version && h != last.SHA256) {
			return fmt.Errorf("%w: scope %s version %d (last accepted %d)", ErrReplayed, sc.ID, sc.Version, last.Version)
		}
		if sc.Version == last.Version {
			return nil
		}
	}
	t.seen[sc.ID] = seenVersion{Version: sc.Version, SHA256: h}
	if t.path == "" {
		return nil
	}
	b, err := json.Marshal(t.seen)
	if err != nil {
		return fmt.Errorf("scope tracker: %w", err)
	}
	if err := fsutil.WriteFileAtomic(t.path, b); err != nil {
		return fmt.Errorf("scope tracker: %w", err)
	}
	return nil
}
