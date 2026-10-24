package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"filippo.io/age"

	"github.com/uvamai/meiscope-collector/internal/fsutil"
)

// FileSource reads credentials from an age-encrypted file (ADR-0009: the
// secret stays with the customer; nothing outside this package can read a
// value). The file holds one JSON object {"reference": "value"} encrypted to
// the X25519 recipient of the collector's own identity file (the collector's
// keystore), which is a local file with mode 0600. Every Get decrypts the
// file anew, so values live in memory only for the call that needs them.
//
// Create both files with InitIdentity and SetFile (or the "credential"
// command). The identity file protects the credential file only against
// copies of the credential file taken without the identity file; protect the
// identity file with file permissions and, where the platform allows, a
// hardware-backed or vault-backed source (WP3.4).
type FileSource struct {
	// Path is the encrypted credential file.
	Path string
	// IdentityPath is the age identity file (the collector's keystore).
	IdentityPath string
}

// ErrIdentityPermissions is returned for an identity file others can read.
var ErrIdentityPermissions = errors.New("the identity file must not be accessible to group or others (chmod 600)")

// Get returns the credential for ref or ErrNotFound.
func (f FileSource) Get(_ context.Context, ref string) (Secret, error) {
	if !refPattern.MatchString(ref) {
		return Secret{}, fmt.Errorf("invalid credential reference %q", ref)
	}
	m, err := f.load()
	if err != nil {
		return Secret{}, err
	}
	v, ok := m[ref]
	if !ok || v == "" {
		return Secret{}, ErrNotFound
	}
	return NewSecret(v), nil
}

// Refs lists the references the file holds (never the values).
func (f FileSource) Refs() ([]string, error) {
	m, err := f.load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (f FileSource) identities() ([]age.Identity, error) {
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(f.IdentityPath)
		if err != nil {
			return nil, fmt.Errorf("credential identity: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("credential identity %s: %w", f.IdentityPath, ErrIdentityPermissions)
		}
	}
	fh, err := os.Open(filepath.Clean(f.IdentityPath))
	if err != nil {
		return nil, fmt.Errorf("credential identity: %w", err)
	}
	defer func() { _ = fh.Close() }()
	ids, err := age.ParseIdentities(fh)
	if err != nil {
		return nil, errors.New("credential identity file is not an age identity file")
	}
	return ids, nil
}

// load decrypts the file; a missing file is an empty store.
func (f FileSource) load() (map[string]string, error) {
	enc, err := os.ReadFile(filepath.Clean(f.Path))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("credential file: %w", err)
	}
	ids, err := f.identities()
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(enc), ids...)
	if err != nil {
		return nil, errors.New("credential file cannot be decrypted with the identity file")
	}
	plain, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, errors.New("credential file is damaged")
	}
	m := map[string]string{}
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, errors.New("credential file does not hold a reference map")
	}
	return m, nil
}

// InitIdentity creates a new age identity file with mode 0600. It refuses to
// overwrite an existing file.
func InitIdentity(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("# meiscope-collector credential keystore (age identity); keep private\n"+id.String()+"\n"), 0o600)
}

// Set stores value under ref, re-encrypting the whole file to the identity's
// recipient. The reference must be valid and the value non-empty.
func (f FileSource) Set(ref, value string) error {
	if !refPattern.MatchString(ref) {
		return fmt.Errorf("invalid credential reference %q", ref)
	}
	if value == "" {
		return errors.New("empty credential value")
	}
	m, err := f.load()
	if err != nil {
		return err
	}
	m[ref] = value
	ids, err := f.identities()
	if err != nil {
		return err
	}
	var recips []age.Recipient
	for _, id := range ids {
		x, ok := id.(*age.X25519Identity)
		if !ok {
			return errors.New("credential identity must be an X25519 identity")
		}
		recips = append(recips, x.Recipient())
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recips...)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(f.Path, buf.Bytes())
}
