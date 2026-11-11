// Package identity keeps the collector's enrolled identity on this host: its
// private key and client certificate (mTLS to the core), the core's CA
// bundle pinned at enrolment, and the scope-signing keys pinned for scope
// verification.
//
// The private key is generated here and never leaves the host: only a CSR
// is sent to the core. The key and its certificate chain are kept together
// in one file (identity.pem, mode 0600) that is replaced with a single
// rename, so a crash during renewal can never leave a key that does not
// match its certificate. The state directory is mode 0700.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"
)

// Files in the state directory.
const (
	identityFile  = "identity.pem"    // PRIVATE KEY + CERTIFICATE chain, 0600
	caFile        = "ca.pem"          // the core's CA bundle, pinned
	scopeKeysFile = "scope-keys.json" // the pinned scope-signing keys
	metaFile      = "identity.json"   // collector id and core URL
)

// DefaultDir is the state directory when MEISCOPE_STATE_DIR is unset.
const DefaultDir = "/var/lib/meiscope-collector"

var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ScopeSigningKey is one pinned scope-signing key (schema ScopeSigningKey).
// The JSON shape is also that of MEISCOPE_SCOPE_KEYS.
type ScopeSigningKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// Credentials is the core's answer to POST /enrol and POST /certificate
// (schema CollectorCredentials).
type Credentials struct {
	CollectorID      string            `json:"collector_id"`
	CertificateChain string            `json:"certificate_chain"`
	CABundle         string            `json:"ca_bundle"`
	ScopeSigningKeys []ScopeSigningKey `json:"scope_signing_keys"`
	NotAfter         time.Time         `json:"not_after"`
}

type meta struct {
	CollectorID string `json:"collector_id"`
	CoreURL     string `json:"core_url"`
}

// NewKey generates the collector's key pair (ECDSA P-256).
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CSR returns a PEM certificate signing request signed by key that asks for
// nothing: an empty subject, no subject alternative names, no extensions and
// no attributes. The core decides the certificate's contents.
func CSR(key crypto.Signer) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// Store is an enrolled identity, loaded from or saved to its directory.
// It is safe for concurrent use; Replace swaps in a renewed certificate.
type Store struct {
	dir string

	mu    sync.RWMutex
	gen   uint64
	id    string
	core  string
	cert  *tls.Certificate
	roots *x509.CertPool
	keys  []ScopeSigningKey
}

// parsed is the checked content of a set of credentials.
type parsed struct {
	cert  *tls.Certificate
	roots *x509.CertPool
}

// check validates cred against key: a non-empty certificate chain whose leaf
// carries key's public key, a CA bundle with at least one certificate, and
// one or two well-formed scope-signing keys.
func check(key crypto.Signer, cred Credentials) (parsed, error) {
	if cred.CollectorID == "" {
		return parsed{}, errors.New("credentials: collector_id is empty")
	}
	var chain [][]byte
	rest := []byte(cred.CertificateChain)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return parsed{}, fmt.Errorf("credentials: certificate_chain holds a %q block", b.Type)
		}
		chain = append(chain, b.Bytes)
	}
	if len(chain) == 0 {
		return parsed{}, errors.New("credentials: certificate_chain holds no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return parsed{}, fmt.Errorf("credentials: leaf certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) {
		return parsed{}, errors.New("credentials: the certificate is not for this collector's key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cred.CABundle)) {
		return parsed{}, errors.New("credentials: ca_bundle holds no certificate")
	}
	if n := len(cred.ScopeSigningKeys); n < 1 || n > 2 {
		return parsed{}, fmt.Errorf("credentials: %d scope-signing keys, want 1 or 2", n)
	}
	for _, k := range cred.ScopeSigningKeys {
		if !keyIDPattern.MatchString(k.KeyID) {
			return parsed{}, fmt.Errorf("credentials: malformed scope-signing key id %q", k.KeyID)
		}
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != 32 {
			return parsed{}, fmt.Errorf("credentials: scope-signing key %q is not a 32-byte Ed25519 key", k.KeyID)
		}
	}
	return parsed{
		cert:  &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf},
		roots: roots,
	}, nil
}

// Exists reports whether dir holds an identity.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, identityFile))
	return err == nil
}

// Save checks cred against key and writes the identity into dir, creating
// dir (0700) if needed. core is the core URL the collector enrolled with.
func Save(dir, core string, key crypto.Signer, cred Credentials) (*Store, error) {
	p, err := check(key, cred)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	s := &Store{dir: dir}
	if err := s.write(core, key, cred, p); err != nil {
		return nil, err
	}
	return s, nil
}

// write persists cred and swaps it into memory. The CA bundle, the scope
// keys and the metadata are written before identity.pem, whose rename makes
// the new key and certificate current together.
func (s *Store) write(core string, key crypto.Signer, cred Credentials, p parsed) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, c := range p.cert.Certificate {
		idPEM = append(idPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keys, err := json.MarshalIndent(cred.ScopeSigningKeys, "", "  ")
	if err != nil {
		return err
	}
	m, err := json.MarshalIndent(meta{CollectorID: cred.CollectorID, CoreURL: core}, "", "  ")
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		perm fs.FileMode
	}{
		{caFile, []byte(cred.CABundle), 0o644},
		{scopeKeysFile, append(keys, '\n'), 0o644},
		{metaFile, append(m, '\n'), 0o644},
		{identityFile, idPEM, 0o600},
	} {
		if err := writeAtomic(s.dir, f.name, f.data, f.perm); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	s.id, s.core = cred.CollectorID, core
	s.cert, s.roots = p.cert, p.roots
	s.keys = append([]ScopeSigningKey(nil), cred.ScopeSigningKeys...)
	return nil
}

// writeAtomic writes data to dir/name through a temporary file and a rename.
func writeAtomic(dir, name string, data []byte, perm fs.FileMode) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	ok = true
	return nil
}

// Load reads the identity in dir. It refuses an identity.pem that other
// users can read or write (on systems with POSIX permissions).
func Load(dir string) (*Store, error) {
	idPath := filepath.Join(dir, identityFile)
	st, err := os.Stat(idPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("not enrolled: no %s in %s (run meiscope-collector enrol)", identityFile, dir)
		}
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by other users (mode %v); it must be 0600", idPath, st.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Clean(idPath))
	if err != nil {
		return nil, err
	}
	var key crypto.Signer
	var chain []byte
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: private key: %w", identityFile, err)
			}
			signer, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("%s: unsupported private key type", identityFile)
			}
			key = signer
		case "CERTIFICATE":
			chain = append(chain, pem.EncodeToMemory(b)...)
		default:
			return nil, fmt.Errorf("%s: unexpected %q block", identityFile, b.Type)
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%s holds no private key", identityFile)
	}
	ca, err := os.ReadFile(filepath.Clean(filepath.Join(dir, caFile)))
	if err != nil {
		return nil, err
	}
	var keys []ScopeSigningKey
	if err := readJSON(filepath.Join(dir, scopeKeysFile), &keys); err != nil {
		return nil, err
	}
	var m meta
	if err := readJSON(filepath.Join(dir, metaFile), &m); err != nil {
		return nil, err
	}
	cred := Credentials{CollectorID: m.CollectorID, CertificateChain: string(chain), CABundle: string(ca), ScopeSigningKeys: keys}
	p, err := check(key, cred)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &Store{
		dir: dir, gen: 1, id: m.CollectorID, core: m.CoreURL,
		cert: p.cert, roots: p.roots, keys: keys,
	}, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

// Replace checks and saves renewed credentials for key and makes them
// current. The core URL is kept.
func (s *Store) Replace(key crypto.Signer, cred Credentials) error {
	p, err := check(key, cred)
	if err != nil {
		return err
	}
	if cred.CollectorID != s.CollectorID() {
		return fmt.Errorf("credentials: renewed for collector %s, this collector is %s", cred.CollectorID, s.CollectorID())
	}
	return s.write(s.CoreURL(), key, cred, p)
}

// CollectorID is the collector's id at the core.
func (s *Store) CollectorID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

// CoreURL is the core URL the collector enrolled with.
func (s *Store) CoreURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.core
}

// NotBefore and NotAfter are the current certificate's validity.
func (s *Store) NotBefore() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert.Leaf.NotBefore
}

// NotAfter is when the current certificate expires.
func (s *Store) NotAfter() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert.Leaf.NotAfter
}

// RenewAt is two thirds into the current certificate's lifetime, when the
// collector renews (contract: POST /certificate).
func (s *Store) RenewAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nb, na := s.cert.Leaf.NotBefore, s.cert.Leaf.NotAfter
	return nb.Add(na.Sub(nb) * 2 / 3)
}

// ScopeKeys returns the pinned scope-signing keys.
func (s *Store) ScopeKeys() []ScopeSigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ScopeSigningKey(nil), s.keys...)
}

// current returns the certificate, roots and generation in effect.
func (s *Store) current() (*tls.Certificate, *x509.CertPool, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert, s.roots, s.gen
}
