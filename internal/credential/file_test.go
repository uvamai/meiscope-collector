package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func newStore(t *testing.T) FileSource {
	t.Helper()
	dir := t.TempDir()
	f := FileSource{Path: filepath.Join(dir, "credentials.age"), IdentityPath: filepath.Join(dir, "identity.txt")}
	if err := InitIdentity(f.IdentityPath); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileSourceRoundTrip(t *testing.T) {
	f := newStore(t)
	if _, err := f.Get(context.Background(), "fleet_api_token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	const secret = "synthetic-token-0123456789"
	if err := f.Set("fleet_api_token", secret); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("buffer_key", "another-synthetic-value"); err != nil {
		t.Fatal(err)
	}
	s, err := f.Get(context.Background(), "fleet_api_token")
	if err != nil || s.Reveal() != secret {
		t.Fatalf("got %v", err)
	}
	refs, err := f.Refs()
	if err != nil || strings.Join(refs, ",") != "buffer_key,fleet_api_token" {
		t.Fatalf("refs %v %v", refs, err)
	}
	raw, _ := os.ReadFile(f.Path) //nolint:gosec // test-only
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "fleet_api_token") {
		t.Fatal("the credential file is not encrypted")
	}
	if _, err := f.Get(context.Background(), "Bad Ref"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid ref: %v", err)
	}
}

func TestFileSourceWrongIdentityAndDamage(t *testing.T) {
	f := newStore(t)
	if err := f.Set("a_key", "value-one"); err != nil {
		t.Fatal(err)
	}
	other := newStore(t)
	wrong := FileSource{Path: f.Path, IdentityPath: other.IdentityPath}
	_, err := wrong.Get(context.Background(), "a_key")
	if err == nil || strings.Contains(err.Error(), "value-one") {
		t.Fatalf("wrong identity: %v", err)
	}
	if err := os.WriteFile(f.Path, []byte("not age"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(context.Background(), "a_key"); err == nil {
		t.Fatal("damaged file accepted")
	}
	bad := FileSource{Path: f.Path, IdentityPath: filepath.Join(t.TempDir(), "missing")}
	if _, err := bad.Get(context.Background(), "a_key"); err == nil {
		t.Fatal("missing identity accepted")
	}
	notID := filepath.Join(t.TempDir(), "id")
	_ = os.WriteFile(notID, []byte("hello"), 0o600)
	if _, err := (FileSource{Path: f.Path, IdentityPath: notID}).Get(context.Background(), "a_key"); err == nil {
		t.Fatal("non-identity file accepted")
	}
}

func TestFileSourceRejectsOpenIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	f := newStore(t)
	if err := f.Set("a_key", "v"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.IdentityPath, 0o644); err != nil { //nolint:gosec // the test makes the file readable on purpose
		t.Fatal(err)
	}
	if _, err := f.Get(context.Background(), "a_key"); !errors.Is(err, ErrIdentityPermissions) {
		t.Fatalf("want ErrIdentityPermissions, got %v", err)
	}
}

func TestSetAndInitValidation(t *testing.T) {
	f := newStore(t)
	if err := f.Set("Bad Ref", "v"); err == nil {
		t.Fatal("bad ref accepted")
	}
	if err := f.Set("ok_ref", ""); err == nil {
		t.Fatal("empty value accepted")
	}
	if err := InitIdentity(f.IdentityPath); err == nil {
		t.Fatal("identity overwritten")
	}
}

func TestFileSourceDamagedContent(t *testing.T) {
	f := newStore(t)
	if err := f.Set("a_key", "v"); err != nil {
		t.Fatal(err)
	}
	// An age file that decrypts but holds no reference map.
	ids, err := f.identities()
	if err != nil {
		t.Fatal(err)
	}
	x := ids[0].(*age.X25519Identity)
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, x.Recipient())
	_, _ = w.Write([]byte(`["not","a","map"]`))
	_ = w.Close()
	if err := os.WriteFile(f.Path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(context.Background(), "a_key"); err == nil || !strings.Contains(err.Error(), "reference map") {
		t.Fatalf("%v", err)
	}
	if _, err := f.Refs(); err == nil {
		t.Fatal("Refs accepted a damaged file")
	}
	if err := f.Set("b_key", "v"); err == nil {
		t.Fatal("Set rewrote a damaged file")
	}
}

func TestInitIdentityUnwritableDirectory(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	if err := InitIdentity(filepath.Join(blocker, "sub", "id.txt")); err == nil {
		t.Fatal("created an identity below a file")
	}
}

func TestSecretNeverLeaksFromFileSourceErrors(t *testing.T) {
	f := newStore(t)
	if err := f.Set("a_key", "very-secret-synthetic-value"); err != nil {
		t.Fatal(err)
	}
	other := newStore(t)
	_, err := FileSource{Path: f.Path, IdentityPath: other.IdentityPath}.Get(context.Background(), "a_key")
	if err == nil || strings.Contains(err.Error(), "very-secret-synthetic-value") {
		t.Fatalf("%v", err)
	}
}

func TestSecretEmptyAndUnwritableStore(t *testing.T) {
	if !NewSecret("").Empty() || NewSecret("x").Empty() {
		t.Fatal("Empty")
	}
	f := newStore(t)
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	f.Path = filepath.Join(blocker, "creds.age")
	if err := f.Set("a_key", "v"); err == nil {
		t.Fatal("wrote a credential file below a file")
	}
	// An identity path that is a directory.
	d := FileSource{Path: f.Path, IdentityPath: t.TempDir()}
	if _, err := d.identities(); err == nil {
		t.Fatal("a directory was accepted as an identity file")
	}
}
