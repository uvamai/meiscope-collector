// Package credential is the collector's only way to obtain a credential
// (CLAUDE.md: credentials come only through the CredentialSource interface
// and are never written to disk, logs or observations).
//
// Production sources lease from the customer's vault and arrive with the
// adapter framework (WP1.1). The development-only EnvSource exists only in builds with the devcredentials tag (env_dev.go).
package credential

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
)

// ErrNotFound means the source holds no credential for the reference. Callers
// that can work without one (the Cert Spotter free tier) treat it as "none".
var ErrNotFound = errors.New("credential not found")

// Source returns the credential for a reference such as "certspotter_api_key".
type Source interface {
	Get(ctx context.Context, ref string) (Secret, error)
}

// Secret holds a credential value. It never prints or logs its value.
type Secret struct{ v string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the value, for the single call that uses it.
func (s Secret) Reveal() string { return s.v }

// Empty reports whether the secret has no value.
func (s Secret) Empty() bool { return s.v == "" }

// String redacts the value.
func (s Secret) String() string { return "[redacted]" }

// GoString redacts the value in %#v.
func (s Secret) GoString() string { return "credential.Secret{[redacted]}" }

// LogValue redacts the value in slog records.
func (s Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalText redacts the value so it cannot leak into JSON or YAML.
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

var refPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// None is a source that holds no credentials.
type None struct{}

// Get always returns ErrNotFound.
func (None) Get(context.Context, string) (Secret, error) { return Secret{}, ErrNotFound }
