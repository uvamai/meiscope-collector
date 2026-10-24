//go:build devcredentials

package credential

import (
	"context"
	"fmt"
	"strings"
)

// This file is compiled only with -tags devcredentials (tests and
// "task build:dev"). Release builds do not contain the environment source.

// EnvPrefix is the prefix of EnvSource variables.
const EnvPrefix = "MEISCOPE_DEV_CREDENTIAL_"

// EnvSource reads MEISCOPE_DEV_CREDENTIAL_<REF> (upper case) from the
// environment. DEVELOPMENT ONLY: environment variables are visible to other
// processes of the same user and end up in shell history; production
// deployments use a vault-backed source.
type EnvSource struct {
	Getenv func(string) string
}

// Get returns the credential for ref or ErrNotFound.
func (e EnvSource) Get(_ context.Context, ref string) (Secret, error) {
	if !refPattern.MatchString(ref) {
		return Secret{}, fmt.Errorf("invalid credential reference %q", ref)
	}
	if e.Getenv == nil {
		return Secret{}, ErrNotFound
	}
	v := strings.TrimSpace(e.Getenv(EnvPrefix + strings.ToUpper(ref)))
	if v == "" {
		return Secret{}, ErrNotFound
	}
	return NewSecret(v), nil
}
