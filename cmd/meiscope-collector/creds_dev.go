//go:build devcredentials

package main

import "github.com/uvamai/meiscope-collector/internal/credential"

// Development builds (-tags devcredentials) may read credentials from
// MEISCOPE_DEV_CREDENTIAL_<REF> when no credential file is configured.

func devCredentialGuard() error { return nil }

func defaultCredentialSource(getenv func(string) string) credential.Source {
	if src, ok := fileSource(getenv); ok {
		return src
	}
	return credential.EnvSource{Getenv: getenv}
}
