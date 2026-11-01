//go:build !devcredentials

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/credential"
)

// Release builds have no environment-variable credential source: it exists
// only with -tags devcredentials (tests, "task build:dev").

// devCredentialGuard refuses to run when development credential variables
// are present, so nobody believes they are being used.
func devCredentialGuard() error {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "MEISCOPE_DEV_CREDENTIAL_") {
			return errors.New("MEISCOPE_DEV_CREDENTIAL_* variables are set, but this build has no development credential source; " +
				"store credentials with \"meiscope-collector credential set\" and set MEISCOPE_CREDENTIAL_FILE and MEISCOPE_CREDENTIAL_KEY_FILE (development builds: task build:dev)")
		}
	}
	return nil
}

func defaultCredentialSource(getenv func(string) string) credential.Source {
	if src, ok := fileSource(getenv); ok {
		return src
	}
	return credential.None{}
}
