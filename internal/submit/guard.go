package submit

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ErrPrivateKeyMaterial refuses an observation that carries PEM private-key
// armour in any field. Private keys never leave the host; no observation
// field may hold one, so this is a last check before anything is encoded
// for the core or written to the local buffer. The error never includes the
// offending text.
var ErrPrivateKeyMaterial = errors.New("observation carries private-key material (a PEM PRIVATE KEY block); it is not sent or buffered")

// privateKeyArmour matches the PEM header of any private key: PKCS#8
// ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"), PKCS#1 and SEC 1 ("RSA", "EC",
// "DSA") and OpenSSH ("OPENSSH PRIVATE KEY").
var privateKeyArmour = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

// containsPrivateKey reports whether the JSON encoding of v has PEM
// private-key armour in it. JSON keeps the armour's characters as they are.
func containsPrivateKey(b []byte) bool { return privateKeyArmour.Match(b) }

// CheckObservations returns an error wrapping ErrPrivateKeyMaterial, naming
// the index of the first offending observation, when any observation has
// PEM private-key armour in one of its fields.
func CheckObservations(obs []Observation) error {
	for i := range obs {
		b, err := json.Marshal(&obs[i])
		if err != nil {
			return fmt.Errorf("observation %d: %w", i, err)
		}
		if containsPrivateKey(b) {
			return fmt.Errorf("observation %d: %w", i, ErrPrivateKeyMaterial)
		}
	}
	return nil
}
