package submit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
)

// TestSubmitRefusesPrivateKeyMaterial: a batch with PEM private-key armour
// in any observation field is not encoded, so nothing reaches the core.
func TestSubmitRefusesPrivateKeyMaterial(t *testing.T) {
	core := newCore(t)
	cl, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, armour := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		bad := ctObservation(2)
		bad.Target.Path = armour
		obs := []submit.Observation{ctObservation(0), ctObservation(1), bad}
		_, err := cl.Submit(context.Background(), obs)
		if !errors.Is(err, submit.ErrPrivateKeyMaterial) || !strings.Contains(err.Error(), "observation 2") {
			t.Fatalf("%s: err %v", armour, err)
		}
		if err := submit.CheckObservations(obs); !errors.Is(err, submit.ErrPrivateKeyMaterial) {
			t.Fatalf("CheckObservations: %v", err)
		}
	}
	if n := len(core.Batches()); n != 0 {
		t.Fatalf("%d batches reached the core", n)
	}
	// Public certificate armour is not a key.
	ok := ctObservation(0)
	ok.Target.Path = "-----BEGIN CERTIFICATE-----"
	if err := submit.CheckObservations([]submit.Observation{ok}); err != nil {
		t.Fatalf("certificate armour refused: %v", err)
	}
}
