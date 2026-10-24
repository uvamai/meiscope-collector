//go:build devcredentials

package credential

import (
	"context"
	"errors"
	"testing"
)

func TestEnvSource(t *testing.T) {
	src := EnvSource{Getenv: func(k string) string {
		if k == "MEISCOPE_DEV_CREDENTIAL_CERTSPOTTER_API_KEY" {
			return " k-123 "
		}
		return ""
	}}
	s, err := src.Get(context.Background(), "certspotter_api_key")
	if err != nil || s.Reveal() != "k-123" {
		t.Fatalf("got %q, %v", s.Reveal(), err)
	}
	if _, err := src.Get(context.Background(), "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := src.Get(context.Background(), "../etc"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("want invalid reference error, got %v", err)
	}
	if _, err := (None{}).Get(context.Background(), "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("None: %v", err)
	}
}
