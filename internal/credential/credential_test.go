package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret("hunter2")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "key", s)
	j, _ := json.Marshal(struct{ K Secret }{s})
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), buf.String(), string(j)} {
		if strings.Contains(out, "hunter2") {
			t.Fatalf("secret leaked: %s", out)
		}
	}
}
