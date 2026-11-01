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

func TestNoneHoldsNothing(t *testing.T) {
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
