package osquery

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// MaxPushBytes caps one pushed request body.
const MaxPushBytes = 32 << 20

// PushHandler is the HTTP-push side of the log sink: a log pipeline
// (Fluent Bit, Logstash, osquery's tls logger) POSTs osquery result events
// and the handler appends them, one JSON object per line, to
// <Dir>/push-<UTC date>.jsonl, which the logsink mode then reads. Bodies
// may be newline-delimited JSON, a JSON array of events, or osquery's tls
// logger envelope {"log_type": "result", "data": [...]}. Every request must
// carry "Authorization: Bearer <token>" where the token is the credential
// TokenRef resolves to; it is compared in constant time and never logged.
//
// The handler is not wired to a listener by the collector command: opening
// an inbound port on the collector is a deployment decision (docs/osquery.md).
type PushHandler struct {
	Dir      string
	Creds    credential.Source
	TokenRef string
	Clock    clock.Clock

	mu sync.Mutex
}

func (h *PushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	want, err := h.Creds.Get(r.Context(), h.TokenRef)
	if err != nil || want.Empty() {
		http.Error(w, "push is not configured", http.StatusServiceUnavailable)
		return
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(want.Reveal())) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxPushBytes+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) > MaxPushBytes {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	events, err := splitEvents(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.append(events); err != nil {
		http.Error(w, "could not store events", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// splitEvents returns each event as compact JSON.
func splitEvents(body []byte) ([][]byte, error) {
	t := bytes.TrimSpace(body)
	var raws []json.RawMessage
	switch {
	case len(t) == 0:
		return nil, nil
	case t[0] == '[':
		if err := json.Unmarshal(t, &raws); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
	default:
		var env struct {
			LogType string            `json:"log_type"`
			Data    []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(t, &env) == nil && env.Data != nil {
			if env.LogType != "" && env.LogType != "result" {
				return nil, nil // status logs are not certificate data
			}
			raws = env.Data
			break
		}
		sc := bufio.NewScanner(bytes.NewReader(t))
		sc.Buffer(make([]byte, 0, 1<<20), MaxPushBytes)
		for sc.Scan() {
			if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
				raws = append(raws, append(json.RawMessage(nil), l...))
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	out := make([][]byte, 0, len(raws))
	for i, r := range raws {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(r, &obj); err != nil {
			return nil, fmt.Errorf("event %d is not a JSON object", i)
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, r); err != nil {
			return nil, err
		}
		out = append(out, buf.Bytes())
	}
	return out, nil
}

func (h *PushHandler) append(events [][]byte) error {
	if len(events) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if h.Clock != nil {
		now = h.Clock.Now()
	}
	if err := os.MkdirAll(h.Dir, 0o750); err != nil {
		return err
	}
	name := filepath.Join(h.Dir, "push-"+now.UTC().Format("20060102")+".jsonl")
	f, err := os.OpenFile(filepath.Clean(name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, e := range events {
		buf.Write(e)
		buf.WriteByte('\n')
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
