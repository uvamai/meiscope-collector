package submittest

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
)

// SpecPath returns the path of the vendored api/collector.yaml.
func SpecPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "collector.yaml")
}

// Core is a fake core. Each request must be gzip JSON that validates as an
// ObservationBatch; an invalid request gets 400 and is recorded in Errors.
type Core struct {
	*httptest.Server
	spec *Spec

	mu      sync.Mutex
	batches []json.RawMessage
	errors  []string
	forced  []int
}

// NewCore starts a fake core validating against the vendored spec.
func NewCore() (*Core, error) {
	spec, err := LoadSpec(SpecPath())
	if err != nil {
		return nil, err
	}
	c := &Core{spec: spec}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /collector/v1/observations", c.handle)
	c.Server = httptest.NewTLSServer(mux) // the core is https only; use Client()
	return c, nil
}

// FailNext makes the next len(statuses) requests answer with these statuses
// (for example 503 to force a retry) before any validation.
func (c *Core) FailNext(statuses ...int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forced = append(c.forced, statuses...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *Core) handle(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	if len(c.forced) > 0 {
		st := c.forced[0]
		c.forced = c.forced[1:]
		c.mu.Unlock()
		writeJSON(w, st, map[string]any{"title": http.StatusText(st), "status": st})
		return
	}
	c.mu.Unlock()
	fail := func(msg string) {
		c.mu.Lock()
		c.errors = append(c.errors, msg)
		c.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"title": "Bad Request", "status": 400, "detail": msg})
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail("Content-Type must be application/json")
		return
	}
	if r.Header.Get("Content-Encoding") != "gzip" {
		fail("body must be gzip-encoded")
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		fail("gzip: " + err.Error())
		return
	}
	body, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		fail("read: " + err.Error())
		return
	}
	if err := c.spec.Validate("ObservationBatch", body); err != nil {
		fail(err.Error())
		return
	}
	var batch struct {
		Observations []json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal(body, &batch); err != nil {
		fail(err.Error())
		return
	}
	c.mu.Lock()
	c.batches = append(c.batches, body)
	c.mu.Unlock()
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(batch.Observations), "duplicates": 0, "rejected": []any{}})
}

// Batches returns the decompressed bodies of the accepted batches.
func (c *Core) Batches() []json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]json.RawMessage(nil), c.batches...)
}

// Errors returns the validation errors of refused requests.
func (c *Core) Errors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.errors...)
}
