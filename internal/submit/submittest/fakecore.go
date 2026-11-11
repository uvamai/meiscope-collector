package submittest

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// SpecPath returns the path of the vendored api/collector.yaml.
//
// When MEISCOPE_CONTRACT is set it names another contract file instead, which
// is how "task contract:diff" runs the tests against a core's file.
func SpecPath() string {
	if p := os.Getenv("MEISCOPE_CONTRACT"); p != "" {
		return p
	}
	return VendoredSpecPath()
}

// VendoredSpecPath returns the path of the vendored api/collector.yaml,
// byte-identical to the core's contract 0.8.1.
func VendoredSpecPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "collector.yaml")
}

// ProposedSpecPath returns the path of the proposed contract 0.5.0, which the
// core has not adopted (api/proposed).
func ProposedSpecPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "proposed", "collector-0.5.0-proposed.yaml")
}

// Core is a fake core. Each observations request must be gzip JSON that
// validates as an ObservationBatch; an invalid request gets 400 and is
// recorded in Errors. Observations that break a rule the contract states in
// prose (see rejection) are answered in rejected, as the core does.
// GET /collector/v1/owned-domains answers with the domains of SetDomains.
type Core struct {
	*httptest.Server
	spec *Spec

	mu       sync.Mutex
	batches  []json.RawMessage
	errors   []string
	rejected []Rejection
	forced   []int
	codes    []string
	domains  []string
}

// Rejection is an observation the fake core refused (schema Rejection).
type Rejection struct {
	Index   int    `json:"index"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewCore starts a fake core validating against the vendored spec.
func NewCore() (*Core, error) { return NewCoreWithSpec(SpecPath()) }

// NewProposedCore starts a fake core for the proposed contract 0.5.0.
func NewProposedCore() (*Core, error) { return NewCoreWithSpec(ProposedSpecPath()) }

// NewCoreWithSpec starts a fake core validating against the contract file at
// path.
func NewCoreWithSpec(path string) (*Core, error) {
	spec, err := LoadSpec(path)
	if err != nil {
		return nil, err
	}
	c := &Core{spec: spec}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /collector/v1/observations", c.handle)
	mux.HandleFunc("GET /collector/v1/owned-domains", c.handleDomains)
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

// RejectNext makes the core reject the next len(codes) valid observations it
// receives, in order, with these codes, which may be codes this collector
// does not know (a newer core).
func (c *Core) RejectNext(codes ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codes = append(c.codes, codes...)
}

// SetDomains sets the owned domains GET /collector/v1/owned-domains returns.
func (c *Core) SetDomains(domains ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.domains = append([]string{}, domains...)
}

func (c *Core) handleDomains(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	if len(c.forced) > 0 {
		st := c.forced[0]
		c.forced = c.forced[1:]
		c.mu.Unlock()
		writeJSON(w, st, map[string]any{"title": http.StatusText(st), "status": st})
		return
	}
	body, err := json.Marshal(map[string]any{"domains": append([]string{}, c.domains...)})
	c.mu.Unlock()
	if err == nil {
		// The fake's own answer must conform too.
		err = c.spec.Validate("OwnedDomainList", body)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"title": "Internal Server Error", "status": 500, "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
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
		Observations []observation `json:"observations"`
	}
	if err := json.Unmarshal(body, &batch); err != nil {
		fail(err.Error())
		return
	}
	rejected := []Rejection{}
	c.mu.Lock()
	for i, o := range batch.Observations {
		if code, msg := rejection(o); code != "" {
			rejected = append(rejected, Rejection{Index: i, Code: code, Message: msg})
		} else if len(c.codes) > 0 {
			rejected = append(rejected, Rejection{Index: i, Code: c.codes[0], Message: "rejected by the test"})
			c.codes = c.codes[1:]
		}
	}
	c.batches = append(c.batches, body)
	c.rejected = append(c.rejected, rejected...)
	c.mu.Unlock()
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(batch.Observations) - len(rejected), "duplicates": 0, "rejected": rejected})
}

// observation holds the fields the prose rules of collector.yaml refer to.
type observation struct {
	Target struct {
		Kind  string `json:"kind"`
		SNI   string `json:"sni"`
		Port  int    `json:"port"`
		Store string `json:"store"`
		Path  string `json:"path"`
	} `json:"target"`
	Method      string   `json:"method"`
	Outcome     string   `json:"outcome"`
	ServedChain []string `json:"served_chain"`
	CTEntry     *struct {
		LogID string `json:"log_id"`
	} `json:"ct_entry"`
	Adapter *struct {
		Certificate *struct{} `json:"certificate"`
		File        *struct{} `json:"file"`
	} `json:"adapter"`
}

// rejection applies the rules collector.yaml states in its descriptions
// (the JSON Schema cannot express them) and returns the core's rejection
// code, or "" when the observation is acceptable.
func rejection(o observation) (code, msg string) {
	switch {
	case (o.Target.Kind == "host_port_sni" || o.Target.Kind == "ct_log") && o.Target.Port == 0:
		return "invalid_target", "port is required for host_port_sni and ct_log"
	case o.Target.Kind == "ct_log" && o.Target.SNI != "":
		return "invalid_target", "a ct_log target has no sni"
	case o.Target.Kind == "ct_log" && o.Method != "ct":
		return "invalid_target", "a ct_log target is read by method ct only"
	case o.Target.Kind == "ct_log" && o.Outcome != "cert_seen":
		return "invalid_target", "a ct_log target always yields a certificate (outcome cert_seen)"
	case o.CTEntry != nil && o.Method != "ct":
		return "invalid_ct_entry", "ct_entry is allowed with method ct only"
	case o.CTEntry != nil && o.CTEntry.LogID != "" && !is32Bytes(o.CTEntry.LogID):
		return "invalid_ct_entry", "ct_entry log_id must be the base64 of a 32-byte log ID"
	case (o.Target.Kind == "store" || o.Target.Kind == "file") && o.Method != "adapter":
		return "invalid_target", "store and file targets are read by method adapter only (0.9.0)"
	case (o.Target.Kind == "store" || o.Target.Kind == "file") && o.Target.Port != 0:
		return "invalid_target", "store and file targets have no port (0.9.0)"
	case (o.Target.Kind == "store" || o.Target.Kind == "file") && o.Target.SNI != "":
		return "invalid_target", "store and file targets have no sni (0.9.0)"
	case o.Target.Kind == "store" && o.Target.Store == "":
		return "invalid_target", "a store target needs store (0.9.0)"
	case o.Target.Kind == "file" && o.Target.Path == "":
		return "invalid_target", "a file target needs path (0.9.0)"
	case o.Adapter != nil && o.Method != "adapter":
		return "invalid_target", "adapter evidence is allowed with method adapter only (0.9.0)"
	case o.Method == "adapter" && o.Adapter == nil:
		return "invalid_target", "method adapter requires adapter evidence (0.9.0)"
	case o.Target.Kind == "store" && o.Adapter.Certificate == nil:
		return "invalid_target", "a store target needs adapter.certificate (0.9.0)"
	case o.Target.Kind == "file" && o.Adapter.File == nil:
		return "invalid_target", "a file target needs adapter.file (0.9.0)"
	case len(o.ServedChain) > 0 && o.Outcome != "cert_seen":
		return "chain_outcome_mismatch", "served_chain must be present exactly when outcome is cert_seen"
	case o.Outcome == "cert_seen" && len(o.ServedChain) == 0 && (o.Adapter == nil || o.Adapter.Certificate == nil):
		return "chain_outcome_mismatch", "outcome cert_seen needs served_chain (or adapter.certificate)"
	}
	return "", ""
}

func is32Bytes(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// Rejected returns the observations the fake core answered in rejected.
func (c *Core) Rejected() []Rejection {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Rejection(nil), c.rejected...)
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
