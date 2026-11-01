// Package receiver is the optional log-push receiver (decision D4): it takes
// result events pushed by a customer's log pipeline (Fluent Bit, Logstash,
// osquery's TLS logger) and appends them to a spool directory that the
// osquery adapter's log-sink mode reads.
//
// It is the only listener of the collector that accepts data (the WP0.1
// /healthz endpoint serves liveness only), so it is locked down:
//
//   - Disabled unless explicitly enabled (Config.Enabled, MEISCOPE_RECEIVER_ENABLED).
//   - It binds only to a loopback address or an explicitly configured private
//     address (RFC 1918, IPv6 unique-local). The unspecified address
//     (0.0.0.0, ::), public addresses, link-local and cloud-metadata ranges
//     are rejected when the configuration is loaded (and again at bind).
//     Host names are refused: an address literal cannot resolve somewhere else.
//   - It speaks plain HTTP and expects a customer-controlled TLS terminator in
//     front of it on any non-loopback path (docs/install.md).
//   - Every request needs a bearer token whose value comes from
//     credential.Source, compared in constant time and never logged.
//   - Request bodies are limited to 1 MiB and requests are rate limited.
//   - Pushed content is untrusted data: it is parsed as JSON events,
//     validated by the caller's Validate function, size capped, written as
//     compact JSON lines and never executed or interpreted as instructions.
package receiver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// Limits.
const (
	// MaxBodyBytes is the request size limit (1 MiB). It cannot be raised.
	MaxBodyBytes = 1 << 20
	// MaxEventBytes caps a single event.
	MaxEventBytes = 512 << 10
	// MaxEventsPerRequest caps the events of one request.
	MaxEventsPerRequest = 1000
	// DefaultRatePerSecond and DefaultBurst bound the accepted requests.
	DefaultRatePerSecond = 5.0
	DefaultBurst         = 10
)

var tokenRefPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Config configures the receiver.
type Config struct {
	// Enabled switches the receiver on. The zero value is off.
	Enabled bool
	// Addr is host:port with an IP literal host (loopback or private).
	Addr string
	// Dir is the spool directory events are appended to.
	Dir string
	// TokenRef is the credential.Source reference of the bearer token.
	TokenRef string
	// RatePerSecond and Burst limit requests (0: defaults).
	RatePerSecond float64
	Burst         int
}

// LoadConfig reads MEISCOPE_RECEIVER_ENABLED, _ADDR, _DIR, _TOKEN_REF and
// _RATE through getenv.
func LoadConfig(getenv func(string) string) (Config, error) {
	var c Config
	if v := strings.TrimSpace(getenv("MEISCOPE_RECEIVER_ENABLED")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("MEISCOPE_RECEIVER_ENABLED: want true or false, got %q", v)
		}
		c.Enabled = b
	}
	c.Addr = strings.TrimSpace(getenv("MEISCOPE_RECEIVER_ADDR"))
	c.Dir = strings.TrimSpace(getenv("MEISCOPE_RECEIVER_DIR"))
	c.TokenRef = strings.TrimSpace(getenv("MEISCOPE_RECEIVER_TOKEN_REF"))
	if v := strings.TrimSpace(getenv("MEISCOPE_RECEIVER_RATE")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 || f > 1000 {
			return Config{}, fmt.Errorf("MEISCOPE_RECEIVER_RATE: want requests per second in (0, 1000], got %q", v)
		}
		c.RatePerSecond = f
	}
	return c, c.Validate()
}

// Validate checks the configuration at load time. A disabled receiver needs
// nothing else.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if _, err := ParseListenAddr(c.Addr); err != nil {
		return fmt.Errorf("MEISCOPE_RECEIVER_ADDR: %w", err)
	}
	if c.Dir == "" {
		return errors.New("MEISCOPE_RECEIVER_DIR: the spool directory is required")
	}
	if !tokenRefPattern.MatchString(c.TokenRef) {
		return errors.New("MEISCOPE_RECEIVER_TOKEN_REF: a credential reference for the bearer token is required (^[a-z][a-z0-9_]{0,63}$)")
	}
	return nil
}

// ErrBadListenAddr marks addresses the receiver refuses to bind.
var ErrBadListenAddr = errors.New("refused listen address")

// ParseListenAddr validates host:port and returns the address. Only loopback
// and private IP literals are allowed.
func ParseListenAddr(addr string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: want ip:port, got %q", ErrBadListenAddr, addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: the host must be an IP address literal (127.0.0.1 or a private address), got %q", ErrBadListenAddr, host)
	}
	ip = ip.Unmap()
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return netip.AddrPort{}, fmt.Errorf("%w: invalid port %q", ErrBadListenAddr, port)
	}
	switch {
	case ip.IsUnspecified():
		return netip.AddrPort{}, fmt.Errorf("%w: %s listens on every interface; use 127.0.0.1 or one private address", ErrBadListenAddr, ip)
	case ip.IsMulticast():
		return netip.AddrPort{}, fmt.Errorf("%w: %s is a multicast address", ErrBadListenAddr, ip)
	case ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast():
		return netip.AddrPort{}, fmt.Errorf("%w: %s is a link-local address (cloud metadata ranges live there)", ErrBadListenAddr, ip)
	case isCGNAT(ip):
		return netip.AddrPort{}, fmt.Errorf("%w: %s is in the shared address space 100.64.0.0/10 (some clouds serve metadata there)", ErrBadListenAddr, ip)
	case ip.IsLoopback(), ip.IsPrivate():
		return netip.AddrPortFrom(ip, uint16(p)), nil //nolint:gosec // p is in 1..65535
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: %s is a public address; the receiver binds only to loopback or private addresses", ErrBadListenAddr, ip)
	}
}

func isCGNAT(ip netip.Addr) bool {
	return ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// Receiver serves the push endpoint.
type Receiver struct {
	cfg      Config
	creds    credential.Source
	clk      clock.Clock
	validate func(event []byte) error

	mu     sync.Mutex // guards the spool file and the bucket
	tokens float64
	last   time.Time
}

// New builds a receiver. validate is called for every event and returns an
// error for events that must be refused; it must not retain the slice.
func New(cfg Config, creds credential.Source, clk clock.Clock, validate func(event []byte) error) (*Receiver, error) {
	if !cfg.Enabled {
		return nil, errors.New("the log-push receiver is disabled; set MEISCOPE_RECEIVER_ENABLED=true to enable it (docs/install.md)")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if creds == nil || validate == nil || clk == nil {
		return nil, errors.New("receiver needs a credential source, a clock and an event validator")
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = DefaultRatePerSecond
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	return &Receiver{cfg: cfg, creds: creds, clk: clk, validate: validate, tokens: float64(cfg.Burst), last: clk.Now()}, nil
}

// allow takes one token from the bucket.
func (r *Receiver) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clk.Now()
	r.tokens = min(float64(r.cfg.Burst), r.tokens+now.Sub(r.last).Seconds()*r.cfg.RatePerSecond)
	r.last = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// Handler returns the HTTP handler: POST only.
func (r *Receiver) Handler() http.Handler {
	return http.HandlerFunc(r.serve)
}

func (r *Receiver) serve(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !r.allow() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	want, err := r.creds.Get(req.Context(), r.cfg.TokenRef)
	if err != nil || want.Empty() {
		http.Error(w, "push is not configured", http.StatusServiceUnavailable)
		return
	}
	got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(want.Reveal())) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if req.ContentLength > MaxBodyBytes {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, MaxBodyBytes)
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(req.Body); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	events, err := SplitEvents(buf.Bytes())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i, e := range events {
		if err := r.validate(e); err != nil {
			http.Error(w, fmt.Sprintf("event %d refused: %v", i, err), http.StatusBadRequest)
			return
		}
	}
	if err := r.append(events); err != nil {
		http.Error(w, "could not store events", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SplitEvents returns each event of a body as compact JSON. The body may be
// newline-delimited JSON, a JSON array, or the osquery TLS logger envelope
// {"log_type": "result", "data": [...]}; status logs are dropped. Every
// event must be a JSON object within MaxEventBytes, at most
// MaxEventsPerRequest per request.
func SplitEvents(body []byte) ([][]byte, error) {
	t := bytes.TrimSpace(body)
	var raws []json.RawMessage
	switch {
	case len(t) == 0:
		return nil, nil
	case t[0] == '[':
		if err := json.Unmarshal(t, &raws); err != nil {
			return nil, errors.New("invalid JSON array")
		}
	default:
		var env struct {
			LogType string            `json:"log_type"`
			Data    []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(t, &env) == nil && env.Data != nil {
			if env.LogType != "" && env.LogType != "result" {
				return nil, nil
			}
			raws = env.Data
			break
		}
		sc := bufio.NewScanner(bytes.NewReader(t))
		sc.Buffer(make([]byte, 0, 64<<10), MaxBodyBytes)
		for sc.Scan() {
			if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
				raws = append(raws, append(json.RawMessage(nil), l...))
			}
		}
		if err := sc.Err(); err != nil {
			return nil, errors.New("invalid event stream")
		}
	}
	if len(raws) > MaxEventsPerRequest {
		return nil, fmt.Errorf("too many events (%d, at most %d)", len(raws), MaxEventsPerRequest)
	}
	out := make([][]byte, 0, len(raws))
	for i, r := range raws {
		if len(r) > MaxEventBytes {
			return nil, fmt.Errorf("event %d is larger than %d bytes", i, MaxEventBytes)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(r, &obj); err != nil {
			return nil, fmt.Errorf("event %d is not a JSON object", i)
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, r); err != nil {
			return nil, fmt.Errorf("event %d is not valid JSON", i)
		}
		out = append(out, buf.Bytes())
	}
	return out, nil
}

func (r *Receiver) append(events [][]byte) error {
	if len(events) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.cfg.Dir, 0o700); err != nil {
		return err
	}
	name := filepath.Join(r.cfg.Dir, "push-"+r.clk.Now().UTC().Format("20060102")+".jsonl")
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

// Serve listens on the configured address and serves until ctx ends. The
// address is validated again here.
func (r *Receiver) Serve(ctx context.Context) error {
	ap, err := ParseListenAddr(r.cfg.Addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", ap.String())
	if err != nil {
		return fmt.Errorf("receiver listen: %w", err)
	}
	return r.ServeOn(ctx, ln)
}

// ServeOn serves on an existing listener (tests).
func (r *Receiver) ServeOn(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}
