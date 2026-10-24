package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	_ "github.com/uvamai/meiscope-collector/internal/adapter/osquery" // registers the osquery adapter
	"github.com/uvamai/meiscope-collector/internal/buffer"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// DefaultBufferKeyRef is the credential reference of the buffer key (32
// bytes, base64) when MEISCOPE_BUFFER_KEY_REF is not set.
const DefaultBufferKeyRef = "buffer_key"

// adapterDeps are the injectable parts of the adapter command.
type adapterDeps struct {
	clk      clock.Clock
	creds    func(getenv func(string) string) credential.Source
	envProxy func(*http.Request) (*url.URL, error) // nil: HTTPS_PROXY from the process environment
}

func defaultAdapterDeps() adapterDeps {
	return adapterDeps{
		clk:   clock.System{},
		creds: defaultCredentialSource,
	}
}

const adapterUsage = `Usage: meiscope-collector adapter <list | run> [flags]

  list                         list the registered adapters
  run --config FILE [--every D] [NAME...]
                               run the adapter instances in FILE (a JSON array of
                               {"name","adapter","settings","credentials"}), once or
                               every D; observations go to the core through the
                               local buffer (MEISCOPE_BUFFER_DIR), or to stdout
                               without MEISCOPE_CORE_URL (docs/adapters.md)
`

func adapterCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps adapterDeps) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, adapterUsage)
		return errors.New("missing adapter subcommand")
	}
	switch args[0] {
	case "list":
		for _, n := range adapter.Names() {
			f, _ := adapter.Lookup(n)
			d := f(adapter.Env{}).Describe()
			fmt.Fprintf(stdout, "%s\t%s\n", d.Name, d.Summary)
			for _, s := range d.Settings {
				fmt.Fprintf(stdout, "\tsetting: %s\n", s)
			}
			for _, c := range d.Credentials {
				fmt.Fprintf(stdout, "\tcredential: %s\n", c)
			}
		}
		return nil
	case "run":
		return adapterRunCmd(ctx, args[1:], stdout, stderr, getenv, deps)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, adapterUsage)
		return nil
	default:
		fmt.Fprint(stderr, adapterUsage)
		return fmt.Errorf("unknown adapter subcommand %q", args[0])
	}
}

func loadAdapterConfigs(path string, names []string) ([]adapter.Config, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return nil, fmt.Errorf("%s: want a JSON array of adapter configurations: %w", path, err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []adapter.Config
	seen := map[string]bool{}
	for i, r := range raws {
		c, err := adapter.ParseConfig(r)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d: %w", path, i, err)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: duplicate instance name %q", path, c.Name)
		}
		seen[c.Name] = true
		if len(want) == 0 || want[c.Name] {
			out = append(out, c)
			delete(want, c.Name)
		}
	}
	for n := range want {
		return nil, fmt.Errorf("%s: no adapter instance named %q", path, n)
	}
	return out, nil
}

// directSink submits straight to the core (no buffer configured).
type directSink struct {
	sub *submit.Client
	log *slog.Logger
}

func (d directSink) Enqueue(ctx context.Context, obs []submit.Observation) error {
	res, err := d.sub.Submit(ctx, obs)
	if err != nil {
		return err
	}
	d.log.Info("adapter observations submitted", "observations", len(obs), "accepted", res.Accepted, "duplicates", res.Duplicates, "rejected", len(res.Rejected))
	return nil
}

// stdoutSink collects a dry run's observations.
type stdoutSink struct{ obs []submit.Observation }

func (s *stdoutSink) Enqueue(_ context.Context, obs []submit.Observation) error {
	s.obs = append(s.obs, obs...)
	return nil
}

func adapterRunCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps adapterDeps) error {
	fs := flag.NewFlagSet("adapter run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON file with the adapter instances (required)")
	every := fs.Duration("every", 0, "repeat at this interval (e.g. 24h) until stopped; 0 runs once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}
	cfg, err := platform.LoadConfig(getenv)
	if err != nil {
		return err
	}
	log, err := platform.NewLogger(stderr, cfg)
	if err != nil {
		return err
	}
	instances, err := loadAdapterConfigs(*cfgPath, fs.Args())
	if err != nil {
		return err
	}
	creds := deps.creds(getenv)
	ecfg := egress.LoadConfig(getenv)
	tr, err := egress.Transport(ecfg, creds, egress.Options{EnvProxy: deps.envProxy})
	if err != nil {
		return err
	}
	hc := egress.Client(tr, 2*time.Minute)
	env := adapter.Env{HTTP: hc, Creds: creds, Clock: deps.clk, Log: log}

	var sub *submit.Client
	var buf *buffer.Buffer
	stateFile := getenv("MEISCOPE_ADAPTER_STATE_FILE")
	if cfg.CoreURL != "" {
		sub, err = submit.New(cfg.CoreURL, hc, submit.WithClock(deps.clk), submit.WithUserAgent("meiscope-collector/"+platform.Version))
		if err != nil {
			return err
		}
		if dir := getenv("MEISCOPE_BUFFER_DIR"); dir != "" {
			if buf, err = openBuffer(ctx, dir, getenv, creds, deps.clk, log); err != nil {
				return err
			}
			defer func() { _ = buf.Close() }()
		} else {
			log.Warn("MEISCOPE_BUFFER_DIR is not set: observations are not buffered while the core is unreachable")
		}
	} else {
		log.Warn("MEISCOPE_CORE_URL is not set: observations are written to stdout and adapter cursors are not saved")
		stateFile = ""
	}
	cursors, err := adapter.LoadCursors(stateFile)
	if err != nil {
		return err
	}
	for {
		err := adapterCycle(ctx, env, instances, cursors, sub, buf, stdout, log)
		if *every == 0 {
			return err
		}
		if err != nil {
			log.Error("adapter cycle failed; retrying next cycle", "error", err)
		}
		if err := deps.clk.Sleep(ctx, *every); err != nil {
			return nil // stopped by a signal
		}
	}
}

func openBuffer(ctx context.Context, dir string, getenv func(string) string, creds credential.Source, clk clock.Clock, log *slog.Logger) (*buffer.Buffer, error) {
	ref := getenv("MEISCOPE_BUFFER_KEY_REF")
	if ref == "" {
		ref = DefaultBufferKeyRef
	}
	s, err := creds.Get(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("buffer key (credential %s): %w", ref, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s.Reveal()))
	if err != nil || len(key) != buffer.KeySize {
		return nil, fmt.Errorf("buffer key (credential %s): want %d bytes, base64-encoded", ref, buffer.KeySize)
	}
	return buffer.Open(buffer.Options{Dir: dir, Key: key, Clock: clk, Log: log})
}

// adapterCycle runs every instance once, then flushes the buffer. One
// instance failing does not stop the others.
func adapterCycle(ctx context.Context, env adapter.Env, instances []adapter.Config, cursors *adapter.CursorStore, sub *submit.Client, buf *buffer.Buffer, stdout io.Writer, log *slog.Logger) error {
	var sink adapter.Sink
	dry := &stdoutSink{}
	switch {
	case buf != nil:
		sink = buf
	case sub != nil:
		sink = directSink{sub: sub, log: log}
	default:
		sink = dry
	}
	var errs []error
	for _, inst := range instances {
		n, err := adapter.RunOnce(ctx, env, inst, cursors, sink)
		if err != nil {
			errs = append(errs, err)
			log.Error("adapter run failed", "instance", inst.Name, "adapter", inst.Adapter, "error", err)
			continue
		}
		log.Info("adapter run", "instance", inst.Name, "adapter", inst.Adapter, "observations", n)
	}
	if buf != nil {
		res, err := buf.Flush(ctx, sub, submit.MaxBatch)
		if err != nil {
			errs = append(errs, err)
		}
		// Heartbeat fields until the core's heartbeat endpoint exists (WP0.3).
		log.Info("collector heartbeat", "buffer_depth", buf.Depth(), "buffer_expired", buf.Expired(), "sent", res.Sent, "accepted", res.Accepted, "duplicates", res.Duplicates, "rejected", res.Rejected)
	}
	if sub == nil {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if len(dry.obs) > 0 {
			if err := enc.Encode(submit.ObservationBatch{Observations: dry.obs}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
