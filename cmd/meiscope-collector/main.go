// Command meiscope-collector is the Meiscope collector: an outbound-only
// probe and adapter runner deployed in customer networks.
//
// run serves /healthz and, with a signed scope configured, probes the
// scope's listed targets on its rescan schedule (D1). Enrolment against the
// core arrives with D1b; until then scopes come from MEISCOPE_SCOPE_FILE,
// verified against the pinned keys in MEISCOPE_SCOPE_KEYS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

const usage = `Usage: meiscope-collector <command> [flags]

Commands:
  version             print build information
  run                 run the collector: /healthz, and the probe schedule when MEISCOPE_SCOPE_FILE is set (docs/probe.md)
  enrol --token TOKEN enrol with the core (WP0.1: placeholder)
  ct-poll [--every 1h] poll Certificate Transparency for the owned domains (docs/ct.md)
  ct-baseline --domain D  coverage of the CT poller against the crt.sh baseline
  receiver run         run the optional log-push receiver (disabled by default; docs/install.md)
  credential init|set|list  manage the age-encrypted credential file (docs/install.md)
  adapter list|run     run read-only adapters such as osquery (docs/adapters.md)
`

// idleInterval is how often the placeholder run loop reports that it is idle.
const idleInterval = time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if args[0] != "version" && args[0] != "help" && args[0] != "-h" && args[0] != "--help" {
		if err := devCredentialGuard(); err != nil {
			fmt.Fprintf(stderr, "meiscope-collector: %v\n", err)
			return 1
		}
	}
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "meiscope-collector %s (commit %s)\n", platform.Version, platform.Commit)
	case "run":
		err = runCmd(ctx, args[1:], stdout, stderr, getenv)
	case "enrol":
		err = enrolCmd(args[1:], stdout, stderr)
	case "ct-poll":
		err = ctPollCmd(ctx, args[1:], stdout, stderr, getenv, defaultCTDeps())
	case "ct-baseline":
		err = ctBaselineCmd(ctx, args[1:], stdout, stderr, getenv, defaultCTDeps())
	case "receiver":
		err = receiverCmd(ctx, args[1:], stderr, getenv, defaultAdapterDeps())
	case "credential":
		err = credentialCmd(args[1:], os.Stdin, stdout, stderr, getenv)
	case "adapter":
		err = adapterCmd(ctx, args[1:], stdout, stderr, getenv, defaultAdapterDeps())
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "meiscope-collector %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func enrolCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "one-time enrolment token issued by the core (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *token == "" {
		return errors.New("--token is required")
	}
	// The token is a credential: it is never printed or logged.
	fmt.Fprint(stdout, `enrol: token accepted (not used yet).
Enrolment is a placeholder in WP0.1. From WP0.3 this command will:
  1. generate a private key on this host (it never leaves the host),
  2. send the one-time token and a CSR to the core over TLS,
  3. store the returned client certificate for mTLS to /collector/v1,
  4. pin the control plane's job-signing public key.
`)
	return nil
}

func runCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := platform.LoadConfig(getenv)
	if err != nil {
		return err
	}
	log, err := platform.NewLogger(stderr, cfg)
	if err != nil {
		return err
	}
	var sub *submit.Client
	if cfg.CoreURL != "" {
		if sub, err = submit.New(cfg.CoreURL, nil, submit.WithLogger(log)); err != nil {
			return err
		}
	}
	sched, err := newProbeSchedule(getenv, sub, stdout, log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.HealthAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HealthAddr, err)
	}
	return serve(ctx, ln, log, idleInterval, sched)
}

// serve runs the health server on ln, and the probe schedule when sched is
// not nil, until ctx ends.
func serve(ctx context.Context, ln net.Listener, log *slog.Logger, interval time.Duration, sched *probeSchedule) error {
	handler := platform.HealthHandler()
	if sched != nil {
		handler = controlHandler(handler, sched.run, log)
		probeCtx, stopProbe := context.WithCancel(ctx)
		probeDone := make(chan struct{})
		go func() { defer close(probeDone); sched.loop(probeCtx) }()
		defer func() { stopProbe(); <-probeDone }()
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("collector started", "health_addr", ln.Addr().String())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("collector stopping")
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("shutdown: %w", err)
			}
			return nil
		case err := <-errc:
			return fmt.Errorf("health server: %w", err)
		case <-ticker.C:
			if sched == nil {
				log.Info("idle: no scan scope configured (MEISCOPE_SCOPE_FILE)")
			}
		}
	}
}
