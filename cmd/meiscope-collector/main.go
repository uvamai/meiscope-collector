// Command meiscope-collector is the Meiscope collector: an outbound-only
// probe and adapter runner deployed in customer networks.
//
// WP0.1 skeleton: version, a placeholder run loop with /healthz, and a
// placeholder enrol command. Probing and enrolment arrive in WP0.3.
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
)

const usage = `Usage: meiscope-collector <command> [flags]

Commands:
  version             print build information
  run                 run the collector (WP0.1: idle loop with /healthz)
  enrol --token TOKEN enrol with the core (WP0.1: placeholder)
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
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "meiscope-collector %s (commit %s)\n", platform.Version, platform.Commit)
	case "run":
		err = runCmd(ctx, args[1:], stderr, getenv)
	case "enrol":
		err = enrolCmd(args[1:], stdout, stderr)
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

func runCmd(ctx context.Context, args []string, stderr io.Writer, getenv func(string) string) error {
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
	ln, err := net.Listen("tcp", cfg.HealthAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HealthAddr, err)
	}
	return serve(ctx, ln, log, idleInterval)
}

// serve runs the health server on ln and the placeholder loop until ctx ends.
func serve(ctx context.Context, ln net.Listener, log *slog.Logger, interval time.Duration) error {
	srv := &http.Server{
		Handler:           platform.HealthHandler(),
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
			log.Info("idle: no scan scopes until enrolment exists (WP0.3)")
		}
	}
}
