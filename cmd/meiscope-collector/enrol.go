package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/enrol"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/platform"
)

// envStateDir is where the enrolled identity is kept (identity.DefaultDir
// when unset).
const envStateDir = "MEISCOPE_STATE_DIR"

// stateDir returns the identity directory from the environment.
func stateDir(getenv func(string) string) string {
	if d := strings.TrimSpace(getenv(envStateDir)); d != "" {
		return filepath.Clean(d)
	}
	return identity.DefaultDir
}

// userAgent is the User-Agent of every request to the core.
func userAgent() string { return "meiscope-collector/" + platform.Version }

// readToken returns the token from --token, or from --token-file (a path,
// or "-" for standard input), trimmed. The token is a credential: it is
// never printed or logged.
func readToken(flagToken, file string, stdin io.Reader) (string, error) {
	switch {
	case flagToken != "" && file != "":
		return "", errors.New("give the token with --token or --token-file, not both")
	case flagToken != "":
		return strings.TrimSpace(flagToken), nil
	case file == "-":
		line, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read token from standard input: %w", err)
		}
		return strings.TrimSpace(line), nil
	case file != "":
		b, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// enrolDeps are the enrol command's external dependencies (tests replace them).
type enrolDeps struct {
	stdin io.Reader
	creds func(getenv func(string) string) credential.Source
}

func defaultEnrolDeps() enrolDeps {
	return enrolDeps{stdin: os.Stdin, creds: defaultCredentialSource}
}

func enrolCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps enrolDeps) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "deprecated: use --token-file (arguments are visible to other users and kept in shell history)")
	tokenFile := fs.String("token-file", "", `file holding the enrolment token, or "-" to read it from standard input`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	tok, err := readToken(*token, *tokenFile, deps.stdin)
	if err != nil {
		return err
	}
	if tok == "" {
		return errors.New("a token is required: --token-file PATH, or --token-file - to read it from standard input")
	}
	if *token != "" {
		fmt.Fprintln(stderr, "warning: --token is deprecated and will be removed: command-line arguments are visible to other users of this host and are kept in shell history; use --token-file PATH or --token-file - (standard input) instead")
	}
	cfg, err := platform.LoadConfig(getenv)
	if err != nil {
		return err
	}
	if cfg.CoreURL == "" {
		return errors.New("MEISCOPE_CORE_URL is not set: the https URL of the core's collector endpoint")
	}
	dir := stateDir(getenv)
	if identity.Exists(dir) {
		if s, lerr := identity.Load(dir); lerr == nil {
			return fmt.Errorf("already enrolled as collector %s in %s; to enrol again, stop the collector and move that directory away", s.CollectorID(), dir)
		}
		return fmt.Errorf("%s already holds an identity; to enrol again, stop the collector and move that directory away", dir)
	}

	// First contact: when MEISCOPE_CA_BUNDLE (the core's CA, given by the
	// operator) is set, the core's server certificate is verified against
	// that bundle ONLY, not the system roots, so a certificate any public CA
	// issued for the core's name cannot receive the token. Without the
	// bundle the system roots apply (a core with a publicly trusted
	// certificate). Every later call trusts only the CA bundle pinned here.
	ecfg := egress.LoadConfig(getenv)
	tr, err := egress.Transport(ecfg, deps.creds(getenv), egress.Options{CABundleOnly: true})
	if err != nil {
		return err
	}
	cl, err := enrol.New(cfg.CoreURL, egress.Client(tr, time.Minute), userAgent())
	if err != nil {
		return err
	}
	key, err := identity.NewKey()
	if err != nil {
		return err
	}
	csr, err := identity.CSR(key)
	if err != nil {
		return err
	}
	cred, err := cl.Enrol(ctx, tok, csr)
	if err != nil {
		return err
	}
	s, err := identity.Save(dir, cfg.CoreURL, key, cred)
	if err != nil {
		return fmt.Errorf("the core issued a certificate, but it could not be kept (the token is now used; ask for a new one): %w", err)
	}
	fmt.Fprintf(stdout, "enrolled as collector %s\ncertificate valid until %s (renewed automatically from %s)\nidentity kept in %s\n",
		s.CollectorID(), s.NotAfter().UTC().Format(time.RFC3339), s.RenewAt().UTC().Format(time.RFC3339), dir)
	return nil
}
