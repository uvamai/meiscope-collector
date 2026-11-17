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
	"regexp"
	"runtime"
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

// envCollectorName is the collector's name, as approved in the portal request
// (contract 0.10.0: the core compares it with the request).
const envCollectorName = "MEISCOPE_COLLECTOR_NAME"

var collectorNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

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
// never printed or logged. For a file it also returns the path, so the
// caller can wipe it after a successful enrolment (AC-G3-13). A file that
// group or others can read is refused: the code is already exposed.
func readToken(flagToken, file string, stdin io.Reader) (token, wipePath string, err error) {
	switch {
	case flagToken != "" && file != "":
		return "", "", errors.New("give the token with --token or --token-file, not both")
	case flagToken != "":
		return strings.TrimSpace(flagToken), "", nil
	case file == "-":
		line, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", "", fmt.Errorf("read token from standard input: %w", err)
		}
		return strings.TrimSpace(line), "", nil
	case file != "":
		path := filepath.Clean(file)
		f, err := os.Open(path)
		if err != nil {
			return "", "", fmt.Errorf("read --token-file: %w", err)
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil {
			return "", "", fmt.Errorf("read --token-file: %w", err)
		}
		if !st.Mode().IsRegular() {
			return "", "", fmt.Errorf("--token-file %s is not a regular file", path)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
			return "", "", fmt.Errorf("--token-file %s is readable by group or others (mode %04o): the code in it is exposed, so ask for a new one; for the next one run chmod 600 on the file first", path, st.Mode().Perm())
		}
		b, err := io.ReadAll(io.LimitReader(f, 4096))
		if err != nil {
			return "", "", fmt.Errorf("read --token-file: %w", err)
		}
		return strings.TrimSpace(string(b)), path, nil
	}
	return "", "", nil
}

// wipeFile overwrites the file with zeros, syncs, and removes it.
func wipeFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil {
		_, err = f.Write(make([]byte, st.Size()))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// buildPlatform is what this binary was built for.
func buildPlatform() enrol.Platform {
	return enrol.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH, Package: platform.Package, Version: platform.Version}
}

// enrolDeps are the enrol command's external dependencies (tests replace them).
type enrolDeps struct {
	stdin io.Reader
	creds func(getenv func(string) string) credential.Source
	// platform reports the build's os, arch, package and version.
	platform func() enrol.Platform
}

func defaultEnrolDeps() enrolDeps {
	return enrolDeps{stdin: os.Stdin, creds: defaultCredentialSource, platform: buildPlatform}
}

func enrolCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps enrolDeps) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "one-time enrolment token issued by the core (prefer --token-file: arguments are visible to other users)")
	tokenFile := fs.String("token-file", "", `file holding the enrolment token, or "-" to read it from standard input`)
	nameFlag := fs.String("name", "", "the collector's name as approved in the portal (default: "+envCollectorName+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	tok, tokenPath, err := readToken(*token, *tokenFile, deps.stdin)
	if err != nil {
		return err
	}
	if tok == "" {
		return errors.New("a token is required: --token-file PATH (or - for standard input), or --token TOKEN")
	}
	name := strings.TrimSpace(*nameFlag)
	if name == "" {
		name = strings.TrimSpace(getenv(envCollectorName))
	}
	if !collectorNameRE.MatchString(name) {
		return fmt.Errorf("the collector name is required (--name or %s) and must be the name approved in the portal: lower-case letters, digits and hyphens, starting with a letter or digit, at most 63 characters", envCollectorName)
	}
	plat := deps.platform()
	switch plat.Package {
	case "deb", "rpm", "container":
	default:
		return errors.New("this binary was not built as a Meiscope package (deb, rpm or container), so the core cannot match it to an approved request: install the package from the release page")
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

	// First contact: the core's server certificate is verified against
	// MEISCOPE_CA_BUNDLE (the Meiscope CA, saved from the portal) and nothing
	// else; the system roots are not trusted and a missing bundle is refused
	// before any request (AC-G3-14). Every later call trusts only the CA
	// bundle pinned at enrolment.
	ecfg := egress.LoadConfig(getenv)
	tr, err := egress.Transport(ecfg, deps.creds(getenv), egress.Options{PinnedOnly: true})
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
	cred, err := cl.Enrol(ctx, tok, name, plat, csr)
	if err != nil {
		return err
	}
	s, err := identity.Save(dir, cfg.CoreURL, key, cred)
	if err != nil {
		return fmt.Errorf("the core issued a certificate, but it could not be kept (the token is now used; ask for a new one): %w", err)
	}
	if tokenPath != "" {
		if werr := wipeFile(tokenPath); werr != nil {
			fmt.Fprintf(stderr, "warning: could not wipe the token file %s (%v); the code is used, but delete the file\n", tokenPath, werr)
		}
	}
	fmt.Fprintf(stdout, "enrolled as collector %s\ncertificate valid until %s (renewed automatically from %s)\nidentity kept in %s\n",
		s.CollectorID(), s.NotAfter().UTC().Format(time.RFC3339), s.RenewAt().UTC().Format(time.RFC3339), dir)
	return nil
}
