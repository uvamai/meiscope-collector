package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/credential"
)

// Credential file settings: MEISCOPE_CREDENTIAL_FILE is the age-encrypted
// credential file, MEISCOPE_CREDENTIAL_KEY_FILE the collector's age identity
// file (its keystore).
const (
	envCredentialFile = "MEISCOPE_CREDENTIAL_FILE"     //nolint:gosec // an environment variable name
	envCredentialKey  = "MEISCOPE_CREDENTIAL_KEY_FILE" //nolint:gosec // an environment variable name
)

// fileSource returns the configured encrypted-file source, or false when
// neither variable is set.
func fileSource(getenv func(string) string) (credential.FileSource, bool) {
	f, k := getenv(envCredentialFile), getenv(envCredentialKey)
	return credential.FileSource{Path: f, IdentityPath: k}, f != "" || k != ""
}

// credentialCmd manages the credential file: init creates the identity,
// set stores one value read from standard input (never from an argument,
// which would land in shell history), list prints the references only.
func credentialCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("credential", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if len(args) == 0 {
		return errors.New("usage: credential init | set REF (value on stdin) | list")
	}
	sub, rest := args[0], args[1:]
	if err := fs.Parse(rest); err != nil {
		return err
	}
	src, ok := fileSource(getenv)
	if !ok || src.Path == "" || src.IdentityPath == "" {
		return fmt.Errorf("set both %s and %s", envCredentialFile, envCredentialKey)
	}
	switch sub {
	case "init":
		if err := credential.InitIdentity(src.IdentityPath); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "created the identity file %s (mode 0600); back it up separately from the credential file\n", src.IdentityPath)
		return nil
	case "set":
		if fs.NArg() != 1 {
			return errors.New("usage: credential set REF (the value is read from standard input)")
		}
		line, err := bufio.NewReader(io.LimitReader(stdin, 1<<20)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if err := src.Set(fs.Arg(0), strings.TrimRight(line, "\r\n")); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "stored credential %s\n", fs.Arg(0))
		return nil
	case "list":
		refs, err := src.Refs()
		if err != nil {
			return err
		}
		for _, r := range refs {
			fmt.Fprintln(stdout, r)
		}
		return nil
	default:
		return fmt.Errorf("unknown credential subcommand %q", sub)
	}
}
