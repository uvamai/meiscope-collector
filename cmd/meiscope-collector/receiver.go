package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/uvamai/meiscope-collector/internal/adapter/osquery"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/receiver"
)

// receiverCmd runs the optional log-push receiver. It is off unless
// MEISCOPE_RECEIVER_ENABLED=true and binds only to loopback or a private
// address (internal/receiver).
func receiverCmd(ctx context.Context, args []string, stderr io.Writer, getenv func(string) string, deps adapterDeps) error {
	if len(args) != 1 || args[0] != "run" {
		return errors.New("usage: receiver run")
	}
	cfg, err := platform.LoadConfig(getenv)
	if err != nil {
		return err
	}
	log, err := platform.NewLogger(stderr, cfg)
	if err != nil {
		return err
	}
	rc, err := receiver.LoadConfig(getenv)
	if err != nil {
		return err
	}
	r, err := receiver.New(rc, deps.creds(getenv), deps.clk, osquery.ValidateEvent)
	if err != nil {
		return err
	}
	log.Info("log-push receiver starting", "addr", rc.Addr, "spool", rc.Dir)
	if err := r.Serve(ctx); err != nil {
		return fmt.Errorf("receiver: %w", err)
	}
	return nil
}
