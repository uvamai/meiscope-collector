package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/ct"
	"github.com/uvamai/meiscope-collector/internal/platform"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// ctDeps are the injectable parts of the CT commands (tests replace them).
type ctDeps struct {
	rt    http.RoundTripper // base transport to public CT services; nil = default
	core  *http.Client      // client for the core; nil = default
	clk   clock.Clock
	creds func(getenv func(string) string) credential.Source
}

func defaultCTDeps() ctDeps {
	return ctDeps{
		clk: clock.System{},
		creds: func(getenv func(string) string) credential.Source {
			// Development fallback only; vault-backed sources arrive with WP1.1.
			return credential.EnvSource{Getenv: getenv}
		},
	}
}

func ctPollCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps ctDeps) error {
	fs := flag.NewFlagSet("ct-poll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	every := fs.Duration("every", 0, "repeat the poll at this interval (e.g. 1h) until stopped; 0 polls once")
	out := fs.String("out", "", "without MEISCOPE_CORE_URL: write the observation batch to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	cfg, err := platform.LoadConfig(getenv)
	if err != nil {
		return err
	}
	log, err := platform.NewLogger(stderr, cfg)
	if err != nil {
		return err
	}
	ctCfg, err := ct.LoadConfig(getenv)
	if err != nil {
		return err
	}
	if len(ctCfg.Domains) == 0 {
		return errors.New("no owned domains: set MEISCOPE_CT_DOMAINS")
	}
	poller, err := ctCfg.NewPoller(deps.rt, deps.clk, deps.creds(getenv))
	if err != nil {
		return err
	}
	poller.Log = log
	var sub *submit.Client
	if cfg.CoreURL != "" {
		sub, err = submit.New(cfg.CoreURL, deps.core, submit.WithClock(deps.clk), submit.WithUserAgent(ctCfg.UserAgent()))
		if err != nil {
			return err
		}
	} else {
		log.Warn("MEISCOPE_CORE_URL is not set: observations are written out, not submitted, and CT progress is not saved")
	}
	st := ct.NewState()
	if ctCfg.StateFile != "" {
		if st, err = ct.LoadState(ctCfg.StateFile); err != nil {
			return err
		}
	}
	for {
		if err := pollOnce(ctx, poller, st, ctCfg.StateFile, sub, *out, stdout, log); err != nil {
			if *every == 0 {
				return err
			}
			log.Error("CT poll failed; retrying next cycle", "error", err)
		}
		if *every == 0 {
			return nil
		}
		if err := deps.clk.Sleep(ctx, *every); err != nil {
			return nil // stopped by a signal: a clean exit
		}
	}
}

func pollOnce(ctx context.Context, p *ct.Poller, st *ct.State, stateFile string, sub *submit.Client, out string, stdout io.Writer, log *slog.Logger) error {
	cycle := p.Poll(ctx, st)
	if err := ctx.Err(); err != nil {
		return err
	}
	obs := cycle.Observations()
	for src, s := range cycle.Stats {
		log.Info("CT source", "source", src, "scanned", s.Scanned, "matched", s.Matched, "new", s.New, "errors", s.Errors)
	}
	if sub == nil {
		w := stdout
		if out != "" {
			f, err := os.Create(filepath.Clean(out))
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(submit.ObservationBatch{Observations: obs})
	}
	if len(obs) > 0 {
		res, err := sub.Submit(ctx, obs)
		if err != nil {
			return fmt.Errorf("submit %d CT observations: %w", len(obs), err)
		}
		log.Info("CT observations submitted", "observations", len(obs), "accepted", res.Accepted, "duplicates", res.Duplicates, "rejected", len(res.Rejected))
		for _, r := range res.Rejected {
			log.Warn("CT observation rejected by the core", "index", r.Index, "code", r.Code, "message", r.Message)
		}
	}
	cycle.Commit(st)
	if stateFile != "" {
		if err := st.Save(stateFile); err != nil {
			return err
		}
	}
	if len(cycle.Errors) > 0 {
		log.Warn("CT poll finished with source errors", "errors", len(cycle.Errors))
	}
	return nil
}

func ctBaselineCmd(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, deps ctDeps) error {
	fs := flag.NewFlagSet("ct-baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	domain := fs.String("domain", "", "owned domain to measure (required)")
	asJSON := fs.Bool("json", false, "print the coverage as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" || fs.NArg() > 0 {
		return errors.New("usage: ct-baseline --domain example.com [--json]")
	}
	ctCfg, err := ct.LoadConfig(getenv)
	if err != nil {
		return err
	}
	ds, err := ct.ParseDomains([]string{*domain})
	if err != nil {
		return err
	}
	ua := ctCfg.UserAgent()
	// The collector side: Cert Spotter only, from scratch, no crt.sh (the
	// baseline would otherwise measure itself).
	p := &ct.Poller{
		Domains:     ds,
		CertSpotter: ct.NewCertSpotter(ctCfg.CertSpotterURL, deps.rt, deps.clk, ct.CertSpotterPoliteness, ua, deps.creds(getenv)),
		Clock:       deps.clk,
	}
	started := deps.clk.Now()
	cycle := p.Poll(ctx, ct.NewState())
	if len(cycle.Errors) > 0 {
		return fmt.Errorf("cert spotter: %w", errors.Join(cycle.Errors...))
	}
	crt := ct.NewCrtSh(ctCfg.CrtShURL, deps.rt, deps.clk, ct.CrtShPoliteness, ua)
	rows, err := crt.Search(ctx, ds[0])
	if err != nil {
		return err
	}
	cov := ct.ComputeCoverage(ds[0], cycle.Found, rows)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			ct.Coverage
			CertPercent float64 `json:"CertPercent"`
			NamePercent float64 `json:"NamePercent"`
			Elapsed     string  `json:"Elapsed"`
		}{cov, cov.CertPercent(), cov.NamePercent(), deps.clk.Now().Sub(started).Round(time.Millisecond).String()})
	}
	cov.Write(stdout)
	fmt.Fprintf(stdout, "elapsed:       %s (collector source: Cert Spotter API; baseline: crt.sh, unexpired)\n",
		deps.clk.Now().Sub(started).Round(time.Millisecond))
	return nil
}
