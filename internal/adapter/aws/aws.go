// Package aws is the read-only AWS adapter (FR-DISC-024, FR-DISC-025,
// FR-DISC-026): AWS Certificate Manager certificates with the resources that
// use them and their managed-renewal status, Elastic Load Balancing
// listeners (Application, Network and Classic) with their certificates, and
// IAM server certificates. It signs its own requests with Signature
// Version 4 using credentials resolved just in time from credential.Source.
//
// It calls read operations only (see readOnlyOps), reads public
// certificates only, and never connects to anything but the AWS API
// endpoints. Its observations use the proposed cloud_resource target
// (api/proposed/collector-0.10.0-proposed.yaml) and are sent only when
// MEISCOPE_FEATURE_CLOUD_RESOURCE_V1 is on.
package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Registry name, evidence source and provider of the adapter.
const (
	Name     = "aws"
	Source   = "aws"
	Provider = "aws"
)

// Services (setting "services").
const (
	ServiceACM = "acm"
	ServiceELB = "elb"
	ServiceIAM = "iam"
)

// Credential purposes: names of credential references in the
// configuration, never credential values.
const (
	CredAccessKeyID     = "access_key_id"     //nolint:gosec // a purpose name, not a credential
	CredSecretAccessKey = "secret_access_key" //nolint:gosec // a purpose name, not a credential
	CredSessionToken    = "session_token"     //nolint:gosec // a purpose name, not a credential
)

var (
	regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	allServices   = []string{ServiceACM, ServiceELB, ServiceIAM}
)

func init() {
	adapter.Register(Name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env} })
}

// Adapter is the AWS adapter.
type Adapter struct {
	env adapter.Env
}

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    Name,
		Source:  Source,
		Summary: "AWS ACM certificates, ELB listeners and IAM server certificates (read-only API)",
		Settings: []string{
			"regions (comma-separated, required, e.g. ap-southeast-2,us-east-1)",
			"services (comma-separated subset of acm,elb,iam; default all)",
			"rate_per_second (default 5), refresh_hours (re-send unchanged resources; default 24, 0 = only changes)",
			"max_pages (default 10000)",
		},
		Credentials: []string{"access_key_id", "secret_access_key", "session_token (optional; temporary role-session credentials)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	regions := splitList(cfg.Setting("regions", ""))
	if len(regions) == 0 {
		return errors.New("aws: regions is required")
	}
	for _, r := range regions {
		if !regionPattern.MatchString(r) {
			return fmt.Errorf("aws: %q is not an AWS region name", r)
		}
	}
	for _, s := range services(cfg) {
		if !slices.Contains(allServices, s) {
			return fmt.Errorf("aws: unknown service %q (want acm, elb or iam)", s)
		}
	}
	for _, p := range []string{CredAccessKeyID, CredSecretAccessKey} {
		if _, ok := cfg.Credentials[p]; !ok {
			return fmt.Errorf("aws: credentials.%s (a credential reference) is required", p)
		}
	}
	if v := cfg.Setting("rate_per_second", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err != nil || f <= 0 || f > 100 {
			return errors.New("aws: rate_per_second must be a number in (0, 100]")
		}
	}
	if err := intIn(cfg, "refresh_hours", 0, 24*365); err != nil {
		return err
	}
	return intIn(cfg, "max_pages", 1, adapter.DefaultMaxPages)
}

// StatBindingsCapped counts bindings dropped over cloud.MaxBindings;
// StatBindingNoCertificate counts listener bindings whose certificate was
// not read in the same sync (its service is not configured, or it is in a
// region not configured).
const (
	StatBindingsCapped       = "bindings_capped"
	StatBindingNoCertificate = "binding_certificate_not_read"
)

type syncer struct {
	c        *client
	now      time.Time
	maxPages int
	st       map[string]int
}

// Sync reads every configured service and region and returns the resources
// that changed since the cursor (all of them every refresh_hours).
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	var creds Credentials
	var err error
	if creds.AccessKeyID, err = cfg.Credential(ctx, a.env.Creds, CredAccessKeyID); err != nil {
		return adapter.Result{}, fmt.Errorf("aws: %w", err)
	}
	if creds.SecretAccessKey, err = cfg.Credential(ctx, a.env.Creds, CredSecretAccessKey); err != nil {
		return adapter.Result{}, fmt.Errorf("aws: %w", err)
	}
	if _, ok := cfg.Credentials[CredSessionToken]; ok {
		if creds.SessionToken, err = cfg.Credential(ctx, a.env.Creds, CredSessionToken); err != nil {
			return adapter.Result{}, fmt.Errorf("aws: %w", err)
		}
	}
	clk := a.env.Clock
	if clk == nil {
		clk = clock.System{}
	}
	hc := a.env.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	rate := 5.0
	if v, err := strconv.ParseFloat(cfg.Setting("rate_per_second", ""), 64); err == nil && v > 0 {
		rate = v
	}
	s := &syncer{
		c:        &client{hc: hc, creds: creds, clk: clk, lim: adapter.NewLimiter(clk, rate), suffix: "amazonaws.com"},
		now:      clk.Now().UTC(),
		maxPages: intSetting(cfg, "max_pages", 0),
		st:       map[string]int{},
	}
	svcs := services(cfg)
	var obs []submit.Observation
	// Listener bindings are read first, so each certificate observation
	// carries the listeners that serve it.
	binds := listenerBindings{}
	for _, region := range splitList(cfg.Setting("regions", "")) {
		if slices.Contains(svcs, ServiceELB) {
			if err := s.syncELB(ctx, region, binds); err != nil {
				return adapter.Result{}, s.wrap(err)
			}
		}
		if slices.Contains(svcs, ServiceACM) {
			o, err := s.syncACM(ctx, region, binds)
			if err != nil {
				return adapter.Result{}, s.wrap(err)
			}
			obs = append(obs, o...)
		}
	}
	if slices.Contains(svcs, ServiceIAM) {
		o, err := s.syncIAM(ctx, binds)
		if err != nil {
			return adapter.Result{}, s.wrap(err)
		}
		obs = append(obs, o...)
	}
	for _, b := range binds {
		s.st[StatBindingNoCertificate] += len(b)
	}
	st := s.st
	st[cloud.StatObserved] = len(obs)
	out, next, err := cloud.Filter(since, obs, s.now, time.Duration(intSetting(cfg, "refresh_hours", 24))*time.Hour, st)
	if err != nil {
		return adapter.Result{}, err
	}
	return cloud.Finish(a.env, Name, cfg, out, st, since, next), nil
}

// wrap keeps the error chain (errors.Is(err, ErrAuth)) and makes sure no
// credential value can appear in its text.
func (s *syncer) wrap(err error) error {
	msg := s.c.redact(err.Error())
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

func services(cfg adapter.Config) []string {
	if s := splitList(cfg.Setting("services", "")); len(s) > 0 {
		return s
	}
	return allServices
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func intSetting(cfg adapter.Config, name string, def int) int {
	n, err := strconv.Atoi(cfg.Setting(name, ""))
	if err != nil {
		return def
	}
	return n
}

func intIn(cfg adapter.Config, name string, lo, hi int) error {
	v := cfg.Setting(name, "")
	if v == "" {
		return nil
	}
	if n, err := strconv.Atoi(v); err != nil || n < lo || n > hi {
		return fmt.Errorf("aws: %s must be an integer in [%d, %d]", name, lo, hi)
	}
	return nil
}
