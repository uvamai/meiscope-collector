package enrol

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/identity"
	"github.com/uvamai/meiscope-collector/internal/retry"
)

// ErrExpired is returned once the collector certificate has expired without
// being renewed: the core will refuse every request, so the collector stops
// calling it until it is enrolled again.
var ErrExpired = errors.New("the collector certificate has expired without renewal: stop the collector, move the state directory away and enrol again with a new token")

// RenewBackoff is the wait between failed renewals: 30 seconds, doubling,
// at most one hour, each wait jittered (and never past the expiry).
var RenewBackoff = retry.Policy{Base: 30 * time.Second, Max: time.Hour}

// Renewer renews the collector certificate at Store.RenewAt (two thirds of
// its lifetime): a new key generated on this host, a CSR, POST
// /collector/v1/certificate over mTLS with the current certificate, then
// Store.Replace. Only the CSR leaves the host.
type Renewer struct {
	Store  *identity.Store
	Client *Client // its HTTP client presents Store's certificate
	Clock  clock.Clock
	Log    *slog.Logger
	// Backoff is the wait between failures (RenewBackoff when zero).
	Backoff retry.Policy
	// Jitter randomises a back-off wait (default: uniform in [d/2, d]).
	Jitter func(time.Duration) time.Duration

	mu          sync.Mutex
	failures    int
	lastErr     string
	lastRenewed time.Time
	expired     bool
}

func (r *Renewer) policy() retry.Policy {
	if r.Backoff.Base > 0 {
		return r.Backoff
	}
	return RenewBackoff
}

func (r *Renewer) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

func defaultJitter(d time.Duration) time.Duration {
	if d < 2 {
		return d
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // back-off jitter, not a secret
}

// Step does what is due now and returns how long to wait before the next
// Step: until RenewAt while the certificate is young, the back-off after a
// failed renewal, or ErrExpired once the certificate has expired.
func (r *Renewer) Step(ctx context.Context) (time.Duration, error) {
	now := r.Clock.Now()
	notAfter := r.Store.NotAfter()
	if !now.Before(notAfter) {
		r.mu.Lock()
		r.expired = true
		r.mu.Unlock()
		r.log().ErrorContext(ctx, "collector certificate expired without renewal; the collector no longer calls the core",
			"collector_id", r.Store.CollectorID(), "not_after", notAfter, "action", ErrExpired.Error())
		return 0, ErrExpired
	}
	if at := r.Store.RenewAt(); now.Before(at) {
		return at.Sub(now), nil
	}
	err := r.renew(ctx)
	if err == nil {
		r.mu.Lock()
		r.failures, r.lastErr, r.lastRenewed = 0, "", now
		r.mu.Unlock()
		r.log().InfoContext(ctx, "collector certificate renewed",
			"collector_id", r.Store.CollectorID(), "not_after", r.Store.NotAfter(), "renew_at", r.Store.RenewAt())
		// Never spin: a core that issues very short certificates is still
		// asked at most once per back-off base.
		return max(r.Store.RenewAt().Sub(now), r.policy().Base), nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return 0, cerr
	}
	r.mu.Lock()
	r.failures++
	n := r.failures
	r.lastErr = err.Error()
	r.mu.Unlock()
	jitter := r.Jitter
	if jitter == nil {
		jitter = defaultJitter
	}
	wait := jitter(r.policy().Delay(n - 1))
	if rem := notAfter.Sub(now); wait > rem {
		wait = rem // wake at the expiry to report it
	}
	r.log().WarnContext(ctx, "collector certificate renewal failed; retrying",
		"attempt", n, "retry_in", wait.String(), "not_after", notAfter, "error", err)
	return wait, nil
}

// renew makes and stores a new key and certificate.
func (r *Renewer) renew(ctx context.Context) error {
	key, err := identity.NewKey()
	if err != nil {
		return err
	}
	csr, err := identity.CSR(key)
	if err != nil {
		return err
	}
	cred, err := r.Client.Renew(ctx, csr)
	if err != nil {
		return err
	}
	if err := checkRenewedValidity(cred, r.Clock.Now(), r.Store.NotAfter()); err != nil {
		return err
	}
	if err := r.Store.Replace(key, cred); err != nil {
		return fmt.Errorf("keep the renewed certificate: %w", err)
	}
	return nil
}

// ErrRenewedValidity refuses a renewed certificate that is not valid now or
// does not outlive the current one; the current certificate stays in use and
// renewal is retried with back-off.
var ErrRenewedValidity = errors.New("the renewed certificate is refused")

// checkRenewedValidity accepts the leaf of cred only when
// NotBefore <= now < NotAfter and its NotAfter is later than current's: a
// renewal must never swap in a certificate that is not yet valid, already
// expired, or shorter-lived than the one it replaces.
func checkRenewedValidity(cred identity.Credentials, now, current time.Time) error {
	b, _ := pem.Decode([]byte(cred.CertificateChain))
	if b == nil || b.Type != "CERTIFICATE" {
		return fmt.Errorf("%w: no certificate in the answer", ErrRenewedValidity)
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRenewedValidity, err)
	}
	switch {
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("%w: not valid before %s, now is %s (check this host's clock)", ErrRenewedValidity, leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return fmt.Errorf("%w: it expired at %s", ErrRenewedValidity, leaf.NotAfter.UTC().Format(time.RFC3339))
	case !leaf.NotAfter.After(current):
		return fmt.Errorf("%w: it expires at %s, not later than the current certificate (%s)", ErrRenewedValidity, leaf.NotAfter.UTC().Format(time.RFC3339), current.UTC().Format(time.RFC3339))
	}
	return nil
}

// Run renews until ctx ends (nil) or the certificate expires (ErrExpired).
func (r *Renewer) Run(ctx context.Context) error {
	for {
		wait, err := r.Step(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if r.Clock.Sleep(ctx, wait) != nil {
			return nil
		}
	}
}

// RenewalStatus is what the collector's status output shows of renewal.
type RenewalStatus struct {
	LastRenewed time.Time `json:"last_renewed,omitzero"`
	Failures    int       `json:"consecutive_failures"`
	LastError   string    `json:"last_error,omitempty"`
	Expired     bool      `json:"expired"`
}

// Status reports the renewal state.
func (r *Renewer) Status() RenewalStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RenewalStatus{LastRenewed: r.lastRenewed, Failures: r.failures, LastError: r.lastErr, Expired: r.expired}
}
