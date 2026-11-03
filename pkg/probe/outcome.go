package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
)

// ErrDialGuard is returned when the connect-time re-check refuses an address.
var ErrDialGuard = errors.New("dial guard")

// Phases of a probe, as reported by PhaseError.
const (
	PhaseConnect   = "connect"
	PhaseStartTLS  = "starttls"
	PhaseHandshake = "tls handshake"
)

// PhaseError is a failure after the policy checks, once the probe has
// started talking to the network: it says how far the attempt got.
type PhaseError struct {
	Phase string
	Mode  string // the STARTTLS mode, for PhaseStartTLS
	Err   error
}

func (e *PhaseError) Error() string {
	if e.Phase == PhaseStartTLS {
		return "starttls " + e.Mode + ": " + e.Err.Error()
	}
	return e.Phase + ": " + e.Err.Error()
}

func (e *PhaseError) Unwrap() error { return e.Err }

// Outcomes of one probe attempt (D1). A scanner reports every attempt with
// its outcome so that an endpoint that stops answering is noticed.
const (
	OutcomeOK              = "ok"               // a certificate chain was captured
	OutcomeRefused         = "refused"          // the connection was refused
	OutcomeTimeout         = "timeout"          // no answer to the connection attempt
	OutcomeNoTLS           = "no_tls"           // connected, but the server did not start TLS
	OutcomeHandshakeFailed = "handshake_failed" // TLS started but no certificate was captured
)

// Outcome classifies the result of Probe. It returns "" when nothing was
// attempted on the network (a policy refusal, invalid target, failed DNS
// lookup) or the attempt was cancelled (pause or shutdown): such results are
// not observations.
func Outcome(err error) string {
	if err == nil {
		return OutcomeOK
	}
	var pe *PhaseError
	if !errors.As(err, &pe) || errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrDialGuard) || errors.Is(err, ErrForbiddenTarget) || errors.Is(err, ErrNotAllowed) {
		return ""
	}
	switch pe.Phase {
	case PhaseConnect:
		if isRefused(pe.Err) {
			return OutcomeRefused
		}
		return OutcomeTimeout // timed out, unreachable or reset before connecting: no answer
	case PhaseStartTLS:
		if errors.Is(pe.Err, ErrPreTLSInjection) {
			return OutcomeHandshakeFailed
		}
		return OutcomeNoTLS
	default:
		var rh tls.RecordHeaderError
		var ne net.Error
		if errors.As(pe.Err, &rh) || (errors.As(pe.Err, &ne) && ne.Timeout()) || errors.Is(pe.Err, context.DeadlineExceeded) {
			return OutcomeNoTLS // the server answered with something other than TLS, or stayed silent
		}
		return OutcomeHandshakeFailed
	}
}

func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaECONNREFUSED
}

// wsaECONNREFUSED is WSAECONNREFUSED: on Windows syscall.ECONNREFUSED does
// not match it. Elsewhere no errno has this value.
const wsaECONNREFUSED = 10061
