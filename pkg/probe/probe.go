// Package probe performs a single, unauthenticated TLS handshake against one
// host and port and returns what the server presented.
//
// Safety model (enforced here and tested):
//   - one TCP connection per call, no retries, hard deadline (max 15 s);
//   - one host only: no CIDRs, ranges or lists; no port scanning;
//   - link-local and cloud metadata addresses are refused, both after DNS
//     resolution and again at dial time;
//   - the handshake is abandoned straight after the server's Certificate
//     message (crypto/tls calls VerifyConnection there, before
//     CertificateVerify), so no client certificate, Finished message,
//     application data or credential is ever sent. Key possession is
//     therefore not proven: the result is what the server presents;
//   - STARTTLS sends only the protocol's upgrade command (SMTP EHLO and
//     STARTTLS, IMAP STARTTLS, POP3 STLS, LDAP StartTLS extended operation,
//     RDP X.224 negotiation, PostgreSQL SSLRequest, MySQL SSLRequest, TDS
//     PRELOGIN); no authentication, no LDAP bind, no user or database name.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Timeouts.
const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = 15 * time.Second
)

// STARTTLS modes.
const (
	StartTLSAuto = "auto"
	StartTLSNone = "none"
	StartTLSSMTP = "smtp"
	StartTLSIMAP = "imap"
	StartTLSPOP3 = "pop3"
	StartTLSLDAP = "ldap"
	// Not STARTTLS in the strict sense but the same idea: a plaintext
	// exchange that asks the server to start TLS.
	StartTLSRDP      = "rdp"
	StartTLSPostgres = "postgres"
	StartTLSMySQL    = "mysql"
	StartTLSMSSQL    = "mssql"
)

// errStopAfterCertificate aborts the handshake once the chain is captured.
var errStopAfterCertificate = errors.New("probe: certificate chain captured; handshake intentionally stopped")

// Resolver resolves a host name to addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Target is one endpoint to probe.
type Target struct {
	Host     string
	Port     int
	SNI      string
	StartTLS string
	Timeout  time.Duration
}

// Prober probes TLS endpoints. The zero value is not usable; use New.
type Prober struct {
	resolver Resolver
	roots    *x509.CertPool
	now      func() time.Time
	log      *slog.Logger
	budget   *Budget
	allow    *Allow
	pace     func(context.Context, netip.Addr) error
}

// Options configure a Prober.
type Options struct {
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Roots is the trust store for chain verification; nil uses the system roots.
	Roots *x509.CertPool
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Budget caps probes per rolling minute across calls; nil means
	// DefaultProbesPerMinute.
	Budget *Budget
	// Allow restricts targets; nil means no list (the metadata block still
	// applies).
	Allow *Allow
	// Pace, when set, is called with the vetted address after every policy
	// check and immediately before the dial; an error refuses the probe. A
	// scanner uses it for its own rate limits and pause. When Pace is set and
	// Budget is nil, no per-process budget applies (the caller paces). Pace
	// runs outside Target.Timeout: its context is the caller's, and the
	// timeout's remainder after the lookup starts when Pace returns.
	Pace func(ctx context.Context, addr netip.Addr) error
}

// New returns a Prober.
func New(o Options) *Prober {
	p := &Prober{resolver: o.Resolver, roots: o.Roots, now: o.Now, log: o.Logger, budget: o.Budget, allow: o.Allow, pace: o.Pace}
	if p.resolver == nil {
		p.resolver = net.DefaultResolver
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	if p.budget == nil && p.pace == nil {
		p.budget, _ = NewBudget(DefaultProbesPerMinute, p.now) // a valid constant cannot fail
	}
	return p
}

// Result is what one probe observed.
type Result struct {
	Host          string
	Port          int
	SNI           string
	IP            string
	AddressClass  string
	StartTLS      string
	TLSVersion    string
	CipherSuite   string
	ALPN          string
	OCSPStapled   bool
	Chain         []*x509.Certificate
	Verification  Verification
	Findings      []Finding
	Notes         []string
	ObservedAtUTC time.Time
}

// Finding is a weakness of the negotiated session. It has the same shape as
// the certificate weaknesses reported by inspect_certificate.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// Session finding codes.
const (
	FindingLegacyTLS10    = "legacy_tls_1_0"
	FindingLegacyTLS11    = "legacy_tls_1_1"
	FindingRSAKeyExchange = "rsa_key_exchange"
)

// inspectionCipherSuites is every TLS 1.0-1.2 suite Go implements, secure
// ones first, so the server's choice reveals what it actually accepts.
// TLS 1.3 suites are not configurable and are always offered.
func inspectionCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// sessionFindings reports a legacy protocol version and RSA key exchange.
func sessionFindings(version, suite uint16) []Finding {
	var f []Finding
	switch version {
	case tls.VersionTLS10:
		f = append(f, Finding{FindingLegacyTLS10, "high", "The server negotiated TLS 1.0, deprecated by RFC 8996 and refused by current browsers."})
	case tls.VersionTLS11:
		f = append(f, Finding{FindingLegacyTLS11, "high", "The server negotiated TLS 1.1, deprecated by RFC 8996 and refused by current browsers."})
	}
	if version <= tls.VersionTLS12 && strings.HasPrefix(tls.CipherSuiteName(suite), "TLS_RSA_") {
		f = append(f, Finding{FindingRSAKeyExchange, "warning", "The server chose RSA key exchange (" + tls.CipherSuiteName(suite) + "): no forward secrecy, so a later key compromise exposes recorded sessions."})
	}
	return f
}

// Validate checks t and fills defaults. It never touches the network.
func Validate(t Target) (Target, error) {
	h, err := NormalizeHost(t.Host)
	if err != nil {
		return t, err
	}
	t.Host = h
	if t.Port == 0 {
		t.Port = 443
	}
	if t.Port < 1 || t.Port > 65535 {
		return t, ErrInvalidPort
	}
	switch {
	case t.Timeout == 0:
		t.Timeout = DefaultTimeout
	case t.Timeout < time.Second || t.Timeout > MaxTimeout:
		return t, ErrInvalidTimeout
	}
	if t.SNI != "" {
		sni, err := NormalizeHost(t.SNI)
		if err != nil {
			return t, fmt.Errorf("sni: %w", err)
		}
		t.SNI = sni
	}
	mode, err := startTLSMode(t.StartTLS, t.Port)
	if err != nil {
		return t, err
	}
	t.StartTLS = mode
	return t, nil
}

func startTLSMode(m string, port int) (string, error) {
	switch m {
	case "", StartTLSAuto:
		switch port {
		case 25, 587:
			return StartTLSSMTP, nil
		case 143:
			return StartTLSIMAP, nil
		case 110:
			return StartTLSPOP3, nil
		case 389:
			return StartTLSLDAP, nil
		case 3389:
			return StartTLSRDP, nil
		case 5432:
			return StartTLSPostgres, nil
		case 3306:
			return StartTLSMySQL, nil
		case 1433:
			return StartTLSMSSQL, nil
		default:
			return StartTLSNone, nil
		}
	case StartTLSNone, StartTLSSMTP, StartTLSIMAP, StartTLSPOP3, StartTLSLDAP,
		StartTLSRDP, StartTLSPostgres, StartTLSMySQL, StartTLSMSSQL:
		return m, nil
	default:
		return "", ErrInvalidSTARTTLS
	}
}

// Probe performs exactly one connection to t.
func (p *Prober) Probe(ctx context.Context, t Target) (*Result, error) {
	t, err := Validate(t)
	if err != nil {
		return nil, err
	}
	// Policy, before any packet (DNS included): the allow list by name or
	// literal, then one slot of the per-process budget.
	if p.allow != nil && !p.allow.allowsHost(t.Host) {
		return nil, fmt.Errorf("%w (%s)", ErrNotAllowed, t.Host)
	}
	if p.budget != nil {
		if err := p.budget.Take(); err != nil {
			return nil, err
		}
	}
	// t.Timeout covers the lookup, the dial and the handshake, never the
	// wait in Pace: a scanner's queue for a busy network is not the
	// target's slowness (S-25).
	start := time.Now()
	rctx, rcancel := context.WithTimeout(ctx, t.Timeout)
	addr, class, err := p.resolve(rctx, t.Host)
	rcancel()
	if err != nil {
		return nil, err
	}
	left := t.Timeout - time.Since(start)
	if p.allow != nil && !p.allow.allowsDial(addr, addr) {
		return nil, fmt.Errorf("%w (%s resolves to %s)", ErrNotAllowed, t.Host, addr)
	}
	res := &Result{Host: t.Host, Port: t.Port, SNI: t.SNI, IP: addr.String(), AddressClass: class, StartTLS: t.StartTLS}
	if class != ClassPublic {
		res.Notes = append(res.Notes, fmt.Sprintf("target address %s is %s (not on the public internet); make sure you are authorised to test it", addr, class))
	}
	if p.pace != nil {
		if err := p.pace(ctx, addr); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, left)
	defer cancel()

	d := net.Dialer{Timeout: left, ControlContext: p.dialGuard(addr)}
	p.log.DebugContext(ctx, "probe dial", slog.String("ip", addr.String()), slog.Int("port", t.Port), slog.String("starttls", t.StartTLS))
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(t.Port)))
	if err != nil {
		return nil, &PhaseError{Phase: PhaseConnect, Err: err}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn, err := startTLS(conn, t.StartTLS)
	if err != nil {
		return nil, &PhaseError{Phase: PhaseStartTLS, Mode: t.StartTLS, Err: err}
	}

	serverName := t.SNI
	if serverName == "" {
		if _, perr := netip.ParseAddr(t.Host); perr != nil {
			serverName = t.Host
		}
	}
	var captured *tls.ConnectionState
	// This connection only inspects; it never carries data. It accepts TLS
	// 1.0/1.1 and every cipher suite Go implements (including RSA key
	// exchange) so certificates on legacy servers can still be captured; the
	// weak protocol is reported as a finding, not treated as a failure.
	//
	// Nothing secret is sent on it. crypto/tls calls VerifyConnection from
	// verifyServerCertificate, as soon as the server's Certificate message
	// arrives and before the client builds its key exchange (TLS <= 1.2) or
	// any further handshake message, and the abort below ends the handshake
	// there. With RSA key exchange no pre-master secret is ever generated,
	// let alone encrypted to the server's key; no client certificate, Finished
	// message, application data or credential follows. Sessions are never
	// cached, so the resumption path (which verifies later) cannot run.
	// Tests assert on the wire that only a ClientHello and an alert are sent.
	cfg := &tls.Config{
		ServerName: serverName,
		// The chain is verified explicitly below, against the system roots,
		// so that invalid chains can still be inspected and explained.
		InsecureSkipVerify: true,             // #nosec G402 -- verification is performed by verifyChain; this is an inspection tool.
		MinVersion:         tls.VersionTLS10, // #nosec G402 -- legacy servers are inspected and reported, never used for data.
		CipherSuites:       inspectionCipherSuites(),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil // never present a client certificate
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			captured = &cs
			return errStopAfterCertificate
		},
	}
	if t.StartTLS == StartTLSNone {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	hsErr := tls.Client(tlsConn, cfg).HandshakeContext(ctx)
	if captured == nil {
		if hsErr == nil {
			hsErr = errors.New("handshake ended without a server certificate")
		}
		return nil, &PhaseError{Phase: PhaseHandshake, Err: hsErr}
	}

	res.ObservedAtUTC = p.now().UTC()
	res.TLSVersion = tls.VersionName(captured.Version)
	res.CipherSuite = tls.CipherSuiteName(captured.CipherSuite)
	res.ALPN = captured.NegotiatedProtocol
	res.OCSPStapled = len(captured.OCSPResponse) > 0
	res.Chain = captured.PeerCertificates
	res.Findings = sessionFindings(captured.Version, captured.CipherSuite)
	verifyName := t.SNI
	if verifyName == "" {
		verifyName = t.Host
	}
	res.Verification = verifyChain(res.Chain, verifyName, p.roots, res.ObservedAtUTC)
	return res, nil
}

func (p *Prober) resolve(ctx context.Context, host string) (netip.Addr, string, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		class, forbidden := ClassifyAddr(a)
		if forbidden {
			return netip.Addr{}, "", ErrForbiddenTarget
		}
		return a.Unmap(), class, nil
	}
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, "", errors.New("resolve host: no addresses")
	}
	// Refuse if any address is forbidden, so a name cannot smuggle a
	// metadata address in among public ones.
	for _, a := range addrs {
		if _, forbidden := ClassifyAddr(a); forbidden {
			return netip.Addr{}, "", fmt.Errorf("%w (host resolves to %s)", ErrForbiddenTarget, a.Unmap())
		}
	}
	a := addrs[0].Unmap()
	class, _ := ClassifyAddr(a)
	return a, class, nil
}

// dialGuard re-checks the address at connect time (defence in depth): the
// metadata block always, then the allow list against the address actually
// being dialled, which must also be the address vetted for this call.
func (p *Prober) dialGuard(vetted netip.Addr) func(context.Context, string, string, syscall.RawConn) error {
	return func(_ context.Context, _, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDialGuard, err)
		}
		dialled := ap.Addr().Unmap()
		if _, forbidden := ClassifyAddr(dialled); forbidden {
			return ErrForbiddenTarget
		}
		if dialled != vetted {
			return fmt.Errorf("%w: dialling %s, but %s was vetted", ErrDialGuard, dialled, vetted)
		}
		if p.allow != nil && !p.allow.allowsDial(dialled, vetted) {
			return fmt.Errorf("%w (dial to %s)", ErrNotAllowed, dialled)
		}
		return nil
	}
}
