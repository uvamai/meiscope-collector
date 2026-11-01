package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Target errors. All are refusals made before any packet is sent.
var (
	ErrInvalidHost     = errors.New("host must be a single DNS name or IP address")
	ErrCIDR            = errors.New("CIDR blocks are not accepted; give a single host")
	ErrRange           = errors.New("address ranges and lists are not accepted; give a single host")
	ErrInvalidPort     = errors.New("port must be between 1 and 65535")
	ErrForbiddenTarget = errors.New("target refused: link-local and cloud metadata addresses are never probed")
	ErrInvalidTimeout  = errors.New("timeout_seconds must be between 1 and 15")
	ErrInvalidSTARTTLS = errors.New("starttls must be one of auto, none, smtp, imap, pop3, ldap")
)

// Address classes reported to the caller.
const (
	ClassPublic   = "public"
	ClassPrivate  = "private"
	ClassLoopback = "loopback"
)

// forbiddenPrefixes are never dialled: link-local ranges (which host every
// major cloud's instance metadata service) and specific metadata addresses.
func forbiddenPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),     // IPv4 link-local; AWS, GCP, Azure, OCI, DigitalOcean metadata
		netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
		netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
		netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
		netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud Classic metadata
		netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
		netip.MustParsePrefix("::/128"),             // unspecified
		netip.MustParsePrefix("224.0.0.0/4"),        // IPv4 multicast
		netip.MustParsePrefix("255.255.255.255/32"), // broadcast
		netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
		netip.MustParsePrefix("fd00:ec2::/32"),      // AWS Nitro reserved IPv6, incl. IMDS fd00:ec2::254
		netip.MustParsePrefix("fd20:ce::254/128"),   // GCP metadata over IPv6
	}
}

// metadataHostnames are refused by name, before resolution.
func metadataHostnames() []string {
	return []string{
		"metadata", "metadata.google.internal", "metadata.goog",
		"instance-data", "instance-data.ec2.internal", "metadata.azure.internal",
	}
}

// ClassifyAddr reports the class of addr and whether it is forbidden.
// IPv4-mapped IPv6 and NAT64 (64:ff9b::/96) forms are judged by the
// embedded IPv4 address.
func ClassifyAddr(addr netip.Addr) (class string, forbidden bool) {
	addr = addr.Unmap()
	if addr.Is6() && netip.MustParsePrefix("64:ff9b::/96").Contains(addr) {
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if c, f := ClassifyAddr(embedded); f {
			return c, true
		}
	}
	for _, p := range forbiddenPrefixes() {
		if p.Contains(addr) {
			return "forbidden", true
		}
	}
	switch {
	case addr.IsLoopback():
		return ClassLoopback, false
	case addr.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr):
		return ClassPrivate, false
	default:
		return ClassPublic, false
	}
}

// NormalizeHost validates a host argument and returns it without IPv6
// brackets or a trailing dot. It rejects anything that is not one host.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || len(h) > 253 {
		return "", ErrInvalidHost
	}
	if strings.Contains(h, "/") {
		return "", ErrCIDR
	}
	if strings.ContainsAny(h, ", \t\r\n;*") {
		return "", ErrRange
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	if strings.Contains(h, "-") && strings.Trim(h, "0123456789.-") == "" {
		return "", ErrRange
	}
	for _, r := range h {
		ok := r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return "", fmt.Errorf("%w: unexpected character %q", ErrInvalidHost, r)
		}
	}
	for _, m := range metadataHostnames() {
		if h == m {
			return "", ErrForbiddenTarget
		}
	}
	return h, nil
}
