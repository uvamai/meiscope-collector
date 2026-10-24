// Package egress builds the collector's outbound HTTP transport
// (FR-DISC-033): HTTPS through a forward proxy with CONNECT, from explicit
// configuration or the standard environment variables, with an optional
// extra CA bundle (for a TLS-inspecting proxy or a private core CA).
//
// Proxy credentials come only from the credential source, just in time for
// each CONNECT, and are sent only in the CONNECT request's
// Proxy-Authorization header. A proxy URL that embeds user information is
// refused, because it would end up in logs and errors; error messages name
// the proxy by host only.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/credential"
)

// Config is the egress configuration (MEISCOPE_PROXY_URL,
// MEISCOPE_PROXY_CREDENTIAL, MEISCOPE_NO_PROXY, MEISCOPE_CA_BUNDLE).
type Config struct {
	// ProxyURL is an explicit http:// or https:// proxy; it wins over the
	// environment. Empty: HTTPS_PROXY / NO_PROXY from the environment.
	ProxyURL string
	// NoProxy lists hosts that bypass the explicit proxy (comma-separated,
	// as NO_PROXY).
	NoProxy string
	// CredentialRef names the proxy credential ("user:password", sent as
	// Basic) in the credential source; empty: no proxy authentication.
	CredentialRef string
	// CABundle is a PEM file of extra trusted roots, added to the system pool.
	CABundle string
}

// LoadConfig reads the configuration through getenv.
func LoadConfig(getenv func(string) string) Config {
	return Config{
		ProxyURL:      strings.TrimSpace(getenv("MEISCOPE_PROXY_URL")),
		NoProxy:       strings.TrimSpace(getenv("MEISCOPE_NO_PROXY")),
		CredentialRef: strings.TrimSpace(getenv("MEISCOPE_PROXY_CREDENTIAL")),
		CABundle:      strings.TrimSpace(getenv("MEISCOPE_CA_BUNDLE")),
	}
}

// ErrProxyUserinfo refuses proxy URLs that embed credentials.
var ErrProxyUserinfo = errors.New("the proxy URL must not contain user information; set MEISCOPE_PROXY_CREDENTIAL to a credential reference instead")

// Options are injectable parts (tests).
type Options struct {
	// Getenv reads HTTPS_PROXY / NO_PROXY when no explicit proxy is set;
	// nil uses http.ProxyFromEnvironment.
	EnvProxy func(*http.Request) (*url.URL, error)
}

// Transport returns an http.Transport for cfg. creds may be nil when no
// proxy credential is configured.
func Transport(cfg Config, creds credential.Source, opts Options) (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSHandshakeTimeout = 15 * time.Second
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CABundle != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(filepath.Clean(cfg.CABundle))
		if err != nil {
			return nil, fmt.Errorf("MEISCOPE_CA_BUNDLE: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("MEISCOPE_CA_BUNDLE: no PEM certificates found")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	proxy, err := proxyFunc(cfg, opts)
	if err != nil {
		return nil, err
	}
	t.Proxy = proxy
	if cfg.CredentialRef != "" {
		if creds == nil {
			return nil, errors.New("MEISCOPE_PROXY_CREDENTIAL is set but there is no credential source")
		}
		ref := cfg.CredentialRef
		t.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, _ string) (http.Header, error) {
			s, err := creds.Get(ctx, ref)
			if err != nil {
				return nil, fmt.Errorf("proxy %s: credential %s: %w", proxyURL.Host, ref, err)
			}
			v := s.Reveal()
			if !strings.Contains(v, ":") {
				return nil, fmt.Errorf("proxy %s: credential %s must be user:password", proxyURL.Host, ref)
			}
			return http.Header{"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(v))}}, nil
		}
	}
	return t, nil
}

func proxyFunc(cfg Config, opts Options) (func(*http.Request) (*url.URL, error), error) {
	if cfg.ProxyURL == "" {
		env := opts.EnvProxy
		if env == nil {
			env = http.ProxyFromEnvironment
		}
		return func(r *http.Request) (*url.URL, error) {
			u, err := env(r)
			if err != nil {
				return nil, errors.New("invalid proxy in HTTPS_PROXY/HTTP_PROXY")
			}
			if u != nil && u.User != nil {
				return nil, ErrProxyUserinfo
			}
			return u, nil
		}, nil
	}
	u, err := url.Parse(cfg.ProxyURL)
	if err != nil {
		return nil, errors.New("MEISCOPE_PROXY_URL: not a URL")
	}
	if u.User != nil {
		return nil, fmt.Errorf("MEISCOPE_PROXY_URL: %w", ErrProxyUserinfo)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("MEISCOPE_PROXY_URL: want http://host:port or https://host:port, got scheme %q", u.Scheme)
	}
	bypass := splitNoProxy(cfg.NoProxy)
	return func(r *http.Request) (*url.URL, error) {
		if bypassed(r.URL.Hostname(), bypass) {
			return nil, nil
		}
		return u, nil
	}, nil
}

func splitNoProxy(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// bypassed matches host against NO_PROXY-style entries: "*", an exact host
// or IP, ".suffix" or "suffix" for a domain and its subdomains, or a CIDR.
func bypassed(host string, entries []string) bool {
	host = strings.ToLower(host)
	ip := net.ParseIP(host)
	for _, e := range entries {
		switch {
		case e == "*":
			return true
		case strings.Contains(e, "/"):
			if _, n, err := net.ParseCIDR(e); err == nil && ip != nil && n.Contains(ip) {
				return true
			}
		case host == strings.TrimPrefix(e, "."):
			return true
		case strings.HasSuffix(host, "."+strings.TrimPrefix(e, ".")):
			return true
		}
	}
	return false
}

// Client wraps a transport in an http.Client with a timeout.
func Client(t http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{Transport: t, Timeout: timeout}
}
