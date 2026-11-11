package identity

import (
	"crypto/tls"
	"net/http"
	"sync"
)

// Transport returns an http.RoundTripper for calls to the core: base's
// settings (proxy, timeouts) with the pinned CA bundle as the only trusted
// roots and the collector certificate presented as the client certificate.
// It follows Replace: after a renewal the next request uses the new
// certificate and roots, and idle connections made with the old ones are
// closed. base is cloned, never modified.
func (s *Store) Transport(base *http.Transport) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	return &coreTransport{s: s, base: base}
}

type coreTransport struct {
	s    *Store
	base *http.Transport

	mu  sync.Mutex
	gen uint64
	cur *http.Transport
}

func (t *coreTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.transport().RoundTrip(r)
}

// transport returns the http.Transport for the identity in effect, building
// a new one when the identity changed since the last request.
func (t *coreTransport) transport() *http.Transport {
	cert, roots, gen := t.s.current()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil && t.gen == gen {
		return t.cur
	}
	tr := t.base.Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots, // the pinned core CA bundle only, never the system roots
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}
	if t.cur != nil {
		t.cur.CloseIdleConnections()
	}
	t.cur, t.gen = tr, gen
	return tr
}

// CloseIdleConnections closes the idle connections of the transport in use.
func (t *coreTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil {
		t.cur.CloseIdleConnections()
	}
}
