package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// The local listener (MEISCOPE_HEALTH_ADDR) serves GET /healthz to anyone
// who can reach it, so container probes keep working when it binds to all
// interfaces. Everything else on it is local-only:
//
//   - POST /pause and POST /resume always need a loopback peer address AND a
//     loopback Host header (localhost, 127.0.0.1 or [::1], with or without a
//     port). A Host check alone would not stop a peer on the network; a
//     peer check alone would not stop DNS rebinding from a local browser.
//   - GET /status needs the same unless MEISCOPE_STATUS_REMOTE=true.
//   - Every path but /healthz refuses a cross-site request: an Origin header
//     must be absent (curl, scripts) or name a loopback host.
//
// A refused request gets 403 and changes nothing.

// isLoopbackPeer reports whether the request came from a loopback address.
func isLoopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackHost reports whether hostport (a Host header or URL host) names
// localhost, 127.0.0.1 or ::1, with or without a port.
func isLoopbackHost(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host // brackets already removed
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]") // "[::1]" without a port
	switch strings.ToLower(strings.TrimSuffix(h, ".")) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// sameOriginOK reports whether the request carries no Origin header, or one
// whose host is loopback (a page served from the collector itself).
func sameOriginOK(r *http.Request) bool {
	vals, present := r.Header["Origin"]
	if !present {
		return true
	}
	if len(vals) != 1 {
		return false
	}
	u, err := url.Parse(vals[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false // includes "null" from sandboxed or file: pages
	}
	return isLoopbackHost(u.Host)
}

// localOnly reports whether r may use a local-only endpoint.
func localOnly(r *http.Request) bool {
	return isLoopbackPeer(r) && isLoopbackHost(r.Host) && sameOriginOK(r)
}

// requireLocal wraps h so that only local, same-origin requests reach it.
func requireLocal(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOnly(r) {
			http.Error(w, "forbidden: this endpoint accepts loopback requests only", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// listenerGuard applies the rules above to the whole local listener:
// /healthz is open, /status is local-only unless remoteStatus, and every
// other path (pause, resume, anything added later) is local-only.
func listenerGuard(h http.Handler, remoteStatus bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/healthz":
		case r.URL.Path == "/status" && remoteStatus:
			if !sameOriginOK(r) {
				http.Error(w, "forbidden: cross-site request", http.StatusForbidden)
				return
			}
		default:
			if !localOnly(r) {
				http.Error(w, "forbidden: this endpoint accepts loopback requests only", http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
