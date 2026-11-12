package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/runner"
)

func localReq(method, path, remote, host, origin string) *http.Request {
	r := httptest.NewRequest(method, "http://placeholder"+path, http.NoBody)
	r.RemoteAddr = remote
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestLocalOnly(t *testing.T) {
	cases := []struct {
		name, remote, host, origin string
		want                       bool
	}{
		{"v4 loopback with port", "127.0.0.1:5000", "127.0.0.1:8090", "", true},
		{"localhost no port", "127.0.0.1:5000", "localhost", "", true},
		{"LOCALHOST upper case", "127.0.0.1:5000", "LOCALHOST:8090", "", true},
		{"v6 loopback", "[::1]:5000", "[::1]:8090", "", true},
		{"v6 loopback no port", "[::1]:5000", "[::1]", "", true},
		{"other 127/8 peer", "127.0.0.2:5000", "127.0.0.1:8090", "", true},
		{"loopback origin", "127.0.0.1:5000", "localhost:8090", "http://localhost:8090", true},
		{"network peer", "10.1.2.3:5000", "127.0.0.1:8090", "", false},
		{"network peer, network host", "10.1.2.3:5000", "10.0.0.5:8090", "", false},
		{"dns rebinding host", "127.0.0.1:5000", "attacker.example:8090", "", false},
		{"pod ip host", "127.0.0.1:5000", "10.0.0.5:8090", "", false},
		{"localhost suffix trick", "127.0.0.1:5000", "localhost.attacker.example", "", false},
		{"empty host", "127.0.0.1:5000", "", "", false},
		{"cross-site origin", "127.0.0.1:5000", "127.0.0.1:8090", "https://attacker.example", false},
		{"null origin", "127.0.0.1:5000", "127.0.0.1:8090", "null", false},
		{"file origin", "127.0.0.1:5000", "127.0.0.1:8090", "file://", false},
		{"v4-mapped peer is not trusted by host alone", "[::ffff:10.1.2.3]:5000", "localhost", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := localOnly(localReq(http.MethodPost, "/pause", c.remote, c.host, c.origin)); got != c.want {
				t.Fatalf("localOnly = %v, want %v", got, c.want)
			}
		})
	}
	// Two Origin headers are refused.
	r := localReq(http.MethodPost, "/pause", "127.0.0.1:1", "localhost", "")
	r.Header.Add("Origin", "http://localhost")
	r.Header.Add("Origin", "http://localhost")
	if localOnly(r) {
		t.Fatal("two Origin headers accepted")
	}
}

func TestControlEndpointsRefuseNonLocalCallers(t *testing.T) {
	run := runner.New(runner.Options{Logger: quietLog()})
	h := listenerGuard(controlHandler(http.NotFoundHandler(), run, quietLog()), true)
	for _, path := range []string{"/pause", "/resume"} {
		for name, req := range map[string]*http.Request{
			"network peer": localReq(http.MethodPost, path, "192.0.2.10:4444", "127.0.0.1:8090", ""),
			"rebound host": localReq(http.MethodPost, path, "127.0.0.1:4444", "attacker.example:8090", ""),
			"cross-site":   localReq(http.MethodPost, path, "127.0.0.1:4444", "127.0.0.1:8090", "https://attacker.example"),
		} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden || run.Paused() {
				t.Fatalf("%s %s: status %d, paused %v", path, name, w.Code, run.Paused())
			}
		}
	}
	// The handler on its own (without listenerGuard) refuses as well.
	w := httptest.NewRecorder()
	controlHandler(http.NotFoundHandler(), run, quietLog()).ServeHTTP(w, localReq(http.MethodPost, "/pause", "192.0.2.10:1", "localhost", ""))
	if w.Code != http.StatusForbidden || run.Paused() {
		t.Fatalf("unguarded pause from the network: %d, paused %v", w.Code, run.Paused())
	}
	// A local caller pauses and resumes.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, localReq(http.MethodPost, "/pause", "127.0.0.1:4444", "127.0.0.1:8090", ""))
	if w.Code != http.StatusNoContent || !run.Paused() {
		t.Fatalf("local pause: %d, paused %v", w.Code, run.Paused())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, localReq(http.MethodPost, "/resume", "[::1]:4444", "localhost:8090", ""))
	if w.Code != http.StatusNoContent || run.Paused() {
		t.Fatalf("local resume: %d, paused %v", w.Code, run.Paused())
	}
}

func TestListenerGuardHealthzOpenStatusLocal(t *testing.T) {
	inner := http.NewServeMux()
	inner.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	inner.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	remote := func(path string) *http.Request {
		return localReq(http.MethodGet, path, "10.244.0.7:5555", "10.244.0.9:8090", "")
	}
	local := func(path string) *http.Request {
		return localReq(http.MethodGet, path, "127.0.0.1:5555", "127.0.0.1:8090", "")
	}
	cases := []struct {
		name         string
		remoteStatus bool
		req          *http.Request
		want         int
	}{
		{"healthz from the network", false, remote("/healthz"), http.StatusOK},
		{"healthz cross-site still open", false, localReq(http.MethodGet, "/healthz", "10.0.0.1:1", "x:1", "https://attacker.example"), http.StatusOK},
		{"status from the network, default", false, remote("/status"), http.StatusForbidden},
		{"status rebound host, default", false, localReq(http.MethodGet, "/status", "127.0.0.1:1", "attacker.example", ""), http.StatusForbidden},
		{"status locally, default", false, local("/status"), http.StatusOK},
		{"status from the network, remote enabled", true, remote("/status"), http.StatusOK},
		{"status cross-site, remote enabled", true, localReq(http.MethodGet, "/status", "10.0.0.1:1", "10.0.0.2:8090", "https://attacker.example"), http.StatusForbidden},
		{"unknown path from the network", false, remote("/debug"), http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			listenerGuard(inner, c.remoteStatus).ServeHTTP(w, c.req)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestPauseOverRealListenerRefusesRebindingHost(t *testing.T) {
	run := runner.New(runner.Options{Logger: quietLog()})
	srv := httptest.NewServer(listenerGuard(controlHandler(http.NotFoundHandler(), run, quietLog()), false))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/pause", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "rebind.attacker.example"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || run.Paused() {
		t.Fatalf("status %d, paused %v", resp.StatusCode, run.Paused())
	}
}
