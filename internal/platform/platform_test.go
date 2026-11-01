package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := Config{HealthAddr: DefaultHealthAddr, LogLevel: DefaultLogLevel, LogFormat: DefaultLogFormat}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"http core url":  {"MEISCOPE_CORE_URL": "http://core.example"},
		"relative url":   {"MEISCOPE_CORE_URL": "/collector/v1"},
		"bad addr":       {"MEISCOPE_HEALTH_ADDR": "8090"},
		"bad level":      {"MEISCOPE_LOG_LEVEL": "loud"},
		"bad log format": {"MEISCOPE_LOG_FORMAT": "xml"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(env(m)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(env(map[string]string{
		"MEISCOPE_CORE_URL":    "https://10.80.0.1",
		"MEISCOPE_HEALTH_ADDR": ":9000",
		"MEISCOPE_LOG_LEVEL":   "debug",
		"MEISCOPE_LOG_FORMAT":  "text",
	}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.CoreURL != "https://10.80.0.1" || cfg.HealthAddr != ":9000" {
		t.Fatalf("unexpected config %+v", cfg)
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	log, err := NewLogger(&buf, Config{LogLevel: "info", LogFormat: "json"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	log.Debug("hidden")
	log.Info("shown", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("want exactly one JSON record, got %q: %v", buf.String(), err)
	}
	if rec["msg"] != "shown" || rec["component"] != "collector" {
		t.Fatalf("unexpected record %v", rec)
	}
}

func TestHealthHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var h Health
	if err := json.Unmarshal(rr.Body.Bytes(), &h); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h != (Health{Status: "ok", Version: Version, Commit: Commit}) {
		t.Fatalf("unexpected body %+v", h)
	}

	rr = httptest.NewRecorder()
	HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", rr.Code)
	}
}
