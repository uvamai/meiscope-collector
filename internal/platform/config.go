package platform

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Default values used when the matching MEISCOPE_* variable is unset.
const (
	DefaultHealthAddr = "127.0.0.1:8090"
	DefaultLogLevel   = "info"
	DefaultLogFormat  = "json"
)

// Config is the collector's runtime configuration, read from the environment.
type Config struct {
	// CoreURL is the base URL of the Meiscope core (MEISCOPE_CORE_URL).
	// Optional in WP0.1: the collector does not contact the core yet.
	CoreURL string
	// HealthAddr is the local listen address of /healthz (MEISCOPE_HEALTH_ADDR).
	HealthAddr string
	// LogLevel is debug, info, warn or error (MEISCOPE_LOG_LEVEL).
	LogLevel string
	// LogFormat is json or text (MEISCOPE_LOG_FORMAT).
	LogFormat string
	// StatusRemote lets GET /status answer non-loopback callers
	// (MEISCOPE_STATUS_REMOTE=true). Off by default: only /healthz is open
	// to the network; /pause and /resume are always loopback-only.
	StatusRemote bool
}

// LoadConfig reads the configuration through getenv (os.Getenv in production)
// and validates it.
func LoadConfig(getenv func(string) string) (Config, error) {
	cfg := Config{
		CoreURL:    getenv("MEISCOPE_CORE_URL"),
		HealthAddr: valueOr(getenv("MEISCOPE_HEALTH_ADDR"), DefaultHealthAddr),
		LogLevel:   valueOr(getenv("MEISCOPE_LOG_LEVEL"), DefaultLogLevel),
		LogFormat:  valueOr(getenv("MEISCOPE_LOG_FORMAT"), DefaultLogFormat),
	}
	if v := strings.TrimSpace(getenv("MEISCOPE_STATUS_REMOTE")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("MEISCOPE_STATUS_REMOTE: want true or false, got %q", v)
		}
		cfg.StatusRemote = b
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.CoreURL != "" {
		u, err := url.Parse(c.CoreURL)
		if err != nil {
			return fmt.Errorf("MEISCOPE_CORE_URL: %w", err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("MEISCOPE_CORE_URL: must be an absolute https URL, got %q", c.CoreURL)
		}
	}
	if _, _, err := net.SplitHostPort(c.HealthAddr); err != nil {
		return fmt.Errorf("MEISCOPE_HEALTH_ADDR: %w", err)
	}
	if _, err := parseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("MEISCOPE_LOG_LEVEL: %w", err)
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return fmt.Errorf("MEISCOPE_LOG_FORMAT: must be json or text, got %q", c.LogFormat)
	}
	return nil
}

func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
