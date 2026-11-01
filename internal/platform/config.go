package platform

import (
	"fmt"
	"net"
	"net/url"
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
