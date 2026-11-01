package platform

import (
	"fmt"
	"io"
	"log/slog"
)

// NewLogger returns a structured logger writing to w in the configured format.
func NewLogger(w io.Writer, cfg Config) (*slog.Logger, error) {
	level, err := parseLevel(cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch cfg.LogFormat {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.LogFormat)
	}
	return slog.New(h).With("component", "collector", "version", Version), nil
}

func parseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("unknown log level %q", s)
	}
	return l, nil
}
