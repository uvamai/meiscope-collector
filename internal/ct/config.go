package ct

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/platform"
)

// Config is the CT poller's configuration, read from MEISCOPE_CT_*
// variables. The Cert Spotter key is not here: it comes from the
// credential source.
type Config struct {
	Domains          Domains
	Logs             []LogConfig
	StateFile        string
	CertSpotter      bool
	CrtShFallback    bool
	MaxEntriesPerLog uint64
	Contact          string
	CertSpotterURL   string
	CrtShURL         string
}

// LogConfig names a log to tail.
type LogConfig struct {
	Kind string // "rfc6962" or "static"
	URL  string
}

// LoadConfig reads the configuration through getenv.
func LoadConfig(getenv func(string) string) (Config, error) {
	cfg := Config{
		StateFile:        getenv("MEISCOPE_CT_STATE_FILE"),
		CertSpotter:      true,
		CrtShFallback:    true,
		MaxEntriesPerLog: DefaultMaxEntriesPerLog,
		Contact:          strings.TrimSpace(getenv("MEISCOPE_CT_CONTACT")),
		CertSpotterURL:   valueOr(getenv("MEISCOPE_CT_CERTSPOTTER_URL"), CertSpotterURL),
		CrtShURL:         valueOr(getenv("MEISCOPE_CT_CRTSH_URL"), CrtShURL),
	}
	ds, err := ParseDomains(splitList(getenv("MEISCOPE_CT_DOMAINS")))
	if err != nil {
		return Config{}, fmt.Errorf("MEISCOPE_CT_DOMAINS: %w", err)
	}
	cfg.Domains = ds
	for _, item := range splitList(getenv("MEISCOPE_CT_LOGS")) {
		lc, err := ParseLogConfig(item)
		if err != nil {
			return Config{}, fmt.Errorf("MEISCOPE_CT_LOGS: %w", err)
		}
		cfg.Logs = append(cfg.Logs, lc)
	}
	for name, dst := range map[string]*bool{"MEISCOPE_CT_CERTSPOTTER": &cfg.CertSpotter, "MEISCOPE_CT_CRTSH_FALLBACK": &cfg.CrtShFallback} {
		if v := getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", name, err)
			}
			*dst = b
		}
	}
	if v := getenv("MEISCOPE_CT_MAX_ENTRIES_PER_LOG"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			return Config{}, fmt.Errorf("MEISCOPE_CT_MAX_ENTRIES_PER_LOG: want a positive integer, got %q", v)
		}
		cfg.MaxEntriesPerLog = n
	}
	for name, u := range map[string]string{"MEISCOPE_CT_CERTSPOTTER_URL": cfg.CertSpotterURL, "MEISCOPE_CT_CRTSH_URL": cfg.CrtShURL} {
		if err := checkURL(u); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	return cfg, nil
}

// ParseLogConfig parses "rfc6962=<log URL>" or "static=<monitoring prefix>".
func ParseLogConfig(s string) (LogConfig, error) {
	kind, u, ok := strings.Cut(s, "=")
	if !ok || (kind != "rfc6962" && kind != "static") {
		return LogConfig{}, fmt.Errorf("want rfc6962=<url> or static=<url>, got %q", s)
	}
	if err := checkURL(u); err != nil {
		return LogConfig{}, err
	}
	return LogConfig{Kind: kind, URL: u}, nil
}

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("want an absolute http(s) URL, got %q", s)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// UserAgent identifies the collector to public CT services. Some logs
// require contact details; MEISCOPE_CT_CONTACT adds them.
func (c Config) UserAgent() string {
	ua := "meiscope-collector/" + platform.Version + " (+https://github.com/uvamai/meiscope-collector)"
	if c.Contact != "" {
		ua += " contact: " + c.Contact
	}
	return ua
}

// NewPoller builds a poller from the configuration. rt is the base
// transport (nil for http.DefaultTransport).
func (c Config) NewPoller(rt http.RoundTripper, clk clock.Clock, creds credential.Source) (*Poller, error) {
	ua := c.UserAgent()
	p := &Poller{Domains: c.Domains, MaxEntriesPerLog: c.MaxEntriesPerLog, StartAtHead: true, Clock: clk}
	if c.CertSpotter {
		p.CertSpotter = NewCertSpotter(c.CertSpotterURL, rt, clk, CertSpotterPoliteness, ua, creds)
	}
	if c.CrtShFallback {
		p.CrtSh = NewCrtSh(c.CrtShURL, rt, clk, CrtShPoliteness, ua)
	}
	for _, lc := range c.Logs {
		switch lc.Kind {
		case "rfc6962":
			l, err := NewRFC6962Log(lc.URL, nil, rt, clk, LogPoliteness, ua)
			if err != nil {
				return nil, err
			}
			p.Logs = append(p.Logs, l)
		case "static":
			p.Logs = append(p.Logs, NewStaticLog(lc.URL, nil, rt, clk, LogPoliteness, ua))
		default:
			return nil, fmt.Errorf("unknown log kind %q", lc.Kind)
		}
	}
	return p, nil
}
