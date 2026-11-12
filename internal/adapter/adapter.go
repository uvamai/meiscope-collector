// Package adapter is the framework for read-only adapters (FR-DISC-022): an
// adapter reads certificate data from a system the customer already runs
// (ADR-0016) and maps it to observations with method adapter. Adapters never
// scan networks or connect to hosts other than the system they are
// configured to read.
//
// The framework provides the Adapter interface, a registry, configuration
// that names credentials by credential.Source reference only, delta cursors,
// pagination, rate limiting, redaction and recorded-fixture replay
// (package adapter/fixture).
package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Cursor is an adapter's opaque delta watermark. The zero value means "from
// the beginning". Adapters encode their state with EncodeCursor.
type Cursor string

// Description describes an adapter.
type Description struct {
	// Name is the registry name, e.g. "osquery".
	Name string
	// Source is the AdapterEvidence.source the adapter reports.
	Source string
	// Summary is one line for "adapter list".
	Summary string
	// Settings lists the setting names the adapter understands.
	Settings []string
	// Credentials lists the credential purposes the adapter may need.
	Credentials []string
}

// Result is the outcome of one Sync.
type Result struct {
	Observations []submit.Observation
	// Cursor is the watermark to pass to the next Sync. The runner stores it
	// only after the observations are durably buffered or submitted.
	Cursor Cursor
	// Stats are counters of the run (for example rows skipped, by reason);
	// they go to the logs and the heartbeat. Keys are stable.
	Stats map[string]int
}

// Adapter reads one external system.
type Adapter interface {
	Describe() Description
	// Validate checks a configuration without contacting anything.
	Validate(cfg Config) error
	// Sync returns the observations made since the cursor and a new cursor.
	// It must be deterministic for the same inputs and cursor.
	Sync(ctx context.Context, cfg Config, since Cursor) (Result, error)
}

// Env holds what the collector gives adapters.
type Env struct {
	// HTTP is the client for adapter API calls (proxy-aware, see egress).
	HTTP *http.Client
	// Creds resolves credential references just in time (ADR-0009).
	Creds credential.Source
	Clock clock.Clock
	Log   *slog.Logger
	// Features are the collector's feature switches.
	Features Features
}

// Features are switches for behaviour the core has not adopted yet. They
// default to off: the collector never sends what the core's current contract
// would reject.
type Features struct {
	// LocalStoreV1 enables store and file targets and adapter evidence
	// (proposed contract 0.5.0). Environment: MEISCOPE_FEATURE_LOCAL_STORE_V1.
	LocalStoreV1 bool
	// CloudResourceV1 enables cloud_resource targets and the adapter
	// evidence fields of the proposed contract 0.10.0 (cloud adapters).
	// Environment: MEISCOPE_FEATURE_CLOUD_RESOURCE_V1.
	CloudResourceV1 bool
}

// EnvLocalStoreV1 is the environment variable of Features.LocalStoreV1.
const EnvLocalStoreV1 = "MEISCOPE_FEATURE_LOCAL_STORE_V1"

// EnvCloudResourceV1 is the environment variable of Features.CloudResourceV1.
const EnvCloudResourceV1 = "MEISCOPE_FEATURE_CLOUD_RESOURCE_V1"

// LoadFeatures reads the feature switches through getenv; unset means off.
func LoadFeatures(getenv func(string) string) (Features, error) {
	var f Features
	for _, sw := range []struct {
		env string
		dst *bool
	}{{EnvLocalStoreV1, &f.LocalStoreV1}, {EnvCloudResourceV1, &f.CloudResourceV1}} {
		v := strings.TrimSpace(getenv(sw.env))
		if v == "" {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Features{}, fmt.Errorf("%s: want true or false, got %q", sw.env, v)
		}
		*sw.dst = b
	}
	return f, nil
}

// Factory builds an adapter for an environment.
type Factory func(Env) Adapter

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register adds a factory under name; it panics on a duplicate, as
// registration happens in init.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("adapter: duplicate registration of " + name)
	}
	registry[name] = f
}

// Lookup returns the factory registered under name.
func Lookup(name string) (Factory, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[name]
	return f, ok
}

// Names returns the registered adapter names, sorted.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Config is one adapter instance's configuration. Settings hold plain
// values; Credentials map a purpose (e.g. "api_token") to a credential.Source
// reference, never to a credential value.
type Config struct {
	// Name identifies the instance; it keys the stored cursor.
	Name        string            `json:"name"`
	Adapter     string            `json:"adapter"`
	Settings    map[string]string `json:"settings,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	refPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// secretish matches setting names that would hold a credential value.
	secretish = regexp.MustCompile(`(?i)(token|passw|secret|api_?key|private|credential|bearer)`)
)

// ErrSecretInSettings is returned when a setting looks like a credential.
var ErrSecretInSettings = errors.New("settings must not hold credentials; name a credential reference under credentials")

// ParseConfig decodes a JSON configuration and checks its shape.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("adapter config: %w", err)
	}
	return c, c.Check()
}

// Check validates the parts of a configuration common to all adapters:
// names, credential references and that no setting carries a credential.
// Error messages never include setting values.
func (c Config) Check() error {
	if !namePattern.MatchString(c.Name) {
		return fmt.Errorf("adapter config: name %q must match %s", c.Name, namePattern)
	}
	if c.Adapter == "" {
		return errors.New("adapter config: adapter is required")
	}
	for k, v := range c.Settings {
		if secretish.MatchString(k) || LooksSecret(v) {
			return fmt.Errorf("adapter config: setting %q: %w", k, ErrSecretInSettings)
		}
	}
	for purpose, ref := range c.Credentials {
		if !refPattern.MatchString(ref) {
			return fmt.Errorf("adapter config: credential %q: reference must match %s", purpose, refPattern)
		}
	}
	return nil
}

// Setting returns a setting or its default.
func (c Config) Setting(name, def string) string {
	if v, ok := c.Settings[name]; ok && v != "" {
		return v
	}
	return def
}

// Credential resolves the credential for purpose through the source. The
// value is a credential.Secret, which never prints.
func (c Config) Credential(ctx context.Context, src credential.Source, purpose string) (credential.Secret, error) {
	ref, ok := c.Credentials[purpose]
	if !ok {
		return credential.Secret{}, fmt.Errorf("credential %q is not configured", purpose)
	}
	if src == nil {
		return credential.Secret{}, credential.ErrNotFound
	}
	s, err := src.Get(ctx, ref)
	if err != nil {
		return credential.Secret{}, fmt.Errorf("credential %q (reference %s): %w", purpose, ref, err)
	}
	return s, nil
}

// EncodeCursor encodes adapter state as a cursor.
func EncodeCursor(v any) (Cursor, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode cursor: %w", err)
	}
	return Cursor(b), nil
}

// DecodeCursor decodes a cursor into v; an empty cursor leaves v unchanged.
func DecodeCursor(c Cursor, v any) error {
	if c == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(c), v); err != nil {
		return fmt.Errorf("decode cursor: %w", err)
	}
	return nil
}
