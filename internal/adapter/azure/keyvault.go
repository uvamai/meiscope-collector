package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Key Vault data-plane API (REST 7.4).
const (
	kvAPIVersion = "7.4"
	// NameKeyVault is the registry name and evidence source of the Key Vault adapter.
	NameKeyVault = "azure_key_vault"

	kvTypeCertificate = "Microsoft.KeyVault/vaults/certificates"
	kvTypeSecret      = "Microsoft.KeyVault/vaults/secrets"

	contentPEM    = "application/x-pem-file"
	contentPKCS12 = "application/x-pkcs12"
)

// Key Vault statistics.
const (
	StatSkippedCertificateBacked = "skipped_certificate_backed"
	StatSkippedNotCertificate    = "skipped_not_certificate"
	StatSkippedNoCertificate     = "skipped_no_certificate"
	StatSecretNotRead            = "secret_not_read"
)

func init() {
	adapter.Register(NameKeyVault, func(env adapter.Env) adapter.Adapter {
		return &KeyVault{base{env: env, desc: adapter.Description{
			Name:    NameKeyVault,
			Source:  NameKeyVault,
			Summary: "Azure Key Vault certificates, and secrets holding PEM or PKCS#12 certificates (read-only)",
			Settings: []string{
				"auth", "tenant_id", "client_id", "vaults", "include_pem_pfx_entries", "read_pem_entries", "rate_per_second",
			},
			Credentials: []string{CredClientSecret},
		}}}
	})
}

// KeyVault reads the certificates of Key Vaults (FR-DISC-024).
//
// Permissions: certificates/list and certificates/get; with include_pem_pfx_entries
// (default true) also secrets/list, and with read_pem_entries (default
// false) secrets/get. In RBAC terms: "Key Vault Certificate User" or
// "Key Vault Reader" plus a custom role with the list data actions; secrets/get
// only when PEM secrets must be read. It never reads key objects.
type KeyVault struct{ base }

// Validate checks the configuration.
func (a *KeyVault) Validate(cfg adapter.Config) error {
	if err := validateAuth(cfg); err != nil {
		return err
	}
	if _, err := vaultsOf(cfg); err != nil {
		return err
	}
	for _, k := range []string{"include_pem_pfx_entries", "read_pem_entries"} {
		if v := cfg.Setting(k, ""); v != "" {
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("%s must be true or false", k)
			}
		}
	}
	return nil
}

func vaultsOf(cfg adapter.Config) ([]string, error) {
	vs := splitList(strings.ToLower(cfg.Setting("vaults", "")))
	if len(vs) == 0 {
		return nil, errors.New("vaults is required (Key Vault names, comma separated)")
	}
	for i, v := range vs {
		v = strings.TrimSuffix(strings.TrimPrefix(v, "https://"), "/")
		v = strings.TrimSuffix(v, vaultSuffix)
		if !vaultName.MatchString(v) {
			return nil, fmt.Errorf("vault %q is not a Key Vault name", v)
		}
		vs[i] = v
	}
	return vs, nil
}

func boolSetting(cfg adapter.Config, name string, def bool) bool {
	b, err := strconv.ParseBool(cfg.Setting(name, strconv.FormatBool(def)))
	if err != nil {
		return def
	}
	return b
}

// mark is a delta watermark: the newest "updated" time seen and the IDs
// updated in that same second.
type mark struct {
	Updated int64    `json:"updated"`
	IDs     []string `json:"ids,omitempty"`
}

func (m mark) seen(id string, upd int64) bool {
	return upd < m.Updated || (upd == m.Updated && slices.Contains(m.IDs, id))
}

func (m *mark) add(id string, upd int64) {
	switch {
	case upd > m.Updated:
		m.Updated, m.IDs = upd, []string{id}
	case upd == m.Updated && !slices.Contains(m.IDs, id):
		m.IDs = append(m.IDs, id)
		slices.Sort(m.IDs)
	}
}

type kvCursor struct {
	Vaults map[string]*kvMarks `json:"vaults"`
}

type kvMarks struct {
	Certificates mark `json:"certificates"`
	Secrets      mark `json:"secrets"`
}

type kvAttributes struct {
	Enabled *bool  `json:"enabled"`
	Expires *int64 `json:"exp"`
	Updated int64  `json:"updated"`
}

type kvCertItem struct {
	ID         string       `json:"id"`
	X5t        string       `json:"x5t"`
	Attributes kvAttributes `json:"attributes"`
}

// kvCertBundle is the answer of GET /certificates/{name}. It holds the
// public certificate (cer) and the policy; key and secret identifiers are
// URLs and are not decoded.
type kvCertBundle struct {
	X5t    string `json:"x5t"`
	Cer    string `json:"cer"`
	Policy *struct {
		KeyProps *struct {
			Exportable *bool `json:"exportable"`
		} `json:"key_props"`
		Issuer *struct {
			Name string `json:"name"`
		} `json:"issuer"`
		LifetimeActions []struct {
			Action struct {
				ActionType string `json:"action_type"`
			} `json:"action"`
		} `json:"lifetime_actions"`
	} `json:"policy"`
}

type kvSecretItem struct {
	ID          string       `json:"id"`
	ContentType string       `json:"contentType"`
	Managed     bool         `json:"managed"`
	Attributes  kvAttributes `json:"attributes"`
}

// Sync reads every configured vault.
func (a *KeyVault) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := kvCursor{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	if cur.Vaults == nil {
		cur.Vaults = map[string]*kvMarks{}
	}
	vaults, err := vaultsOf(cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	c := a.newClient(cfg, 5)
	st := map[string]int{}
	var obs []submit.Observation
	for _, v := range vaults {
		m := cur.Vaults[v]
		if m == nil {
			m = &kvMarks{}
			cur.Vaults[v] = m
		}
		o, err := a.certificates(ctx, c, v, m, st)
		if err != nil {
			return adapter.Result{}, fmt.Errorf("key vault %s: %w", v, err)
		}
		obs = append(obs, o...)
		if boolSetting(cfg, "include_pem_pfx_entries", true) {
			o, err := a.secrets(ctx, c, v, m, boolSetting(cfg, "read_pem_entries", false), st)
			if err != nil {
				return adapter.Result{}, fmt.Errorf("key vault %s: %w", v, err)
			}
			obs = append(obs, o...)
		}
	}
	mergeStats(st, c.stats)
	next, err := adapter.EncodeCursor(cur)
	if err != nil {
		return adapter.Result{}, err
	}
	return a.finish(cfg, obs, st, next, since), nil
}

func vaultBase(v string) string { return "https://" + v + vaultSuffix }

func (a *KeyVault) certificates(ctx context.Context, c *client, v string, m *kvMarks, st map[string]int) ([]submit.Observation, error) {
	q := url.Values{"api-version": {kvAPIVersion}, "maxresults": {"25"}}
	items, _, err := listAll[kvCertItem](ctx, c, vaultBase(v)+"/certificates?"+q.Encode(), scopeVault)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	next := m.Certificates
	var obs []submit.Observation
	for _, it := range items {
		id := strings.ToLower(it.ID)
		if m.Certificates.seen(id, it.Attributes.Updated) {
			st[StatUnchanged]++
			continue
		}
		var b kvCertBundle
		if err := c.get(ctx, it.ID+"?api-version="+kvAPIVersion, scopeVault, &b); err != nil {
			return nil, fmt.Errorf("get certificate: %w", err)
		}
		o := cloudObservation(v+vaultSuffix, it.ID, kvTypeCertificate, "", NameKeyVault, a.now())
		meta := kvMetadata(b.Cer, firstNonEmpty(b.X5t, it.X5t))
		if meta == nil {
			st[StatSkippedNoCertificate]++
		} else {
			withCertificate(&o, meta)
		}
		cust := &submit.Custody{KeyCustody: submit.KeyPresent}
		o.Adapter.RenewalMode = submit.RenewalUnknown
		if b.Policy != nil {
			if b.Policy.KeyProps != nil {
				cust.KeyExportable = b.Policy.KeyProps.Exportable
			}
			o.Adapter.RenewalMode = kvRenewal(b)
		}
		o.Adapter.Custody = cust
		obs = append(obs, o)
		next.add(id, it.Attributes.Updated)
	}
	m.Certificates = next
	return obs, nil
}

// kvRenewal: an issuer named "Unknown" means a manually enrolled
// certificate; a known issuer with an AutoRenew lifetime action is renewed
// by Key Vault itself.
func kvRenewal(b kvCertBundle) string {
	p := b.Policy
	if p.Issuer == nil {
		return submit.RenewalUnknown
	}
	if strings.EqualFold(p.Issuer.Name, "Unknown") {
		return submit.RenewalManual
	}
	for _, la := range p.LifetimeActions {
		if strings.EqualFold(la.Action.ActionType, "AutoRenew") {
			return submit.RenewalExternalAutomated
		}
	}
	return submit.RenewalUnknown
}

// kvMetadata parses cer (base64 DER), else falls back to the x5t
// thumbprint (base64url SHA-1).
func kvMetadata(cer, x5t string) *submit.CertificateMetadata {
	if der, err := base64.StdEncoding.DecodeString(cer); err == nil && len(der) > 0 {
		if m, err := certMetadata(der); err == nil {
			return m
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(x5t, "="))
	if err != nil || len(raw) != 20 {
		return nil
	}
	return &submit.CertificateMetadata{SHA1: fmt.Sprintf("%x", raw)}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *KeyVault) secrets(ctx context.Context, c *client, v string, m *kvMarks, readValues bool, st map[string]int) ([]submit.Observation, error) {
	q := url.Values{"api-version": {kvAPIVersion}, "maxresults": {"25"}}
	items, _, err := listAll[kvSecretItem](ctx, c, vaultBase(v)+"/secrets?"+q.Encode(), scopeVault)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	next := m.Secrets
	var obs []submit.Observation
	for _, it := range items {
		id := strings.ToLower(it.ID)
		if m.Secrets.seen(id, it.Attributes.Updated) {
			st[StatUnchanged]++
			continue
		}
		next.add(id, it.Attributes.Updated)
		if it.Managed {
			// The secret behind a Key Vault certificate, reported above.
			st[StatSkippedCertificateBacked]++
			continue
		}
		ct := strings.ToLower(strings.TrimSpace(it.ContentType))
		if ct != contentPEM && ct != contentPKCS12 {
			st[StatSkippedNotCertificate]++
			continue
		}
		o := cloudObservation(v+vaultSuffix, it.ID, kvTypeSecret, "", NameKeyVault, a.now())
		o.Adapter.RenewalMode = submit.RenewalManual
		if ct == contentPKCS12 || !readValues {
			// A PKCS#12 container is never opened, and a secret is read
			// only when read_pem_entries allows it.
			st[StatSecretNotRead]++
			o.Adapter.Custody = &submit.Custody{KeyCustody: submit.KeyUnknown}
			o.Adapter.Findings = []submit.Finding{{Code: submit.FindingSecretNotRead}}
			obs = append(obs, o)
			continue
		}
		meta, custody, err := a.pemSecret(ctx, c, it.ID)
		if err != nil {
			return nil, err
		}
		o.Adapter.Custody = &submit.Custody{KeyCustody: custody}
		if meta == nil {
			st[StatSkippedNoCertificate]++
			o.Adapter.Findings = []submit.Finding{{Code: submit.FindingSecretNotRead}}
		} else {
			withCertificate(&o, meta)
		}
		obs = append(obs, o)
	}
	m.Secrets = next
	return obs, nil
}

// pemSecret reads a PEM secret and keeps only its first certificate's
// public metadata and whether a private key is present. The value never
// leaves this function: it is not logged, stored or returned, and the
// buffer is overwritten before returning.
func (a *KeyVault) pemSecret(ctx context.Context, c *client, id string) (*submit.CertificateMetadata, string, error) {
	var b struct {
		Value json.RawMessage `json:"value"`
	}
	if err := c.get(ctx, id+"?api-version="+kvAPIVersion, scopeVault, &b); err != nil {
		return nil, "", fmt.Errorf("get secret: %w", err)
	}
	defer clear(b.Value)
	meta, hasKey := scanPEM(unquoteJSON(b.Value))
	custody := submit.KeyAbsent
	if hasKey {
		custody = submit.KeyPresent
	}
	return meta, custody, nil
}

// unquoteJSON decodes a JSON string into a fresh byte slice (so the caller
// can overwrite it); non-strings give nil.
func unquoteJSON(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return []byte(s)
}

// scanPEM returns the metadata of the first certificate and whether any
// private-key block is present. Key blocks are recognised by type only and
// their bytes are overwritten; they are never decoded.
func scanPEM(b []byte) (*submit.CertificateMetadata, bool) {
	defer clear(b)
	var meta *submit.CertificateMetadata
	hasKey := false
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE" && meta == nil:
			if m, err := certMetadata(blk.Bytes); err == nil {
				meta = m
			}
		case strings.Contains(blk.Type, "PRIVATE KEY"):
			hasKey = true
			clear(blk.Bytes)
		}
	}
	return meta, hasKey
}
