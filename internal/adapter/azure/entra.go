package azure

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

const (
	// NameEntra is the registry name and evidence source of the Entra ID adapter.
	NameEntra = "entra_id"

	entraTypeKey      = "Microsoft.Graph/applications/keyCredentials"
	entraTypePassword = "Microsoft.Graph/applications/passwordCredentials"

	// entraSelect names the only properties requested. The key value of a
	// keyCredential and the hint and secretText of a passwordCredential are
	// never requested and never decoded.
	entraSelect = "id,appId,displayName,keyCredentials,passwordCredentials"

	// StatSkippedNoThumbprint counts key credentials whose
	// customKeyIdentifier is not a SHA-1 thumbprint.
	StatSkippedNoThumbprint = "skipped_no_thumbprint"
	// StatRemoved counts deleted applications in a delta.
	StatRemoved = "removed"
	// StatResync counts delta tokens Graph expired (a full read follows).
	StatResync = "delta_resync"
)

func init() {
	adapter.Register(NameEntra, func(env adapter.Env) adapter.Adapter {
		return &Entra{base{env: env, desc: adapter.Description{
			Name:        NameEntra,
			Source:      NameEntra,
			Summary:     "Entra ID application certificate credentials, and password-credential expiry only (read-only)",
			Settings:    []string{"auth", "tenant_id", "client_id", "rate_per_second"},
			Credentials: []string{CredClientSecret},
		}}}
	})
}

// Entra reads the certificate credentials (keyCredentials) of Entra ID
// application registrations, and the expiry of their password credentials
// without any value (FR-DISC-026), through the Microsoft Graph delta query.
// Permission: Microsoft Graph application permission Application.Read.All.
type Entra struct{ base }

// Validate checks the configuration.
func (a *Entra) Validate(cfg adapter.Config) error { return validateAuth(cfg) }

type entraCursor struct {
	// DeltaLink is Graph's @odata.deltaLink of the last complete read.
	DeltaLink string `json:"delta_link,omitempty"`
}

type entraKeyCredential struct {
	KeyID               string `json:"keyId"`
	Type                string `json:"type"`
	CustomKeyIdentifier string `json:"customKeyIdentifier"`
	StartDateTime       string `json:"startDateTime"`
	EndDateTime         string `json:"endDateTime"`
}

// entraPasswordCredential declares only the identifier and validity; the
// hint and secretText properties are deliberately absent.
type entraPasswordCredential struct {
	KeyID         string `json:"keyId"`
	StartDateTime string `json:"startDateTime"`
	EndDateTime   string `json:"endDateTime"`
}

type entraApp struct {
	ID      string `json:"id"`
	Removed *struct {
		Reason string `json:"reason"`
	} `json:"@removed"`
	// nil when a delta page does not carry the property (unchanged).
	KeyCredentials      *[]entraKeyCredential      `json:"keyCredentials"`
	PasswordCredentials *[]entraPasswordCredential `json:"passwordCredentials"`
}

// Sync follows the stored delta link, or starts a full delta read.
func (a *Entra) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := entraCursor{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	c := a.newClient(cfg, 5)
	st := map[string]int{}
	full := "https://" + graphHost + "/v1.0/applications/delta?" + url.Values{"$select": {entraSelect}}.Encode()
	start := full
	if cur.DeltaLink != "" {
		start = cur.DeltaLink
	}
	apps, delta, err := listAll[entraApp](ctx, c, start, scopeGraph)
	var se *statusError
	if err != nil && start != full && errors.As(err, &se) && se.status == http.StatusGone {
		// The delta token expired: read everything again.
		st[StatResync]++
		apps, delta, err = listAll[entraApp](ctx, c, full, scopeGraph)
	}
	if err != nil {
		return adapter.Result{}, fmt.Errorf("entra applications: %w", err)
	}
	if delta == "" {
		return adapter.Result{}, errors.New("entra applications: Graph returned no deltaLink")
	}
	if _, err := checkURL(delta, scopeGraph); err != nil {
		return adapter.Result{}, err
	}
	var obs []submit.Observation
	for _, app := range apps {
		if app.Removed != nil {
			st[StatRemoved]++
			continue
		}
		obs = append(obs, a.mapApp(app, st)...)
	}
	mergeStats(st, c.stats)
	next, err := adapter.EncodeCursor(entraCursor{DeltaLink: delta})
	if err != nil {
		return adapter.Result{}, err
	}
	return a.finish(cfg, obs, st, next, since), nil
}

func (a *Entra) mapApp(app entraApp, st map[string]int) []submit.Observation {
	var out []submit.Observation
	base := "/applications/" + app.ID
	if app.KeyCredentials != nil {
		for _, k := range *app.KeyCredentials {
			if !strings.EqualFold(k.Type, "AsymmetricX509Cert") || k.KeyID == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(k.CustomKeyIdentifier)
			if err != nil || len(raw) != 20 {
				st[StatSkippedNoThumbprint]++
				continue
			}
			o := cloudObservation(graphHost, base+"/keyCredentials/"+k.KeyID, entraTypeKey, "", NameEntra, a.now())
			withCertificate(&o, &submit.CertificateMetadata{
				SHA1:      fmt.Sprintf("%x", raw),
				NotBefore: parseTime(k.StartDateTime),
				NotAfter:  parseTime(k.EndDateTime),
			})
			// Entra holds only the public key; the private key is with the client.
			o.Adapter.Custody = &submit.Custody{KeyCustody: submit.KeyAbsent}
			o.Adapter.RenewalMode = submit.RenewalManual
			out = append(out, o)
		}
	}
	if app.PasswordCredentials != nil {
		for _, p := range *app.PasswordCredentials {
			if p.KeyID == "" {
				continue
			}
			o := cloudObservation(graphHost, base+"/passwordCredentials/"+p.KeyID, entraTypePassword, "", NameEntra, a.now())
			o.Adapter.Findings = []submit.Finding{{
				Code: submit.FindingSecretCredentialExpiry, NotAfter: parseTime(p.EndDateTime), CredentialID: p.KeyID,
			}}
			out = append(out, o)
		}
	}
	return out
}
