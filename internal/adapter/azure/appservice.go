package azure

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// App Service (Microsoft.Web) management API.
const (
	webAPIVersion = "2023-12-01"
	// NameAppService is the registry name and evidence source of the App Service adapter.
	NameAppService = "azure_app_service"

	webTypeCertificate = "Microsoft.Web/certificates"
)

func init() {
	adapter.Register(NameAppService, func(env adapter.Env) adapter.Adapter {
		return &AppService{base{env: env, desc: adapter.Description{
			Name:        NameAppService,
			Source:      NameAppService,
			Summary:     "Azure App Service (Web Apps) certificates and their host-name bindings (read-only)",
			Settings:    []string{"auth", "tenant_id", "client_id", "subscriptions", "rate_per_second"},
			Credentials: []string{CredClientSecret},
		}}}
	})
}

// AppService reads Microsoft.Web certificates and the web apps' SSL
// host-name bindings (FR-DISC-025). Permission: Reader on the
// subscriptions (Microsoft.Web/certificates/read, Microsoft.Web/sites/read).
type AppService struct{ base }

// Validate checks the configuration.
func (a *AppService) Validate(cfg adapter.Config) error {
	if err := validateAuth(cfg); err != nil {
		return err
	}
	_, err := subscriptionsOf(cfg)
	return err
}

type webCertificate struct {
	ID         string `json:"id"`
	Location   string `json:"location"`
	Properties struct {
		Thumbprint     string `json:"thumbprint"`
		ExpirationDate string `json:"expirationDate"`
		IssueDate      string `json:"issueDate"`
		Issuer         string `json:"issuer"`
		SubjectName    string `json:"subjectName"`
		CerBlob        string `json:"cerBlob"`
		KeyVaultID     string `json:"keyVaultId"`
		CanonicalName  string `json:"canonicalName"`
	} `json:"properties"`
}

type webSite struct {
	ID         string `json:"id"`
	Properties struct {
		HostNameSslStates []struct {
			Name       string `json:"name"`
			SslState   string `json:"sslState"`
			Thumbprint string `json:"thumbprint"`
		} `json:"hostNameSslStates"`
	} `json:"properties"`
}

// Sync lists the certificates and sites of each subscription.
func (a *AppService) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := digestCursor{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	subs, err := subscriptionsOf(cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	c := a.newClient(cfg, 5)
	st := map[string]int{}
	var all []submit.Observation
	err = runSubscriptions(ctx, subs, func(ctx context.Context, sub string) error {
		certs, _, err := listAll[webCertificate](ctx, c, "https://"+armHost+"/subscriptions/"+sub+"/providers/Microsoft.Web/certificates?api-version="+webAPIVersion, scopeARM)
		if err != nil {
			return fmt.Errorf("app service certificates (subscription %s): %w", sub, err)
		}
		sites, _, err := listAll[webSite](ctx, c, "https://"+armHost+"/subscriptions/"+sub+"/providers/Microsoft.Web/sites?api-version="+webAPIVersion, scopeARM)
		if err != nil {
			return fmt.Errorf("app service sites (subscription %s): %w", sub, err)
		}
		all = append(all, a.mapWeb(certs, sites, st)...)
		return nil
	})
	if err != nil {
		return adapter.Result{}, err
	}
	obs, digests := deltaByDigest(cur.Digests, all, st)
	mergeStats(st, c.stats)
	next, err := adapter.EncodeCursor(digestCursor{Digests: digests})
	if err != nil {
		return adapter.Result{}, err
	}
	return a.finish(cfg, obs, st, next, since), nil
}

func (a *AppService) mapWeb(certs []webCertificate, sites []webSite, st map[string]int) []submit.Observation {
	bindings := map[string][]submit.Binding{}
	for _, s := range sites {
		for _, h := range s.Properties.HostNameSslStates {
			tp := normThumbprint(h.Thumbprint)
			if tp == "" || strings.EqualFold(h.SslState, "Disabled") || h.Name == "" {
				continue
			}
			bindings[tp] = append(bindings[tp], submit.Binding{Hostname: strings.ToLower(h.Name), Port: 443, ResourceID: s.ID})
		}
	}
	var out []submit.Observation
	for _, wc := range certs {
		p := wc.Properties
		o := cloudObservation(armHost, wc.ID, webTypeCertificate, wc.Location, NameAppService, a.now())
		var meta *submit.CertificateMetadata
		if der, err := base64.StdEncoding.DecodeString(p.CerBlob); err == nil && len(der) > 0 {
			meta, _ = certMetadata(der)
		}
		if meta == nil {
			tp := normThumbprint(p.Thumbprint)
			if tp == "" {
				st[StatSkippedNoCertificate]++
				continue
			}
			meta = &submit.CertificateMetadata{
				SHA1: tp, Subject: p.SubjectName, Issuer: p.Issuer,
				NotBefore: parseTime(p.IssueDate), NotAfter: parseTime(p.ExpirationDate),
			}
		}
		withCertificate(&o, meta)
		// App Service holds the key pair of every certificate it can bind.
		o.Adapter.Custody = &submit.Custody{KeyCustody: submit.KeyPresent}
		switch {
		case p.CanonicalName != "":
			// An App Service managed certificate: the platform renews it.
			o.Adapter.RenewalMode = submit.RenewalExternalAutomated
		case p.KeyVaultID != "":
			// Imported from Key Vault: renewal follows the vault certificate.
			o.Adapter.RenewalMode = submit.RenewalUnknown
		default:
			o.Adapter.RenewalMode = submit.RenewalManual
		}
		b := bindings[meta.SHA1]
		sort.Slice(b, func(i, j int) bool {
			if b[i].Hostname != b[j].Hostname {
				return b[i].Hostname < b[j].Hostname
			}
			return b[i].ResourceID < b[j].ResourceID
		})
		if len(b) > 256 {
			b = b[:256]
		}
		o.Adapter.Bindings = b
		out = append(out, o)
	}
	return out
}
