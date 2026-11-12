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

// Application Gateway (Microsoft.Network) management API.
const (
	netAPIVersion = "2024-05-01"
	// NameAppGateway is the registry name and evidence source of the App Gateway adapter.
	NameAppGateway = "azure_app_gateway"

	agwTypeCertificate = "Microsoft.Network/applicationGateways/sslCertificates"

	// StatListenerNoHostname counts HTTPS listeners without a host name
	// (basic listeners): their certificate is reported without that binding.
	StatListenerNoHostname = "listener_no_hostname"
)

func init() {
	adapter.Register(NameAppGateway, func(env adapter.Env) adapter.Adapter {
		return &AppGateway{base{env: env, desc: adapter.Description{
			Name:        NameAppGateway,
			Source:      NameAppGateway,
			Summary:     "Azure Application Gateway listener certificates and their HTTPS listeners (read-only)",
			Settings:    []string{"auth", "tenant_id", "client_id", "subscriptions", "rate_per_second"},
			Credentials: []string{CredClientSecret},
		}}}
	})
}

// AppGateway reads the SSL certificates of Application Gateways and the
// HTTPS listeners that use them (FR-DISC-025). Permission: Reader on the
// subscriptions (Microsoft.Network/applicationGateways/read).
type AppGateway struct{ base }

// Validate checks the configuration.
func (a *AppGateway) Validate(cfg adapter.Config) error {
	if err := validateAuth(cfg); err != nil {
		return err
	}
	_, err := subscriptionsOf(cfg)
	return err
}

type subRef struct {
	ID string `json:"id"`
}

// appGateway holds the parts of an Application Gateway the adapter reads.
// The write-only certificate fields (data, password) are never returned by
// GET and are not declared here.
type appGateway struct {
	ID         string `json:"id"`
	Location   string `json:"location"`
	Properties struct {
		SSLCertificates []struct {
			ID         string `json:"id"`
			Properties struct {
				PublicCertData   string `json:"publicCertData"`
				KeyVaultSecretID string `json:"keyVaultSecretId"`
			} `json:"properties"`
		} `json:"sslCertificates"`
		FrontendPorts []struct {
			ID         string `json:"id"`
			Properties struct {
				Port int `json:"port"`
			} `json:"properties"`
		} `json:"frontendPorts"`
		HTTPListeners []struct {
			ID         string `json:"id"`
			Properties struct {
				Protocol       string   `json:"protocol"`
				HostName       string   `json:"hostName"`
				HostNames      []string `json:"hostNames"`
				FrontendPort   *subRef  `json:"frontendPort"`
				SSLCertificate *subRef  `json:"sslCertificate"`
			} `json:"properties"`
		} `json:"httpListeners"`
	} `json:"properties"`
}

// Sync lists the Application Gateways of each subscription.
func (a *AppGateway) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
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
		gws, _, err := listAll[appGateway](ctx, c, "https://"+armHost+"/subscriptions/"+sub+"/providers/Microsoft.Network/applicationGateways?api-version="+netAPIVersion, scopeARM)
		if err != nil {
			return fmt.Errorf("application gateways (subscription %s): %w", sub, err)
		}
		for _, g := range gws {
			all = append(all, a.mapGateway(g, st)...)
		}
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

func (a *AppGateway) mapGateway(g appGateway, st map[string]int) []submit.Observation {
	ports := map[string]int{}
	for _, fp := range g.Properties.FrontendPorts {
		ports[strings.ToLower(fp.ID)] = fp.Properties.Port
	}
	bindings := map[string][]submit.Binding{}
	for _, l := range g.Properties.HTTPListeners {
		lp := l.Properties
		if !strings.EqualFold(lp.Protocol, "Https") || lp.SSLCertificate == nil {
			continue
		}
		port := 0
		if lp.FrontendPort != nil {
			port = ports[strings.ToLower(lp.FrontendPort.ID)]
		}
		names := lp.HostNames
		if len(names) == 0 && lp.HostName != "" {
			names = []string{lp.HostName}
		}
		if len(names) == 0 {
			st[StatListenerNoHostname]++
			continue
		}
		key := strings.ToLower(lp.SSLCertificate.ID)
		for _, n := range names {
			b := submit.Binding{Hostname: strings.ToLower(n), ResourceID: l.ID}
			if port > 0 && port <= 65535 {
				b.Port = port
			}
			bindings[key] = append(bindings[key], b)
		}
	}
	var out []submit.Observation
	for _, sc := range g.Properties.SSLCertificates {
		o := cloudObservation(armHost, sc.ID, agwTypeCertificate, g.Location, NameAppGateway, a.now())
		var meta *submit.CertificateMetadata
		if p7, err := base64.StdEncoding.DecodeString(sc.Properties.PublicCertData); err == nil && len(p7) > 0 {
			if ders, err := pkcs7Certificates(p7); err == nil {
				meta, _ = certMetadata(leafOf(ders))
			}
		}
		if meta == nil {
			st[StatSkippedNoCertificate]++
			continue
		}
		withCertificate(&o, meta)
		o.Adapter.Custody = &submit.Custody{KeyCustody: submit.KeyPresent}
		if sc.Properties.KeyVaultSecretID != "" {
			// The gateway follows a Key Vault secret; renewal is the vault's.
			o.Adapter.RenewalMode = submit.RenewalUnknown
		} else {
			o.Adapter.RenewalMode = submit.RenewalManual
		}
		b := bindings[strings.ToLower(sc.ID)]
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
