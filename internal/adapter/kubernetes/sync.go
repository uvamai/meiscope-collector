package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Resources the adapter lists (all read-only, verbs get and list).
const (
	pathSecrets      = "/api/v1/secrets" //nolint:gosec // an API path, not a credential
	pathCertificates = "/apis/cert-manager.io/v1/certificates"
	pathIngresses    = "/apis/networking.k8s.io/v1/ingresses"
	pathGateways     = "/apis/gateway.networking.k8s.io/v1/gateways"

	// tlsSelector limits the Secret listing to TLS Secrets on the server.
	tlsSelector = "type=kubernetes.io/tls"
)

// Run statistics keys (Result.Stats).
const (
	StatSecrets                  = "secrets_listed"
	StatUnchanged                = "unchanged"
	StatRemoved                  = "removed"
	StatBadCertificate           = "skipped_bad_certificate"
	StatCertificateWithoutSecret = "certificate_without_secret"
	StatContinueExpired          = "continue_expired"
	StatSkippedFeatureDisabled   = "skipped_feature_disabled"
	// rbac_missing_<resource> and api_absent_<resource> count optional
	// resources the adapter could not read (403, 404).
	statRBACMissing = "rbac_missing_"
	statAPIAbsent   = "api_absent_"
)

// ErrRBAC means the API server refused to list TLS Secrets: the service
// account lacks the minimal role (docs/adapters-kubernetes.md).
var ErrRBAC = errors.New("the API server refused to list Secrets; grant get and list on secrets (docs/adapters-kubernetes.md, minimal RBAC)")

// cursor is the delta watermark: a fingerprint per Secret of what was last
// sent, and the resourceVersion of the last Secret listing.
type cursor struct {
	Secrets         map[string]string `json:"secrets"`
	ResourceVersion string            `json:"resource_version,omitempty"`
}

type objectMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion"`
	// Annotations are kept raw: only the cert-manager keys are decoded, so
	// kubectl's last-applied-configuration (which can hold the whole Secret,
	// tls.key included) is never turned into a string the adapter keeps.
	Annotations map[string]json.RawMessage `json:"annotations"`
}

type listMeta struct {
	ResourceVersion string `json:"resourceVersion"`
	Continue        string `json:"continue"`
}

type secret struct {
	Metadata objectMeta `json:"metadata"`
	Type     string     `json:"type"`
	// Data is kept raw: tls.crt is decoded, tls.key is only checked for
	// being non-empty and is never decoded.
	Data map[string]json.RawMessage `json:"data"`
}

type certificate struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		SecretName string   `json:"secretName"`
		DNSNames   []string `json:"dnsNames"`
		IssuerRef  struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Group string `json:"group"`
		} `json:"issuerRef"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		NotAfter    *time.Time `json:"notAfter"`
		RenewalTime *time.Time `json:"renewalTime"`
		Revision    *int64     `json:"revision"`
	} `json:"status"`
}

type ingress struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		TLS []struct {
			Hosts      []string `json:"hosts"`
			SecretName string   `json:"secretName"`
		} `json:"tls"`
	} `json:"spec"`
}

type gateway struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Listeners []struct {
			Hostname string `json:"hostname"`
			TLS      *struct {
				CertificateRefs []struct {
					Group     string `json:"group"`
					Kind      string `json:"kind"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"certificateRefs"`
			} `json:"tls"`
		} `json:"listeners"`
	} `json:"spec"`
}

type list[T any] struct {
	Metadata listMeta `json:"metadata"`
	Items    []T      `json:"items"`
}

type lister struct {
	g        *adapter.Getter
	server   *url.URL
	pageSize int
	stats    map[string]int
}

// listAll lists a resource cluster-wide or in each namespace, page by page
// (limit and continue). A continue token the server has expired (410 Gone)
// restarts the listing once from the beginning.
func listAll[T any](ctx context.Context, l *lister, path string, namespaces []string, selector string) ([]T, string, error) {
	paths := []string{path}
	if len(namespaces) > 0 {
		paths = paths[:0]
		for _, ns := range namespaces {
			paths = append(paths, namespaced(path, ns))
		}
	}
	var all []T
	rv := ""
	for _, p := range paths {
		var items []T
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			items, rv, err = listPages[T](ctx, l, p, selector)
			if err == nil || !adapter.IsStatus(err, http.StatusGone) {
				break
			}
			l.stats[StatContinueExpired]++
		}
		if err != nil {
			return nil, "", err
		}
		all = append(all, items...)
	}
	return all, rv, nil
}

// namespaced turns /api/v1/secrets into /api/v1/namespaces/<ns>/secrets.
func namespaced(path, ns string) string {
	i := strings.LastIndex(path, "/")
	return path[:i] + "/namespaces/" + ns + path[i:]
}

func listPages[T any](ctx context.Context, l *lister, path, selector string) ([]T, string, error) {
	rv := ""
	items, err := adapter.Paginate(ctx, 0, func(ctx context.Context, token string) (adapter.Page[T], error) {
		q := url.Values{"limit": {strconv.Itoa(l.pageSize)}}
		if selector != "" {
			q.Set("fieldSelector", selector)
		}
		if token != "" {
			q.Set("continue", token)
		}
		u := l.server.JoinPath(path)
		u.RawQuery = q.Encode()
		b, err := l.g.Get(ctx, u, "application/json")
		if err != nil {
			return adapter.Page[T]{}, err
		}
		var page list[T]
		if err := json.Unmarshal(b, &page); err != nil {
			return adapter.Page[T]{}, fmt.Errorf("GET %s: decode: %w", path, err)
		}
		if token == "" {
			rv = page.Metadata.ResourceVersion
		}
		return adapter.Page[T]{Items: page.Items, Next: page.Metadata.Continue}, nil
	})
	return items, rv, err
}

// optional lists a resource whose absence or missing permission only
// narrows what the adapter reports: 403 counts rbac_missing_<name>, 404
// (the API group or CRD is not installed) counts api_absent_<name>.
func optional[T any](ctx context.Context, l *lister, a *Adapter, name, path string, namespaces []string) ([]T, error) {
	items, _, err := listAll[T](ctx, l, path, namespaces, "")
	switch {
	case err == nil:
		return items, nil
	case adapter.IsStatus(err, http.StatusForbidden, http.StatusUnauthorized):
		l.stats[statRBACMissing+name]++
		a.warn("kubernetes: no permission to list "+name+"; it is left out of this run", "resource", name)
		return nil, nil
	case adapter.IsStatus(err, http.StatusNotFound):
		l.stats[statAPIAbsent+name]++
		a.info("kubernetes: the "+name+" API is not installed; it is left out of this run", "resource", name)
		return nil, nil
	default:
		return nil, err
	}
}

func (a *Adapter) warn(msg string, args ...any) {
	if a.env.Log != nil {
		a.env.Log.Warn(msg, args...)
	}
}

func (a *Adapter) info(msg string, args ...any) {
	if a.env.Log != nil {
		a.env.Log.Info(msg, args...)
	}
}

func (a *Adapter) sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := cursor{}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	c, err := resolveConn(cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	// The token is read just in time and lives only for this sync (ADR-0009).
	tok, err := a.token(ctx, cfg)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("kubernetes: %w", err)
	}
	rate := 5.0
	if v, err := strconv.ParseFloat(cfg.Setting("rate_per_second", ""), 64); err == nil && v > 0 {
		rate = v
	}
	pageSize := 500
	if n, err := strconv.Atoi(cfg.Setting("page_size", "")); err == nil {
		pageSize = n
	}
	st := map[string]int{StatSecrets: 0, StatUnchanged: 0, StatRemoved: 0, StatBadCertificate: 0, StatSkippedFeatureDisabled: 0}
	l := &lister{
		g:        &adapter.Getter{HTTP: a.httpClient(c), Env: a.env, Limiter: adapter.NewLimiter(a.env.Clock, rate), Bearer: tok, MaxBody: 256 << 20},
		server:   c.server,
		pageSize: pageSize,
		stats:    st,
	}
	namespaces := splitList(cfg.Setting("namespaces", ""))

	secrets, rv, err := listAll[secret](ctx, l, pathSecrets, namespaces, tlsSelector)
	if adapter.IsStatus(err, http.StatusForbidden, http.StatusUnauthorized) {
		return adapter.Result{}, fmt.Errorf("kubernetes: %w: %w", ErrRBAC, err)
	}
	if err != nil {
		return adapter.Result{}, fmt.Errorf("kubernetes: list secrets: %w", err)
	}
	st[StatSecrets] = len(secrets)

	var certs []certificate
	if isTrueDefault(cfg, "cert_manager", true) {
		if certs, err = optional[certificate](ctx, l, a, "certificates", pathCertificates, namespaces); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list certificates: %w", err)
		}
	}
	var ings []ingress
	if isTrueDefault(cfg, "ingress", true) {
		if ings, err = optional[ingress](ctx, l, a, "ingresses", pathIngresses, namespaces); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list ingresses: %w", err)
		}
	}
	var gws []gateway
	if isTrueDefault(cfg, "gateway_api", false) {
		if gws, err = optional[gateway](ctx, l, a, "gateways", pathGateways, namespaces); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list gateways: %w", err)
		}
	}

	m := &mapper{
		cluster:  cfg.Setting("cluster", ""),
		host:     c.server.Hostname(),
		at:       adapter.ObservedAt(a.env.Clock.Now()),
		certs:    map[string]*certificate{},
		bindings: map[string]*binding{},
		stats:    st,
	}
	m.index(secrets, certs, ings, gws)
	all := m.observations(secrets)

	next := cursor{Secrets: map[string]string{}, ResourceVersion: rv}
	var out []submit.Observation
	for _, o := range all {
		k := o.Adapter.Kubernetes.Namespace + "/" + o.Adapter.Kubernetes.Name
		fp := adapter.Fingerprint(o)
		next.Secrets[k] = fp
		if cur.Secrets[k] == fp {
			st[StatUnchanged]++
			continue
		}
		out = append(out, o)
	}
	for k := range cur.Secrets {
		if _, ok := next.Secrets[k]; !ok {
			st[StatRemoved]++
		}
	}
	nc, err := adapter.EncodeCursor(next)
	if err != nil {
		return adapter.Result{}, err
	}
	if !a.env.Features.LocalStoreV1 {
		// The core accepts store observations only with the local-store
		// feature on; keep the old cursor so nothing is lost until then.
		st[StatSkippedFeatureDisabled] = len(out)
		a.warn("kubernetes observations were not sent because "+adapter.EnvLocalStoreV1+" is off; the cursor was not advanced", "skipped_feature_disabled", len(out))
		out, nc = nil, since
	}
	a.info("kubernetes sync", "instance", cfg.Name, "observations", len(out), "secrets", st[StatSecrets],
		"unchanged", st[StatUnchanged], "removed", st[StatRemoved], "bad_certificate", st[StatBadCertificate])
	return adapter.Result{Observations: out, Cursor: nc, Stats: st}, nil
}

func isTrueDefault(cfg adapter.Config, name string, def bool) bool {
	b, err := boolSetting(cfg, name, def)
	if err != nil {
		return def
	}
	return b
}

// binding is what Ingresses and Gateways say about one Secret.
type binding struct {
	hosts map[string]bool
	refs  map[submit.KubernetesRef]bool
}

type mapper struct {
	cluster, host string
	at            time.Time
	// certs and bindings are keyed by "<namespace>/<secret name>".
	certs    map[string]*certificate
	bindings map[string]*binding
	stats    map[string]int
}

func (m *mapper) bind(ns, name, host string, ref submit.KubernetesRef) {
	k := ns + "/" + name
	b := m.bindings[k]
	if b == nil {
		b = &binding{hosts: map[string]bool{}, refs: map[submit.KubernetesRef]bool{}}
		m.bindings[k] = b
	}
	if h := strings.ToLower(strings.TrimSpace(host)); h != "" && len(h) <= 253 {
		b.hosts[h] = true
	}
	b.refs[ref] = true
}

func (m *mapper) index(secrets []secret, certs []certificate, ings []ingress, gws []gateway) {
	have := map[string]bool{}
	for _, s := range secrets {
		have[s.Metadata.Namespace+"/"+s.Metadata.Name] = true
	}
	for i := range certs {
		c := &certs[i]
		k := c.Metadata.Namespace + "/" + c.Spec.SecretName
		if !have[k] {
			m.stats[StatCertificateWithoutSecret]++
			continue
		}
		m.certs[k] = c
	}
	for _, ing := range ings {
		ref := submit.KubernetesRef{Kind: "Ingress", Namespace: ing.Metadata.Namespace, Name: ing.Metadata.Name}
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			if len(t.Hosts) == 0 {
				m.bind(ing.Metadata.Namespace, t.SecretName, "", ref)
			}
			for _, h := range t.Hosts {
				m.bind(ing.Metadata.Namespace, t.SecretName, h, ref)
			}
		}
	}
	for _, gw := range gws {
		ref := submit.KubernetesRef{Kind: "Gateway", Namespace: gw.Metadata.Namespace, Name: gw.Metadata.Name}
		for _, li := range gw.Spec.Listeners {
			if li.TLS == nil {
				continue
			}
			for _, cr := range li.TLS.CertificateRefs {
				if (cr.Kind != "" && cr.Kind != "Secret") || (cr.Group != "" && cr.Group != "core") {
					continue
				}
				ns := cr.Namespace
				if ns == "" {
					ns = gw.Metadata.Namespace
				}
				m.bind(ns, cr.Name, li.Hostname, ref)
			}
		}
	}
}

// observations maps each TLS Secret to a store observation, sorted by
// locator.
func (m *mapper) observations(secrets []secret) []submit.Observation {
	var out []submit.Observation
	for _, s := range secrets {
		if o, ok := m.observation(s); ok {
			out = append(out, o)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target.Store < out[j].Target.Store })
	return out
}

func (m *mapper) observation(s secret) (submit.Observation, bool) {
	ns, name := s.Metadata.Namespace, s.Metadata.Name
	if ns == "" || name == "" || strings.Contains(ns+name, "/") {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false
	}
	var crtB64 string
	if raw, ok := s.Data["tls.crt"]; !ok || json.Unmarshal(raw, &crtB64) != nil {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false
	}
	pemBytes, err := base64.StdEncoding.DecodeString(crtB64)
	if err != nil {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false
	}
	chain, err := adapter.ParsePEMCertificates(pemBytes)
	if err != nil {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false
	}
	k8s := &submit.KubernetesEvidence{Cluster: m.cluster, Namespace: ns, Name: name, ChainLength: len(chain)}
	ev := &submit.AdapterEvidence{
		Source:      Source,
		Certificate: adapter.CertificateMetadata(chain[0]),
		Custody:     &submit.Custody{KeyCustody: keyCustody(s.Data["tls.key"])},
		Kubernetes:  k8s,
	}
	key := ns + "/" + name
	if b := m.bindings[key]; b != nil {
		for h := range b.hosts {
			k8s.Hostnames = append(k8s.Hostnames, h)
		}
		sort.Strings(k8s.Hostnames)
		for r := range b.refs {
			k8s.References = append(k8s.References, r)
		}
		sort.Slice(k8s.References, func(i, j int) bool {
			x, y := k8s.References[i], k8s.References[j]
			return x.Kind+"/"+x.Namespace+"/"+x.Name < y.Kind+"/"+y.Namespace+"/"+y.Name
		})
	}
	if c := m.certs[key]; c != nil {
		k8s.CertManager = certManager(c)
	} else if n := annotation(s.Metadata.Annotations, "cert-manager.io/certificate-name"); n != "" {
		k8s.CertManager = &submit.CertManagerCertificate{
			Name:       adapter.Clip(n, 253),
			IssuerName: adapter.Clip(annotation(s.Metadata.Annotations, "cert-manager.io/issuer-name"), 253),
			IssuerKind: adapter.Clip(annotation(s.Metadata.Annotations, "cert-manager.io/issuer-kind"), 64),
		}
	}
	if k8s.CertManager != nil {
		// cert-manager owns the Secret and renews the certificate.
		ev.RenewalMode = submit.RenewalExternalAutomated
	}
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindStore, Host: m.host, Store: adapter.Clip("kubernetes/"+m.cluster+"/"+ns+"/"+name, 512)},
		Method:     submit.MethodAdapter,
		ObservedAt: m.at,
		Outcome:    submit.OutcomeCertSeen,
		Adapter:    ev,
	}, true
}

// keyCustody reports whether tls.key holds anything, from its JSON form
// only: the value is never decoded.
func keyCustody(raw json.RawMessage) string {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" || v == `""` {
		return submit.KeyAbsent
	}
	return submit.KeyPresent
}

func annotation(a map[string]json.RawMessage, key string) string {
	raw, ok := a[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func certManager(c *certificate) *submit.CertManagerCertificate {
	cm := &submit.CertManagerCertificate{
		Name:        adapter.Clip(c.Metadata.Name, 253),
		IssuerKind:  adapter.Clip(c.Spec.IssuerRef.Kind, 64),
		IssuerName:  adapter.Clip(c.Spec.IssuerRef.Name, 253),
		IssuerGroup: adapter.Clip(c.Spec.IssuerRef.Group, 253),
		Revision:    c.Status.Revision,
	}
	for i, n := range c.Spec.DNSNames {
		if i == 256 {
			break
		}
		cm.DNSNames = append(cm.DNSNames, adapter.Clip(n, 253))
	}
	for _, cond := range c.Status.Conditions {
		if cond.Type == "Ready" {
			r := cond.Status == "True"
			cm.Ready = &r
		}
	}
	if t := c.Status.NotAfter; t != nil {
		u := t.UTC()
		cm.NotAfter = &u
	}
	if t := c.Status.RenewalTime; t != nil {
		u := t.UTC()
		cm.RenewalTime = &u
	}
	if cm.Revision != nil && *cm.Revision < 0 {
		cm.Revision = nil
	}
	return cm
}
