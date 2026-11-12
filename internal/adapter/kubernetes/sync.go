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

// Resources the adapter reads (all read-only, verbs get and list).
const (
	pathSecrets      = "/api/v1/secrets" //nolint:gosec // an API path, not a credential
	pathCertificates = "/apis/cert-manager.io/v1/certificates"
	pathIngresses    = "/apis/networking.k8s.io/v1/ingresses"
	pathGateways     = "/apis/gateway.networking.k8s.io/v1/gateways"

	// tlsSelector limits the Secret listing to TLS Secrets on the server.
	tlsSelector = "type=kubernetes.io/tls"
	tlsType     = "kubernetes.io/tls"

	// acceptMetadata asks the API server for object metadata only: a Secret
	// listing made with it carries no data (no tls.crt, no tls.key).
	acceptMetadata = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	kindMetadata   = "PartialObjectMetadataList"

	// maxSecretBody bounds one Secret read with read_tls_crt=true. The
	// API server stores at most 1 MiB per Secret; JSON and base64 add a third.
	maxSecretBody = 2 << 20
	// maxListBody bounds one page of a metadata or resource listing.
	maxListBody = 64 << 20
)

// Run statistics keys (Result.Stats).
const (
	// StatSecrets counts the TLS Secrets whose metadata was listed.
	StatSecrets = "secrets_listed"
	// StatSecretsRead counts the Secrets whose tls.crt was read
	// (read_tls_crt=true).
	StatSecretsRead = "secrets_read"
	// StatSecretsNotRead counts the Secrets reported from metadata and
	// references only (the default).
	StatSecretsNotRead           = "secrets_not_read"
	StatSecretNotFound           = "secret_not_found"
	StatNotTLS                   = "skipped_not_tls"
	StatUnchanged                = "unchanged"
	StatRemoved                  = "removed"
	StatBadCertificate           = "skipped_bad_certificate"
	StatCertificateWithoutSecret = "certificate_without_secret"
	StatReferenceWithoutSecret   = "reference_without_secret"
	StatOutsideNamespaces        = "reference_outside_namespaces"
	StatContinueExpired          = "continue_expired"
	StatSkippedFeatureDisabled   = "skipped_feature_disabled"
	// rbac_missing_<resource> and api_absent_<resource> count optional
	// resources the adapter could not read (403, 404).
	statRBACMissing = "rbac_missing_"
	statAPIAbsent   = "api_absent_"
)

// ErrRBAC means the API server refused to return a Secret the operator
// asked the adapter to read (read_tls_crt=true): the service account
// lacks get on secrets in that namespace (docs/adapters-kubernetes.md).
// Without read_tls_crt the adapter needs no Secret permission at all.
var ErrRBAC = errors.New("the API server refused to return a Secret with read_tls_crt=true; grant get on secrets in the listed namespaces (docs/adapters-kubernetes.md, opt-in RBAC)")

// cursor is the delta watermark: a fingerprint per Secret of what was last
// sent, and the resourceVersion of the last Secret metadata listing.
type cursor struct {
	Secrets         map[string]string `json:"secrets"`
	ResourceVersion string            `json:"resource_version,omitempty"`
}

// certManagerAnnotations are the only annotations the adapter decodes.
// Every other annotation, kubectl's last-applied-configuration included
// (which can hold a whole Secret, tls.key too), is skipped by the decoder
// and never copied.
type certManagerAnnotations struct {
	CertificateName string `json:"cert-manager.io/certificate-name"`
	IssuerName      string `json:"cert-manager.io/issuer-name"`
	IssuerKind      string `json:"cert-manager.io/issuer-kind"`
}

type objectMeta struct {
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	ResourceVersion string                 `json:"resourceVersion"`
	Annotations     certManagerAnnotations `json:"annotations"`
}

type listMeta struct {
	ResourceVersion string `json:"resourceVersion"`
	Continue        string `json:"continue"`
}

// partialMeta is one item of a PartialObjectMetadataList.
type partialMeta struct {
	Metadata objectMeta `json:"metadata"`
}

// presence records whether a JSON value holds anything, without keeping
// it: encoding/json hands UnmarshalJSON a slice of the input, which is not
// retained.
type presence bool

func (p *presence) UnmarshalJSON(b []byte) error {
	v := strings.TrimSpace(string(b))
	*p = presence(v != "" && v != "null" && v != `""`)
	return nil
}

// secretTLS is the part of one Secret the adapter decodes with
// read_tls_crt=true: tls.crt, and only whether tls.key is non-empty.
type secretTLS struct {
	Metadata objectMeta `json:"metadata"`
	Type     string     `json:"type"`
	Data     struct {
		Crt string   `json:"tls.crt"`
		Key presence `json:"tls.key"`
	} `json:"data"`
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
	Kind     string   `json:"kind"`
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
// restarts the listing once from the beginning. With accept set to
// acceptMetadata every page must be a PartialObjectMetadataList.
func listAll[T any](ctx context.Context, l *lister, path string, namespaces []string, selector, accept string) ([]T, string, error) {
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
			items, rv, err = listPages[T](ctx, l, p, selector, accept)
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

func listPages[T any](ctx context.Context, l *lister, path, selector, accept string) ([]T, string, error) {
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
		b, err := l.g.Get(ctx, u, accept)
		if err != nil {
			return adapter.Page[T]{}, err
		}
		var page list[T]
		err = json.Unmarshal(b, &page)
		clear(b)
		if err != nil {
			return adapter.Page[T]{}, fmt.Errorf("GET %s: decode: %w", path, err)
		}
		if accept == acceptMetadata && page.Kind != kindMetadata {
			// The server ignored the metadata-only request; the items are not
			// used, whatever they hold.
			return adapter.Page[T]{}, fmt.Errorf("GET %s: the API server answered %q, not %s; the adapter does not use full Secret listings", path, adapter.Clip(page.Kind, 64), kindMetadata)
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
// (the API group or CRD is not installed) counts api_absent_<name>. ok
// reports whether the listing was read.
func optional[T any](ctx context.Context, l *lister, a *Adapter, name, path string, namespaces []string, selector, accept string, quiet bool) ([]T, string, bool, error) {
	items, rv, err := listAll[T](ctx, l, path, namespaces, selector, accept)
	switch {
	case err == nil:
		return items, rv, true, nil
	case adapter.IsStatus(err, http.StatusForbidden, http.StatusUnauthorized):
		l.stats[statRBACMissing+name]++
		msg := "kubernetes: no permission to list " + name + "; it is left out of this run"
		if quiet {
			a.info(msg, "resource", name)
		} else {
			a.warn(msg, "resource", name)
		}
		return nil, "", false, nil
	case adapter.IsStatus(err, http.StatusNotFound):
		l.stats[statAPIAbsent+name]++
		a.info("kubernetes: the "+name+" API is not installed; it is left out of this run", "resource", name)
		return nil, "", false, nil
	default:
		return nil, "", false, err
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
	namespaces := splitList(cfg.Setting("namespaces", ""))
	readData := isTrue(cfg, "read_tls_crt")
	if readData && len(namespaces) == 0 {
		return adapter.Result{}, errors.New("kubernetes: read_tls_crt=true needs a namespaces allow-list")
	}
	// The token is read just in time and lives only for this sync (ADR-0009).
	tok, err := a.token(ctx, cfg, c)
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
	st := map[string]int{
		StatSecrets: 0, StatSecretsRead: 0, StatSecretsNotRead: 0, StatUnchanged: 0, StatRemoved: 0,
		StatBadCertificate: 0, StatSkippedFeatureDisabled: 0,
	}
	hc := a.httpClient(c)
	limiter := adapter.NewLimiter(a.env.Clock, rate)
	l := &lister{
		g:        &adapter.Getter{HTTP: hc, Env: a.env, Limiter: limiter, Bearer: tok, MaxBody: maxListBody},
		server:   c.server,
		pageSize: pageSize,
		stats:    st,
	}

	// Secret metadata only: names and the cert-manager annotations, never
	// data. Optional: the default RBAC grants no Secret permission at all.
	metas, rv, metaKnown, err := optional[partialMeta](ctx, l, a, "secrets", pathSecrets, namespaces, tlsSelector, acceptMetadata, true)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("kubernetes: list secret metadata: %w", err)
	}
	st[StatSecrets] = len(metas)

	var certs []certificate
	if isTrueDefault(cfg, "cert_manager", true) {
		if certs, _, _, err = optional[certificate](ctx, l, a, "certificates", pathCertificates, namespaces, "", "application/json", false); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list certificates: %w", err)
		}
	}
	var ings []ingress
	if isTrueDefault(cfg, "ingress", true) {
		if ings, _, _, err = optional[ingress](ctx, l, a, "ingresses", pathIngresses, namespaces, "", "application/json", false); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list ingresses: %w", err)
		}
	}
	var gws []gateway
	if isTrueDefault(cfg, "gateway_api", false) {
		if gws, _, _, err = optional[gateway](ctx, l, a, "gateways", pathGateways, namespaces, "", "application/json", false); err != nil {
			return adapter.Result{}, fmt.Errorf("kubernetes: list gateways: %w", err)
		}
	}

	m := &mapper{
		cluster:    cfg.Setting("cluster", ""),
		host:       c.server.Hostname(),
		at:         adapter.ObservedAt(a.env.Clock.Now()),
		namespaces: map[string]bool{},
		metas:      map[string]*objectMeta{},
		certs:      map[string]*certificate{},
		bindings:   map[string]*binding{},
		stats:      st,
	}
	for _, ns := range namespaces {
		m.namespaces[ns] = true
	}
	keys := m.index(metas, metaKnown, certs, ings, gws)

	var all []submit.Observation
	sg := &adapter.Getter{HTTP: hc, Env: a.env, Limiter: limiter, Bearer: tok, MaxBody: maxSecretBody}
	for _, k := range keys {
		ns, name, _ := strings.Cut(k, "/")
		if !readData {
			st[StatSecretsNotRead]++
			all = append(all, m.reference(ns, name))
			continue
		}
		o, ok, err := m.read(ctx, sg, c.server, ns, name)
		if err != nil {
			return adapter.Result{}, err
		}
		if ok {
			all = append(all, o)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Target.Store < all[j].Target.Store })

	if !a.env.Features.LocalStoreV1 {
		// The core accepts store observations only with the local-store
		// feature on; keep the old cursor so nothing is lost until then.
		st[StatSkippedFeatureDisabled] = len(all)
		a.warn("kubernetes observations were not sent because "+adapter.EnvLocalStoreV1+" is off; the cursor was not advanced", "skipped_feature_disabled", len(all))
		return adapter.Result{Cursor: since, Stats: st}, nil
	}

	next := cursor{Secrets: map[string]string{}, ResourceVersion: rv}
	var out []submit.Observation
	for _, o := range all {
		k := o.Adapter.Kubernetes.Namespace + "/" + o.Adapter.Kubernetes.Name
		if o.Adapter.Certificate == nil && !a.env.Features.AdapterEvidenceV2 {
			// A Secret reported without its certificate needs the 0.10.0
			// proposal; it is not recorded as sent, so it goes out once the
			// switch is on.
			st[StatSkippedFeatureDisabled]++
			if fp, ok := cur.Secrets[k]; ok {
				next.Secrets[k] = fp
			}
			continue
		}
		fp := adapter.Fingerprint(o)
		next.Secrets[k] = fp
		if cur.Secrets[k] == fp {
			st[StatUnchanged]++
			continue
		}
		out = append(out, o)
	}
	if n := st[StatSkippedFeatureDisabled]; n > 0 {
		a.warn("kubernetes Secrets reported without their certificate were not sent because "+adapter.EnvAdapterEvidenceV2+" is off", "skipped_feature_disabled", n)
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
	a.info("kubernetes sync", "instance", cfg.Name, "observations", len(out), "secrets", st[StatSecrets],
		"read", st[StatSecretsRead], "not_read", st[StatSecretsNotRead],
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
	// namespaces is the allow-list; empty means every namespace.
	namespaces map[string]bool
	// metas, certs and bindings are keyed by "<namespace>/<secret name>".
	metas    map[string]*objectMeta
	certs    map[string]*certificate
	bindings map[string]*binding
	stats    map[string]int
}

func (m *mapper) allowed(ns string) bool {
	return len(m.namespaces) == 0 || m.namespaces[ns]
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

// validName rejects names that would break the store locator.
func validName(ns, name string) bool {
	return ns != "" && name != "" && !strings.Contains(ns+name, "/") && len(ns) <= 253 && len(name) <= 253 &&
		ns != "." && ns != ".." && name != "." && name != ".."
}

// index gathers the Secrets to report: those listed by metadata, those
// named by cert-manager Certificates and those Ingresses and Gateways
// reference. When the metadata listing was read (metaKnown), a reference to
// a Secret it does not hold is counted, not reported. It returns the
// sorted "<namespace>/<name>" keys.
func (m *mapper) index(metas []partialMeta, metaKnown bool, certs []certificate, ings []ingress, gws []gateway) []string {
	set := map[string]bool{}
	for i := range metas {
		md := &metas[i].Metadata
		if !validName(md.Namespace, md.Name) {
			m.stats[StatBadCertificate]++
			continue
		}
		k := md.Namespace + "/" + md.Name
		m.metas[k] = md
		set[k] = true
	}
	// want admits a Secret a resource names, if it may be reported.
	want := func(ns, name, missingStat string) (string, bool) {
		k := ns + "/" + name
		switch {
		case !validName(ns, name):
			return "", false
		case !m.allowed(ns):
			m.stats[StatOutsideNamespaces]++
			return "", false
		case metaKnown && m.metas[k] == nil:
			m.stats[missingStat]++
			return "", false
		}
		set[k] = true
		return k, true
	}
	for i := range certs {
		c := &certs[i]
		if k, ok := want(c.Metadata.Namespace, c.Spec.SecretName, StatCertificateWithoutSecret); ok {
			m.certs[k] = c
		}
	}
	for _, ing := range ings {
		ref := submit.KubernetesRef{Kind: "Ingress", Namespace: ing.Metadata.Namespace, Name: ing.Metadata.Name}
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			if _, ok := want(ing.Metadata.Namespace, t.SecretName, StatReferenceWithoutSecret); !ok {
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
				if _, ok := want(ns, cr.Name, StatReferenceWithoutSecret); !ok {
					continue
				}
				m.bind(ns, cr.Name, li.Hostname, ref)
			}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// evidence builds the Kubernetes evidence shared by both kinds of
// observation: bindings, cert-manager state and the renewal mode.
func (m *mapper) evidence(ns, name string) *submit.AdapterEvidence {
	k8s := &submit.KubernetesEvidence{Cluster: m.cluster, Namespace: ns, Name: name}
	ev := &submit.AdapterEvidence{Source: Source, Kubernetes: k8s}
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
	var ann certManagerAnnotations
	if md := m.metas[key]; md != nil {
		ann = md.Annotations
	}
	if c := m.certs[key]; c != nil {
		k8s.CertManager = certManager(c)
	} else if ann.CertificateName != "" {
		k8s.CertManager = &submit.CertManagerCertificate{
			Name:       adapter.Clip(ann.CertificateName, 253),
			IssuerName: adapter.Clip(ann.IssuerName, 253),
			IssuerKind: adapter.Clip(ann.IssuerKind, 64),
		}
	}
	if k8s.CertManager != nil {
		// cert-manager owns the Secret and renews the certificate.
		ev.RenewalMode = submit.RenewalExternalAutomated
	}
	return ev
}

func (m *mapper) target(ns, name string) submit.Target {
	return submit.Target{Kind: submit.KindStore, Host: m.host, Store: adapter.Clip("kubernetes/"+m.cluster+"/"+ns+"/"+name, 512)}
}

// reference is the default observation of a Secret: known from metadata,
// cert-manager or a reference, its certificate not read (finding
// secret_not_read, outcome reached; proposed contract 0.10.0).
func (m *mapper) reference(ns, name string) submit.Observation {
	ev := m.evidence(ns, name)
	ev.Findings = []submit.Finding{{Code: submit.FindingSecretNotRead}}
	return submit.Observation{
		Target:     m.target(ns, name),
		Method:     submit.MethodAdapter,
		ObservedAt: m.at,
		Outcome:    submit.OutcomeReached,
		Adapter:    ev,
	}
}

// read fetches one named Secret (read_tls_crt=true) and parses only
// tls.crt. The raw response is zeroed as soon as it is decoded; tls.key is
// only tested for being non-empty and never copied.
func (m *mapper) read(ctx context.Context, g *adapter.Getter, server *url.URL, ns, name string) (submit.Observation, bool, error) {
	u := server.JoinPath("/api/v1/namespaces", ns, "secrets", name)
	b, err := g.Get(ctx, u, "application/json")
	switch {
	case adapter.IsStatus(err, http.StatusForbidden, http.StatusUnauthorized):
		return submit.Observation{}, false, fmt.Errorf("kubernetes: %w: %w", ErrRBAC, err)
	case adapter.IsStatus(err, http.StatusNotFound):
		m.stats[StatSecretNotFound]++
		return submit.Observation{}, false, nil
	case err != nil:
		return submit.Observation{}, false, fmt.Errorf("kubernetes: get secret: %w", err)
	}
	var s secretTLS
	err = json.Unmarshal(b, &s)
	clear(b)
	switch {
	case err != nil:
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false, nil
	case s.Type != tlsType:
		m.stats[StatNotTLS]++
		return submit.Observation{}, false, nil
	}
	m.stats[StatSecretsRead]++
	pemBytes, err := base64.StdEncoding.DecodeString(s.Data.Crt)
	if err != nil {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false, nil
	}
	chain, err := adapter.ParsePEMCertificates(pemBytes)
	clear(pemBytes)
	if err != nil {
		m.stats[StatBadCertificate]++
		return submit.Observation{}, false, nil
	}
	key := ns + "/" + name
	if m.metas[key] == nil {
		// No metadata listing: the Secret's own annotations stand in.
		md := s.Metadata
		m.metas[key] = &md
	}
	ev := m.evidence(ns, name)
	ev.Certificate = adapter.CertificateMetadata(chain[0])
	ev.Kubernetes.ChainLength = len(chain)
	custody := submit.KeyAbsent
	if s.Data.Key {
		custody = submit.KeyPresent
	}
	ev.Custody = &submit.Custody{KeyCustody: custody}
	return submit.Observation{
		Target:     m.target(ns, name),
		Method:     submit.MethodAdapter,
		ObservedAt: m.at,
		Outcome:    submit.OutcomeCertSeen,
		Adapter:    ev,
	}, true, nil
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
