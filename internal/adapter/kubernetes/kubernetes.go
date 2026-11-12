// Package kubernetes is the Kubernetes adapter (FR-DISC-027). It reads,
// through the Kubernetes API and with read-only permissions, the TLS
// sections of Ingresses and Gateways, cert-manager Certificate resources
// and, where permitted, TLS Secret metadata (names and cert-manager
// annotations only, requested as PartialObjectMetadataList, never data).
// Each Secret found that way becomes a store observation
// "kubernetes/<cluster>/<namespace>/<secret>" with method adapter and
// source kubernetes, reported without its certificate (finding
// secret_not_read). Only with read_tls_crt=true and a namespaces
// allow-list does it get each named Secret in those namespaces and parse
// tls.crt; it then only tests whether tls.key is non-empty, never decodes or
// keeps it, and zeroes the raw response once decoded. It never writes and
// never connects to anything but the configured API server.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
)

// Name is the adapter's registry name, and Source its evidence source.
const (
	Name   = "kubernetes"
	Source = "kubernetes"
)

func init() {
	adapter.Register(Name, func(env adapter.Env) adapter.Adapter { return &Adapter{env: env} })
}

// Adapter is the Kubernetes adapter.
type Adapter struct {
	env adapter.Env
}

var (
	clusterPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	dnsLabel       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Describe describes the adapter.
func (a *Adapter) Describe() adapter.Description {
	return adapter.Description{
		Name:    Name,
		Source:  Source,
		Summary: "Kubernetes Ingress/Gateway TLS references, cert-manager Certificates and TLS Secret metadata (read-only API; Secret data only with read_tls_crt)",
		Settings: []string{
			"cluster (required: a short name for the cluster, used in the store locator)",
			"api_server (https URL of the API server; default https://kubernetes.default.svc with in_cluster)",
			"one of: ca_file (PEM of the cluster CA), kubeconfig (+ kube_context; only the cluster's server and CA are read), in_cluster=true, system_roots=true",
			"namespaces (comma-separated; default all namespaces; required with read_tls_crt)",
			"read_tls_crt (default false: Secret data is never read; true gets each named Secret in the listed namespaces and parses tls.crt only)",
			"page_size (default 500, 1..5000), rate_per_second (default 5)",
			"cert_manager (default true), ingress (default true), gateway_api (default false)",
		},
		Credentials: []string{"bearer_token (required unless in_cluster=true with the in-cluster API server, which reads the pod's service-account token)"},
	}
}

// Validate checks a configuration without contacting anything.
func (a *Adapter) Validate(cfg adapter.Config) error {
	if !clusterPattern.MatchString(cfg.Setting("cluster", "")) {
		return fmt.Errorf("kubernetes: cluster must match %s", clusterPattern)
	}
	inCluster, err := boolSetting(cfg, "in_cluster", false)
	if err != nil {
		return err
	}
	sysRoots, err := boolSetting(cfg, "system_roots", false)
	if err != nil {
		return err
	}
	anchors := 0
	for _, s := range []string{"ca_file", "kubeconfig"} {
		if cfg.Setting(s, "") != "" {
			anchors++
		}
	}
	if inCluster {
		anchors++
	}
	if sysRoots {
		anchors++
	}
	if anchors != 1 {
		return errors.New("kubernetes: set exactly one of ca_file, kubeconfig, in_cluster=true or system_roots=true (the API server's certificate is always verified)")
	}
	if cfg.Setting("kube_context", "") != "" && cfg.Setting("kubeconfig", "") == "" {
		return errors.New("kubernetes: kube_context needs kubeconfig")
	}
	if s := cfg.Setting("api_server", ""); s != "" {
		if _, err := apiServerURL(s); err != nil {
			return err
		}
	} else if !inCluster && cfg.Setting("kubeconfig", "") == "" {
		return errors.New("kubernetes: api_server is required (or kubeconfig, or in_cluster=true)")
	}
	if _, ok := cfg.Credentials["bearer_token"]; !ok {
		server := cfg.Setting("api_server", "")
		if server == "" {
			server = DefaultInClusterServer
		}
		u, _ := apiServerURL(server)
		if !inCluster || !inClusterServer(u) {
			return errors.New("kubernetes: " + errNoToken.Error())
		}
	}
	namespaces := splitList(cfg.Setting("namespaces", ""))
	for _, ns := range namespaces {
		if !dnsLabel.MatchString(ns) {
			return fmt.Errorf("kubernetes: namespace %q is not a valid name", ns)
		}
	}
	readData, err := boolSetting(cfg, "read_tls_crt", false)
	if err != nil {
		return err
	}
	if readData && len(namespaces) == 0 {
		return errors.New("kubernetes: read_tls_crt=true needs a namespaces allow-list (Secret data is never read cluster-wide)")
	}
	if err := intRange(cfg, "page_size", 1, 5000); err != nil {
		return err
	}
	if v := cfg.Setting("rate_per_second", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err != nil || f <= 0 {
			return errors.New("kubernetes: rate_per_second must be a positive number")
		}
	}
	for _, s := range []string{"cert_manager", "ingress", "gateway_api"} {
		if _, err := boolSetting(cfg, s, false); err != nil {
			return err
		}
	}
	return nil
}

// apiServerURL parses an API server URL: https, a host, no user
// information, no query.
func apiServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("kubernetes: api_server must be an absolute https URL without user information or query")
	}
	return u, nil
}

func boolSetting(cfg adapter.Config, name string, def bool) (bool, error) {
	v := cfg.Setting(name, "")
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("kubernetes: %s must be true or false", name)
	}
	return b, nil
}

func intRange(cfg adapter.Config, name string, lo, hi int) error {
	v := cfg.Setting(name, "")
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return fmt.Errorf("kubernetes: %s must be an integer in [%d, %d]", name, lo, hi)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Sync reads the cluster and returns the TLS Secrets whose observation
// changed since the cursor.
func (a *Adapter) Sync(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	return a.sync(ctx, cfg, since)
}
