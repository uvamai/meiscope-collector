package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/credential"
)

// ServiceAccountDir is where a pod's service-account token and cluster CA
// are mounted (in_cluster=true). A variable so tests can point elsewhere.
var ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// DefaultInClusterServer is the API server of in_cluster=true.
const DefaultInClusterServer = "https://kubernetes.default.svc"

const maxSmallFile = 1 << 20

// conn is where and how to reach the API server.
type conn struct {
	server *url.URL
	// pool pins the API server's CA; nil means the system roots.
	pool *x509.CertPool
}

// resolveConn works out the API server and its trust anchor.
func resolveConn(cfg adapter.Config) (conn, error) {
	var c conn
	server := cfg.Setting("api_server", "")
	switch {
	case cfg.Setting("ca_file", "") != "":
		pool, err := poolFromFile(cfg.Setting("ca_file", ""))
		if err != nil {
			return c, err
		}
		c.pool = pool
	case cfg.Setting("kubeconfig", "") != "":
		ks, pool, err := fromKubeconfig(cfg.Setting("kubeconfig", ""), cfg.Setting("kube_context", ""))
		if err != nil {
			return c, err
		}
		c.pool = pool
		if server == "" {
			server = ks
		}
	case isTrue(cfg, "in_cluster"):
		pool, err := poolFromFile(filepath.Join(ServiceAccountDir, "ca.crt"))
		if err != nil {
			return c, err
		}
		c.pool = pool
		if server == "" {
			server = DefaultInClusterServer
		}
	}
	u, err := apiServerURL(server)
	if err != nil {
		return c, err
	}
	c.server = u
	return c, nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // path from the operator's configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSmallFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSmallFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxSmallFile)
	}
	return b, nil
}

func poolFromPEM(b []byte, what string) (*x509.CertPool, error) {
	certs, err := adapter.ParsePEMCertificates(b)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s: %w", what, err)
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

func poolFromFile(path string) (*x509.CertPool, error) {
	b, err := readSmall(path)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: cluster CA: %w", err)
	}
	return poolFromPEM(b, "cluster CA "+path)
}

// kubeconfig is the part of a kubeconfig file the adapter reads: clusters
// and contexts. users (credentials) are never decoded.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// fromKubeconfig returns the server and CA of the context's cluster.
func fromKubeconfig(path, context string) (string, *x509.CertPool, error) {
	b, err := readSmall(path)
	if err != nil {
		return "", nil, fmt.Errorf("kubernetes: kubeconfig: %w", err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(b, &kc); err != nil {
		return "", nil, errors.New("kubernetes: kubeconfig does not parse as YAML")
	}
	if context == "" {
		context = kc.CurrentContext
	}
	cluster := ""
	for _, c := range kc.Contexts {
		if c.Name == context {
			cluster = c.Context.Cluster
		}
	}
	if cluster == "" {
		return "", nil, fmt.Errorf("kubernetes: kubeconfig has no context %q", context)
	}
	for _, c := range kc.Clusters {
		if c.Name != cluster {
			continue
		}
		if c.Cluster.InsecureSkipTLSVerify {
			return "", nil, fmt.Errorf("kubernetes: kubeconfig cluster %q sets insecure-skip-tls-verify; the adapter always verifies the API server", cluster)
		}
		var pem []byte
		switch {
		case c.Cluster.CertificateAuthorityData != "":
			pem, err = base64.StdEncoding.DecodeString(strings.TrimSpace(c.Cluster.CertificateAuthorityData))
			if err != nil {
				return "", nil, errors.New("kubernetes: kubeconfig certificate-authority-data is not base64")
			}
		case c.Cluster.CertificateAuthority != "":
			p := c.Cluster.CertificateAuthority
			if !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(path), p)
			}
			if pem, err = readSmall(p); err != nil {
				return "", nil, fmt.Errorf("kubernetes: kubeconfig certificate-authority: %w", err)
			}
		default:
			return "", nil, fmt.Errorf("kubernetes: kubeconfig cluster %q names no CA; set ca_file or system_roots=true", cluster)
		}
		pool, err := poolFromPEM(pem, "kubeconfig CA")
		if err != nil {
			return "", nil, err
		}
		return c.Cluster.Server, pool, nil
	}
	return "", nil, fmt.Errorf("kubernetes: kubeconfig has no cluster %q", cluster)
}

// serviceAccountSource is the credential.Source of in_cluster=true: it reads
// the pod's projected service-account token just in time on every sync, as
// the kubelet rotates it. The token is never copied anywhere else.
type serviceAccountSource struct{}

func (serviceAccountSource) Get(_ context.Context, _ string) (credential.Secret, error) {
	b, err := readSmall(filepath.Join(ServiceAccountDir, "token"))
	if err != nil {
		return credential.Secret{}, fmt.Errorf("service-account token: %w", credential.ErrNotFound)
	}
	return credential.NewSecret(strings.TrimSpace(string(b))), nil
}

// token resolves the bearer token for this sync.
func (a *Adapter) token(ctx context.Context, cfg adapter.Config) (credential.Secret, error) {
	if _, ok := cfg.Credentials["bearer_token"]; ok {
		return cfg.Credential(ctx, a.env.Creds, "bearer_token")
	}
	return serviceAccountSource{}.Get(ctx, "")
}

// httpClient returns the client for the API server: the collector's
// proxy-aware client with the trust anchor pinned to the cluster CA.
func (a *Adapter) httpClient(c conn) *http.Client {
	base := a.env.HTTP
	if base == nil {
		base = &http.Client{Timeout: time.Minute}
	}
	var t *http.Transport
	switch rt := base.Transport.(type) {
	case nil:
		t = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		t = rt.Clone()
	default:
		// A test transport (recorded fixtures) makes no TLS connection.
		return base
	}
	// A fresh TLS configuration: no client certificate is ever presented to
	// the API server, and its certificate is always verified.
	t.TLSClientConfig = &tls.Config{RootCAs: c.pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: t, Timeout: base.Timeout, CheckRedirect: noRedirect}
}

// noRedirect refuses redirects so the bearer token never follows one to
// another host.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// isTrue reads a validated boolean setting.
func isTrue(cfg adapter.Config, name string) bool {
	b, _ := boolSetting(cfg, name, false)
	return b
}
