package kubernetes

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
)

func caB64(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fixture.Dir("kubernetes", "cluster-ca.b64"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func writeKubeconfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The users section is never read: a kubeconfig's credentials do not reach
// the adapter, which takes its token from the credential source.
const kubeconfigTemplate = `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://k8s.example.test:6443
    certificate-authority-data: CADATA
- name: lab-cluster
  cluster:
    server: https://lab.example.test:6443
    insecure-skip-tls-verify: true
contexts:
- name: prod
  context: {cluster: prod-cluster, user: reader}
- name: lab
  context: {cluster: lab-cluster, user: reader}
users:
- name: reader
  user: {}
`

func TestKubeconfig(t *testing.T) {
	p := writeKubeconfig(t, strings.Replace(kubeconfigTemplate, "CADATA", caB64(t), 1))
	server, pool, err := fromKubeconfig(p, "")
	if err != nil || server != "https://k8s.example.test:6443" || pool == nil {
		t.Fatalf("%q %v %v", server, pool, err)
	}
	if _, _, err := fromKubeconfig(p, "lab"); err == nil || !strings.Contains(err.Error(), "insecure-skip-tls-verify") {
		t.Fatalf("insecure cluster: %v", err)
	}
	if _, _, err := fromKubeconfig(p, "nope"); err == nil {
		t.Fatal("unknown context accepted")
	}
	cfg := adapter.Config{Name: "k", Adapter: Name, Settings: map[string]string{"cluster": "prod", "kubeconfig": p}}
	c, err := resolveConn(cfg)
	if err != nil || c.server.Host != "k8s.example.test:6443" || c.pool == nil {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestHTTPClientPinsCA(t *testing.T) {
	p := writeKubeconfig(t, strings.Replace(kubeconfigTemplate, "CADATA", caB64(t), 1))
	_, pool, err := fromKubeconfig(p, "prod")
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{env: adapter.Env{HTTP: &http.Client{Transport: &http.Transport{}}}}
	hc := a.httpClient(conn{pool: pool})
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs != pool || len(tr.TLSClientConfig.Certificates) != 0 ||
		tr.TLSClientConfig.InsecureSkipVerify || hc.CheckRedirect == nil {
		t.Fatalf("client %+v", hc)
	}
}
