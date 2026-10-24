package egress_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/egress"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

const squidImage = "ubuntu/squid:6.10-24.10_beta"

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput() //nolint:gosec // test-only docker calls with fixed arguments
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestSquidProxy submits to the fake core through a real Squid that
// requires proxy authentication (WP1.1 acceptance). It needs Docker, so it
// runs only with MEISCOPE_DOCKER_TESTS=1.
func TestSquidProxy(t *testing.T) {
	if os.Getenv("MEISCOPE_DOCKER_TESTS") != "1" {
		t.Skip("set MEISCOPE_DOCKER_TESTS=1 to run the Squid proxy test (needs Docker)")
	}
	// The fake core, served on all interfaces with a certificate for
	// host.docker.internal, which is how the Squid container reaches the host.
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host.docker.internal"},
		DNSNames:  []string{"host.docker.internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := net.Listen("tcp", "0.0.0.0:0") //nolint:gosec // the Squid container reaches the test core through the host
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           core.Config.Handler,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer func() { _ = srv.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	coreURL := "https://host.docker.internal:" + strconv.Itoa(port)

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	// Squid's basic_ncsa_auth reads an apr1 htpasswd entry; the image has openssl.
	hash := docker(t, "run", "--rm", "--entrypoint", "openssl", squidImage, "passwd", "-apr1", proxyPass)
	_ = os.WriteFile(filepath.Join(dir, "passwd"), []byte(proxyUser+":"+hash+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "squid.conf"), []byte(`http_port 3128
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm meiscope-test
acl authed proxy_auth REQUIRED
http_access allow authed
http_access deny all
access_log stdio:/var/log/squid/access.log squid
pid_filename /var/run/squid.pid
`), 0o600)

	name := "meiscope-wp11-squid-" + strconv.Itoa(os.Getpid())
	docker(t, "create", "--name", name, "-p", "127.0.0.1::3128", squidImage)
	defer func() { _ = exec.Command("docker", "rm", "-f", name).Run() }() //nolint:gosec // test cleanup
	docker(t, "cp", filepath.Join(dir, "squid.conf"), name+":/etc/squid/squid.conf")
	docker(t, "cp", filepath.Join(dir, "passwd"), name+":/etc/squid/passwd")
	docker(t, "start", name)
	hostPort := docker(t, "port", name, "3128/tcp")
	hostPort = strings.TrimSpace(strings.Split(hostPort, "\n")[0])
	proxyURL := "http://" + strings.Replace(hostPort, "0.0.0.0", "127.0.0.1", 1)
	deadline := time.Now().Add(60 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyURL, "http://"), time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("squid did not start:\n%s", docker(t, "logs", name))
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	creds := credSource{"proxy_credential": proxyUser + ":" + proxyPass}
	send := func(c credSource) (submit.Result, error) {
		tr, err := egress.Transport(egress.Config{ProxyURL: proxyURL, CredentialRef: "proxy_credential", CABundle: ca}, c, egress.Options{}) //nolint:gosec // test-only reference name
		if err != nil {
			t.Fatal(err)
		}
		cl, _ := submit.New(coreURL, egress.Client(tr, 20*time.Second), submit.WithRetry(retry.Policy{Attempts: 0}))
		r, err := cl.Submit(context.Background(), []submit.Observation{obs()})
		tr.CloseIdleConnections() // Squid logs a tunnel when it closes
		return r, err
	}
	res, err := send(creds)
	if err != nil || res.Accepted != 1 {
		t.Fatalf("submission through Squid: %+v %v\nsquid log:\n%s", res, err, docker(t, "logs", name))
	}
	// Wrong credential: Squid answers 407 and nothing reaches the core.
	before := len(core.Batches())
	if _, err := send(credSource{"proxy_credential": proxyUser + ":wrong"}); err == nil {
		t.Fatal("submission succeeded with a wrong proxy credential")
	} else {
		assertNoSecret(t, err.Error())
	}
	if len(core.Batches()) != before {
		t.Fatal("a batch reached the core without proxy authentication")
	}
	time.Sleep(2 * time.Second)
	accessLog := docker(t, "exec", name, "cat", "/var/log/squid/access.log")
	t.Logf("squid access.log:\n%s", accessLog)
	if !strings.Contains(accessLog, "CONNECT host.docker.internal:"+strconv.Itoa(port)) || !strings.Contains(accessLog, "TCP_TUNNEL/200") || !strings.Contains(accessLog, "TCP_DENIED/407") {
		t.Fatal("Squid's log does not show the authenticated tunnel and the refused request")
	}
	if strings.Contains(accessLog, proxyPass) {
		t.Fatal("credential in Squid's log")
	}
}
