package osquery_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Docker helpers for the integration tests. They drive the docker CLI
// directly (the repository does not depend on testcontainers-go).
//
// Hygiene: every container, network and volume a test creates carries the
// label io.meiscope.test=<kind> and io.meiscope.test.run=<run id>. A test
// removes its own resources on every exit path (t.Cleanup and a deferred
// sweep, which also run when the test fails or panics), and at its start it
// sweeps leftovers of earlier interrupted runs that carry the kind label.

const testLabelKey = "io.meiscope.test"

func dockerRequired(t *testing.T) {
	t.Helper()
	if os.Getenv("MEISCOPE_DOCKER_TESTS") != "1" {
		t.Skip("set MEISCOPE_DOCKER_TESTS=1 to run the Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
}

// docker runs the docker CLI and returns its combined output.
func docker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput() //nolint:gosec // fixed arguments built by the tests
	return strings.TrimSpace(string(out)), err
}

func mustDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := docker(t, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// sweepLabel removes every container, network and volume carrying the label
// (key=value) and returns how many it removed. Best effort: it never fails.
func sweepLabel(label string) int {
	n := 0
	run := func(args ...string) []string {
		out, err := exec.Command("docker", args...).Output() //nolint:gosec // fixed arguments
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
	for _, id := range run("ps", "-aq", "--filter", "label="+label) {
		_ = exec.Command("docker", "rm", "-f", "-v", id).Run() //nolint:gosec // ids from docker ps
		n++
	}
	for _, id := range run("network", "ls", "-q", "--filter", "label="+label) {
		_ = exec.Command("docker", "network", "rm", id).Run() //nolint:gosec // ids from docker network ls
		n++
	}
	for _, id := range run("volume", "ls", "-q", "--filter", "label="+label) {
		_ = exec.Command("docker", "volume", "rm", "-f", id).Run() //nolint:gosec // ids from docker volume ls
		n++
	}
	return n
}

// testRun starts the hygiene for one integration test: it sweeps leftovers
// of the kind, and registers the removal of this run's resources.
type testRun struct {
	kind string
	id   string
}

func startRun(t *testing.T, kind string) *testRun {
	t.Helper()
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	r := &testRun{kind: kind, id: hex.EncodeToString(b)}
	if n := sweepLabel(testLabelKey + "=" + kind); n > 0 {
		t.Logf("removed %d leftover resources of earlier %s runs", n, kind)
	}
	t.Cleanup(func() { sweepLabel(r.runLabel()) })
	return r
}

// finish is deferred by the test: it removes this run's resources even when
// the test body panics (t.Cleanup also covers that; this is the second net).
func (r *testRun) finish() { sweepLabel(r.runLabel()) }

func (r *testRun) runLabel() string { return testLabelKey + ".run=" + r.id }

// labels are the docker arguments that label a resource of this run.
func (r *testRun) labels() []string {
	return []string{"--label", testLabelKey + "=" + r.kind, "--label", r.runLabel()}
}

func (r *testRun) name(part string) string { return "meiscope-" + r.kind + "-" + r.id + "-" + part }

// waitFor polls f until it returns true or the timeout passes.
func waitFor(t *testing.T, what string, timeout, every time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if f() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(every)
	}
}

// selfSignedCert writes a P-256 certificate for the names to dir and returns
// the certificate PEM path, the key PEM path and the parsed certificate.
func selfSignedCert(t *testing.T, dir string, dns []string, ips []net.IP) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: dns[0], Organization: []string{"Meiscope integration test"}},
		DNSNames: dns, IPAddresses: ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(6 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil { //nolint:gosec // test certificate, public
		t.Fatal(err)
	}
	// Readable by the unprivileged user inside the container; the key is a throw-away test key.
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o644); err != nil { //nolint:gosec // throw-away test key
		t.Fatal(err)
	}
	return certPath, keyPath, cert
}
