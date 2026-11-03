//go:build zoo

// Package zoo probes the TLS zoo (test/zoo/compose.yml) through the same
// runner the collector uses, with a scope that lists every zoo endpoint
// explicitly, and checks each outcome and certificate. Run it with
// `task test:zoo` (needs Docker).
package zoo

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/runner"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// endpoint is one zoo target and what probing it must give.
type endpoint struct {
	port     int
	protocol string
	sni      string // a name in the zoo certificate, or "" for a self-signed server
	want     string // contract outcome
	zooCA    bool   // the chain must verify against the zoo CA for sni
}

var endpoints = []endpoint{
	{15432, scope.ProtocolPostgres, "db.zoo.example.test", submit.OutcomeCertSeen, true},
	{15433, scope.ProtocolPostgres, "", submit.OutcomeReached, false}, // TLS off: SSLRequest answered 'N'
	{13306, scope.ProtocolMySQL, "", submit.OutcomeCertSeen, false},
	{10389, scope.ProtocolLDAPStartTLS, "", submit.OutcomeCertSeen, false},
	{10636, scope.ProtocolTLS, "", submit.OutcomeCertSeen, false},
	{10025, scope.ProtocolSMTPStartTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10587, scope.ProtocolSMTPStartTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10465, scope.ProtocolTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10143, scope.ProtocolIMAPStartTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10993, scope.ProtocolTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10110, scope.ProtocolPOP3StartTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{10995, scope.ProtocolTLS, "mail.zoo.example.test", submit.OutcomeCertSeen, true},
	{13389, scope.ProtocolRDP, "", submit.OutcomeCertSeen, false},
	{10999, scope.ProtocolTLS, "", submit.OutcomeRefused, false}, // nothing listens here
}

// waitReady waits until every zoo port that should answer accepts TCP. This
// is the test harness checking the containers are up, not part of a scan.
func waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for _, e := range endpoints {
		if e.want == submit.OutcomeRefused {
			continue
		}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.port))
		for {
			c, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("zoo port %d not ready: %v", e.port, err)
			}
			time.Sleep(2 * time.Second)
		}
	}
	time.Sleep(10 * time.Second) // let the mail server finish starting Postfix and Dovecot
}

func TestZoo(t *testing.T) {
	if os.Getenv("MEISCOPE_ZOO") != "1" {
		t.Skip("set MEISCOPE_ZOO=1 and start the zoo (task test:zoo)")
	}
	waitReady(t)
	caPEM, err := os.ReadFile(filepath.Join("certs", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("zoo CA not readable")
	}

	// One explicit target per zoo port. The zoo certificate covers every zoo
	// name, so chains from zoo-CA servers are verified for the name below.
	sc := &scope.Scope{
		ID: "zoo", TenantID: "zoo", Version: 1,
		Policy: scope.ScanPolicy{RatePer24: 10, Burst: 10, ConnectTimeoutSeconds: 10, CanaryPercent: 100},
	}
	byPort := map[int]endpoint{}
	for _, e := range endpoints {
		sc.Targets = append(sc.Targets, scope.Target{Host: "127.0.0.1", Port: e.port, Protocol: e.protocol})
		byPort[e.port] = e
	}

	var obs []submit.Observation
	rep, err := runner.New(runner.Options{}).Run(context.Background(), sc, func(o submit.Observation) { obs = append(obs, o) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("report: %+v", rep)
	if len(obs) != len(endpoints) {
		t.Fatalf("%d observations for %d endpoints", len(obs), len(endpoints))
	}
	for _, o := range obs {
		e := byPort[o.Target.Port]
		if o.Outcome != e.want {
			t.Errorf("port %d (%s): outcome %s, want %s", e.port, e.protocol, o.Outcome, e.want)
			continue
		}
		t.Logf("port %d %-14s %-10s %s %s", e.port, e.protocol, o.Outcome, o.TLS.Protocol, o.TLS.Version)
		if e.want != submit.OutcomeCertSeen {
			continue
		}
		leaf, err := x509.ParseCertificate(o.ServedChain[0])
		if err != nil {
			t.Errorf("port %d: leaf: %v", e.port, err)
			continue
		}
		if e.zooCA {
			inter := x509.NewCertPool()
			for _, der := range o.ServedChain[1:] {
				if c, err := x509.ParseCertificate(der); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: e.sni}); err != nil {
				t.Errorf("port %d: chain does not verify for %s: %v", e.port, e.sni, err)
			}
		}
	}

	// Every observation is valid under the vendored contract.
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Submit(context.Background(), obs); err != nil {
		t.Fatal(err)
	}
	if len(core.Errors()) != 0 || len(core.Rejected()) != 0 {
		t.Fatalf("core refused zoo observations: %v %v", core.Errors(), core.Rejected())
	}
}
