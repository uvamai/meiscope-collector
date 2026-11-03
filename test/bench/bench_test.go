//go:build bench

// Package bench is the D1 throughput acceptance: 1,000 listed names × 3
// listed ports (3,000 explicit targets) must finish in under 10 minutes,
// while the scope's per-/24 rate is never exceeded. All names resolve to
// loopback, so the whole run sits in one /24 and the scope's maximum rate
// (10 connections per second) bounds it from below at about 300 s.
// Run it with `task test:bench`.
package bench

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/runner"
	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/testpki"
)

const (
	names = 1000
	ports = 3
	limit = 10 * time.Minute
)

// loopbackResolver resolves every bench name to 127.0.0.1.
type loopbackResolver struct{}

func (loopbackResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if !strings.HasSuffix(host, ".bench.example.test") {
		return nil, fmt.Errorf("unexpected lookup %q", host)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestThousandNamesThreePorts(t *testing.T) {
	now := time.Now()
	root := testpki.NewRoot(t, "Bench Root", now)
	leaf, key := root.Issue(t, testpki.LeafTemplate("bench.example.test", now.Add(-time.Hour), 24*time.Hour, "*.bench.example.test"))
	cfg := &tls.Config{Certificates: []tls.Certificate{testpki.TLSCertificate(leaf, key)}, MinVersion: tls.VersionTLS12}
	var conns atomic.Int64
	var sc scope.Scope
	for range ports {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				conns.Add(1)
				go func() { defer c.Close(); _ = tls.Server(c, cfg).Handshake() }()
			}
		}()
		for i := range names {
			sc.Targets = append(sc.Targets, scope.Target{Host: fmt.Sprintf("host-%04d.bench.example.test", i), Port: ln.Addr().(*net.TCPAddr).Port, Protocol: scope.ProtocolTLS})
		}
	}
	sc.ID, sc.TenantID, sc.Version = "bench", "bench", 1
	sc.Policy = scope.ScanPolicy{RatePer24: scope.MaxRatePer24, Burst: scope.MaxBurst, ConnectTimeoutSeconds: 5, CanaryPercent: 1}

	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	var ok, other atomic.Int64
	start := time.Now()
	rep, err := runner.New(runner.Options{Resolver: loopbackResolver{}, Roots: roots}).Run(context.Background(), &sc, func(o submit.Observation) {
		if o.Outcome == submit.OutcomeCertSeen {
			ok.Add(1)
		} else {
			other.Add(1)
		}
	})
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d targets: %d cert_seen, %d other, %d connections, in %v (limit %v); report %+v",
		len(sc.Targets), ok.Load(), other.Load(), conns.Load(), took.Round(time.Second), limit, rep)
	if ok.Load() != names*ports || conns.Load() != names*ports {
		t.Fatalf("want %d certificates over %d connections", names*ports, names*ports)
	}
	if took > limit {
		t.Fatalf("took %v, over the %v limit", took, limit)
	}
	// The pacer must have held the per-/24 rate: n starts need at least
	// (n - burst) / rate seconds.
	floor := time.Duration(float64(names*ports-scope.MaxBurst)/scope.MaxRatePer24) * time.Second
	if took < floor {
		t.Fatalf("took %v, faster than the per-/24 rate allows (%v)", took, floor)
	}
}
