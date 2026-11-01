package submit_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// The Contract tests below send every shape of observation the collector
// emits today to the fake core. submittest.NewCore validates against the
// vendored api/collector.yaml, or against the file named by
// MEISCOPE_CONTRACT, which is how "task contract:diff CORE=<path>" checks
// the collector's output against a core's own contract file (drift).
// The CT poller's and the adapters' output is covered by the tests named in
// scripts/contract-diff.sh.

func contractCore(t *testing.T) *submittest.Core {
	t.Helper()
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	t.Logf("validating against %s", submittest.SpecPath())
	return core
}

func TestContractCurrentObservationShapes(t *testing.T) {
	core := contractCore(t)
	cl, _ := submit.New(core.URL, core.Client())
	var obs []submit.Observation
	// A CT observation from each source.
	for i, src := range []string{submit.CTSourceLog, submit.CTSourceCertSpotter, submit.CTSourceCrtSh} {
		o := ctObservation(i)
		o.CTEntry.Source = src
		obs = append(obs, o)
	}
	// Probe-style observations of every outcome, with and without a chain, TLS parameters and SNI.
	ocsp := true
	for _, oc := range []string{submit.OutcomeReached, submit.OutcomeRefused, submit.OutcomeTimeout, submit.OutcomeTLSFailed} {
		obs = append(obs, submit.Observation{
			Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.5", Port: 443, SNI: "a.example.test"},
			Method: submit.MethodProbe, ObservedAt: t0, Outcome: oc,
		})
	}
	seen := submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "web01.example.test", Port: 8443}, Method: submit.MethodProbe,
		ObservedAt: t0, Outcome: submit.OutcomeCertSeen, ServedChain: [][]byte{append([]byte{0x30}, []byte("leaf")...), append([]byte{0x30}, []byte("issuer")...)},
		TLS: &submit.TLSParams{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2", OCSPStapled: &ocsp, Protocol: "https", Plugin: "tls"},
	}
	obs = append(obs, seen)
	imp := seen
	imp.Method = submit.MethodImport
	obs = append(obs, imp)
	res, err := cl.Submit(context.Background(), obs)
	if err != nil || res.Accepted != len(obs) || len(res.Rejected) != 0 {
		t.Fatalf("accepted %d of %d: %+v, %v; core errors %v", res.Accepted, len(obs), res.Rejected, err, core.Errors())
	}
}

func TestContractOwnedDomains(t *testing.T) {
	core := contractCore(t)
	core.SetDomains("example.test", "uvam.ai")
	cl, _ := submit.New(core.URL, core.Client())
	got, err := cl.OwnedDomains(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestContractBatchLimits(t *testing.T) {
	core := contractCore(t)
	cl, _ := submit.New(core.URL, core.Client(), submit.WithBatchSize(submit.MaxBatch))
	obs := make([]submit.Observation, submit.MaxBatch+1)
	for i := range obs {
		obs[i] = ctObservation(i)
	}
	res, err := cl.Submit(context.Background(), obs)
	if err != nil || res.Accepted != len(obs) || res.Batches != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

// TestContractVersionIsRecorded logs which contract the run used.
func TestContractVersionIsRecorded(t *testing.T) {
	p := submittest.SpecPath()
	b, err := os.ReadFile(p) //nolint:gosec // contract file chosen by the developer
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("contract %s (%s bytes)", p, strconv.Itoa(len(b)))
}
