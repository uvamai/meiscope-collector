package submit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

func ctObservation(i int) submit.Observation {
	der := []byte("certificate " + strconv.Itoa(i))
	sum := sha256.Sum256(der)
	idx := int64(i)
	ts := t0
	return submit.Observation{
		Target:      submit.Target{Kind: submit.KindCTEntry, Host: "uvam.ai", Fingerprint: hex.EncodeToString(sum[:])},
		Method:      submit.MethodCT,
		ObservedAt:  t0,
		Outcome:     submit.OutcomeCertSeen,
		ServedChain: [][]byte{der},
		CT: &submit.CTEvidence{
			Source: submit.SourceRFC6962, MatchedDomain: "uvam.ai", DNSNames: []string{"a.uvam.ai"},
			EntryType: submit.EntryX509, LogURL: "https://ct.example/log", EntryIndex: &idx, EntryTimestamp: &ts,
			LeafInput: []byte{0, 0, 1}, ExtraData: []byte{0, 0, 0},
			SCTs: []submit.SCT{{LogID: make([]byte, 32), Timestamp: t0}},
		},
	}
}

func newCore(t *testing.T) *submittest.Core {
	t.Helper()
	c, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestSubmitBatchesOfAtMost1000(t *testing.T) {
	core := newCore(t)
	cl, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	obs := make([]submit.Observation, 2345)
	for i := range obs {
		obs[i] = ctObservation(i)
	}
	// A probe observation in the same batch still validates (port required
	// for host_port_sni only).
	obs[7] = submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.1", Port: 443, SNI: "a.uvam.ai"},
		Method: submit.MethodProbe, ObservedAt: t0, Outcome: submit.OutcomeTimeout,
	}
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Batches != 3 || res.Accepted != 2345 {
		t.Fatalf("result %+v", res)
	}
	var sizes []int
	for _, b := range core.Batches() {
		sizes = append(sizes, strings.Count(string(b), `"method":`))
	}
	if !reflect.DeepEqual(sizes, []int{1000, 1000, 345}) {
		t.Fatalf("batch sizes %v", sizes)
	}
}

func TestSubmitRetriesWithBackoff(t *testing.T) {
	core := newCore(t)
	core.FailNext(http.StatusServiceUnavailable, http.StatusTooManyRequests)
	clk := clock.NewFake(t0)
	cl, _ := submit.New(core.URL, core.Client(), submit.WithClock(clk))
	res, err := cl.Submit(context.Background(), []submit.Observation{ctObservation(1)})
	if err != nil || res.Accepted != 1 {
		t.Fatalf("result %+v, %v", res, err)
	}
	if got := clk.Sleeps(); !reflect.DeepEqual(got, []time.Duration{time.Second, 2 * time.Second}) {
		t.Fatalf("sleeps %v", got)
	}
}

func TestSubmitInvalidIsPermanent(t *testing.T) {
	core := newCore(t)
	clk := clock.NewFake(t0)
	cl, _ := submit.New(core.URL, core.Client(), submit.WithClock(clk))
	bad := ctObservation(1)
	bad.Target.Fingerprint = "" // ct_entry requires a fingerprint
	_, err := cl.Submit(context.Background(), []submit.Observation{bad})
	if !submit.IsPermanent(err) || len(clk.Sleeps()) != 0 {
		t.Fatalf("want a permanent error without retries, got %v", err)
	}
	if errs := core.Errors(); len(errs) != 1 || !strings.Contains(errs[0], "fingerprint") {
		t.Fatalf("core errors %v", errs)
	}
}

func TestSpecValidator(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.SpecPath())
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"observations":[{"target":{"kind":"host_port_sni","host":"h","port":443},"method":"probe","observed_at":"2026-10-24T00:00:00Z","outcome":"timeout"}]}`
	if err := spec.Validate("ObservationBatch", []byte(valid)); err != nil {
		t.Fatalf("valid batch refused: %v", err)
	}
	bad := map[string]string{
		"empty batch":     `{"observations":[]}`,
		"extra property":  strings.Replace(valid, `"outcome"`, `"private_key":"x","outcome"`, 1),
		"unknown method":  strings.Replace(valid, `"probe"`, `"guess"`, 1),
		"port missing":    strings.Replace(valid, `,"port":443`, ``, 1),
		"port too large":  strings.Replace(valid, `443`, `70000`, 1),
		"bad time":        strings.Replace(valid, `2026-10-24T00:00:00Z`, `yesterday`, 1),
		"not base64":      strings.Replace(valid, `"outcome":"timeout"`, `"outcome":"cert_seen","served_chain":["%%%"]`, 1),
		"ct bad source":   strings.Replace(valid, `"outcome"`, `"ct":{"source":"google","matched_domain":"x"},"outcome"`, 1),
		"ct without fp":   `{"observations":[{"target":{"kind":"ct_entry","host":"uvam.ai"},"method":"ct","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","served_chain":["MAA="]}]}`,
		"fingerprint hex": `{"observations":[{"target":{"kind":"ct_entry","host":"uvam.ai","fingerprint":"XYZ"},"method":"ct","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","served_chain":["MAA="]}]}`,
	}
	for name, doc := range bad {
		if err := spec.Validate("ObservationBatch", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNewRejectsRelativeURL(t *testing.T) {
	if _, err := submit.New("/collector/v1", nil); err == nil {
		t.Fatal("relative URL accepted")
	}
}
