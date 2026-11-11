package submit_test

import (
	"bytes"
	"compress/gzip"
	"context"
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
	// DER of a certificate is a SEQUENCE (0x30); the content is opaque here.
	der := append([]byte{0x30}, []byte("certificate "+strconv.Itoa(i))...)
	idx := int64(i)
	ts := t0
	return submit.Observation{
		Target:      submit.Target{Kind: submit.KindCTLog, Host: "ct.example", Port: 443},
		Method:      submit.MethodCT,
		ObservedAt:  t0,
		Outcome:     submit.OutcomeCertSeen,
		ServedChain: [][]byte{der},
		CTEntry:     &submit.CTEntry{Source: submit.CTSourceLog, LogID: make([]byte, 32), EntryIndex: &idx, Timestamp: &ts},
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
	// A probe observation in the same batch validates too.
	obs[7] = submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.1", Port: 443, SNI: "a.owned.example"},
		Method: submit.MethodProbe, ObservedAt: t0, Outcome: submit.OutcomeTimeout,
	}
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Batches != 3 || res.Accepted != 2345 || len(res.Rejected) != 0 {
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
	bad.CTEntry.Source = "rfc6962" // not a CTEntry.source of the contract
	_, err := cl.Submit(context.Background(), []submit.Observation{bad})
	if !submit.IsPermanent(err) || len(clk.Sleeps()) != 0 {
		t.Fatalf("want a permanent error without retries, got %v", err)
	}
	if errs := core.Errors(); len(errs) != 1 || !strings.Contains(errs[0], "source") {
		t.Fatalf("core errors %v", errs)
	}
}

// postRaw sends body gzip-compressed to the fake core's observations
// endpoint and returns the status.
func postRaw(t *testing.T, core *submittest.Core, body string) int {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(body))
	_ = zw.Close()
	req, err := http.NewRequest(http.MethodPost, core.URL+submit.ObservationsPath, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := core.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestFakeCoreRejectsUnknownFields proves the fake core is strict, as the
// core is (it decodes with DisallowUnknownFields): a field the vendored
// contract does not define, anywhere in a batch, fails the request. Among
// them are the fields of the earlier proposed CT shape.
func TestFakeCoreRejectsUnknownFields(t *testing.T) {
	core := newCore(t)
	valid := `{"observations":[{"target":{"kind":"ct_log","host":"ct.example","port":443},"method":"ct","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","served_chain":["MAA="],"ct_entry":{"source":"log","entry_index":7,"timestamp":"2026-10-23T00:00:00Z"}}]}`
	if st := postRaw(t, core, valid); st != http.StatusAccepted {
		t.Fatalf("valid batch: HTTP %d, errors %v", st, core.Errors())
	}
	for name, doc := range map[string]string{
		"observation":        strings.Replace(valid, `"method"`, `"ct":{"source":"log"},"method"`, 1),
		"target":             strings.Replace(valid, `"port":443`, `"port":443,"fingerprint":"ab"`, 1),
		"ct_entry":           strings.Replace(valid, `"entry_index":7`, `"entry_index":7,"leaf_input":"AAA="`, 1),
		"ct_entry log_url":   strings.Replace(valid, `"entry_index":7`, `"entry_index":7,"log_url":"https://ct.example/"`, 1),
		"ct_entry dns_names": strings.Replace(valid, `"entry_index":7`, `"entry_index":7,"dns_names":["a.owned.example"]`, 1),
		"batch":              strings.Replace(valid, `{"observations"`, `{"tenant":"t","observations"`, 1),
	} {
		before := len(core.Errors())
		if st := postRaw(t, core, doc); st != http.StatusBadRequest {
			t.Errorf("unknown field in %s: HTTP %d, want 400", name, st)
			continue
		}
		if errs := core.Errors(); len(errs) != before+1 || !strings.Contains(errs[before], "not allowed") {
			t.Errorf("unknown field in %s: errors %v", name, errs)
		}
	}
	if n := len(core.Batches()); n != 1 {
		t.Fatalf("%d batches stored, want only the valid one", n)
	}
}

// TestFakeCoreAppliesContractRules: the rules collector.yaml states in
// prose are answered as rejections, with the core's codes.
func TestFakeCoreAppliesContractRules(t *testing.T) {
	core := newCore(t)
	cl, _ := submit.New(core.URL, core.Client())
	probeCTLog := ctObservation(1)
	probeCTLog.Method, probeCTLog.CTEntry = submit.MethodProbe, nil
	withSNI := ctObservation(2)
	withSNI.Target.SNI = "a.owned.example"
	probeWithEntry := submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.1", Port: 443},
		Method: submit.MethodProbe, ObservedAt: t0, Outcome: submit.OutcomeTimeout,
		CTEntry: &submit.CTEntry{Source: submit.CTSourceLog},
	}
	shortLogID := ctObservation(3)
	shortLogID.CTEntry.LogID = []byte{1, 2, 3}
	// Since contract 0.9.0 the port rule is prose, not schema: the core
	// answers it as a rejection.
	noPort := submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.2"},
		Method: submit.MethodProbe, ObservedAt: t0, Outcome: submit.OutcomeTimeout,
	}
	ctNoPort := ctObservation(4)
	ctNoPort.Target.Port = 0
	res, err := cl.Submit(context.Background(), []submit.Observation{ctObservation(0), probeCTLog, withSNI, probeWithEntry, shortLogID, noPort, ctNoPort})
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, r := range res.Rejected {
		codes = append(codes, strconv.Itoa(r.Index)+":"+r.Code)
	}
	want := []string{"1:invalid_target", "2:invalid_target", "3:invalid_ct_entry", "4:invalid_ct_entry", "5:invalid_target", "6:invalid_target"}
	if res.Accepted != 1 || !reflect.DeepEqual(codes, want) {
		t.Fatalf("accepted %d, rejected %v, want %v", res.Accepted, codes, want)
	}
}

func TestOwnedDomains(t *testing.T) {
	core := newCore(t)
	core.SetDomains("example.com", "owned.example")
	core.FailNext(http.StatusServiceUnavailable)
	clk := clock.NewFake(t0)
	cl, _ := submit.New(core.URL, core.Client(), submit.WithClock(clk))
	got, err := cl.OwnedDomains(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"example.com", "owned.example"}) {
		t.Fatalf("domains %v, %v", got, err)
	}
	if len(clk.Sleeps()) != 1 {
		t.Fatalf("sleeps %v, want one retry", clk.Sleeps())
	}
	core.FailNext(http.StatusUnauthorized)
	if _, err := cl.OwnedDomains(context.Background()); !submit.IsPermanent(err) {
		t.Fatalf("401: want a permanent error, got %v", err)
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
	ct := `{"observations":[{"target":{"kind":"ct_log","host":"ct.example","port":443},"method":"ct","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","served_chain":["MAA="],"ct_entry":{"source":"log","log_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","entry_index":0,"timestamp":"2026-10-23T00:00:00Z"}}]}`
	if err := spec.Validate("ObservationBatch", []byte(ct)); err != nil {
		t.Fatalf("valid ct batch refused: %v", err)
	}
	bad := map[string]string{
		"empty batch":        `{"observations":[]}`,
		"extra property":     strings.Replace(valid, `"outcome"`, `"private_key":"x","outcome"`, 1),
		"unknown method":     strings.Replace(valid, `"probe"`, `"guess"`, 1),
		"port too large":     strings.Replace(valid, `443`, `70000`, 1),
		"bad time":           strings.Replace(valid, `2026-10-24T00:00:00Z`, `yesterday`, 1),
		"not base64":         strings.Replace(valid, `"outcome":"timeout"`, `"outcome":"cert_seen","served_chain":["%%%"]`, 1),
		"ct bad source":      strings.Replace(ct, `"source":"log"`, `"source":"google"`, 1),
		"ct source missing":  strings.Replace(ct, `"source":"log",`, ``, 1),
		"ct negative index":  strings.Replace(ct, `"entry_index":0`, `"entry_index":-1`, 1),
		"ct index not int":   strings.Replace(ct, `"entry_index":0`, `"entry_index":"0"`, 1),
		"ct log_id too long": strings.Replace(ct, `AAA=`, `AAAAAAAA`, 1),
		"ct bad timestamp":   strings.Replace(ct, `2026-10-23T00:00:00Z`, `1761177600000`, 1),
		"old kind ct_entry":  strings.Replace(ct, `"kind":"ct_log"`, `"kind":"ct_entry"`, 1),
		"old ct property":    strings.Replace(ct, `"ct_entry":`, `"ct":`, 1),
	}
	// The adapter objects are additive (additionalProperties true): a reader
	// ignores fields it does not know.
	store := `{"observations":[{"target":{"kind":"store","host":"h","store":"s"},"method":"adapter","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","adapter":{"source":"osquery","later":1,"certificate":{"sha1":"` + strings.Repeat("ab", 20) + `"}}}]}`
	if err := spec.Validate("ObservationBatch", []byte(store)); err != nil {
		t.Fatalf("additive adapter object with an unknown field refused: %v", err)
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
