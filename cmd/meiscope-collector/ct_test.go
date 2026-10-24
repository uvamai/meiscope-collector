package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

const fixtures = "../../internal/ct/testdata/"

// fakeCTServices serves the recorded Cert Spotter issuances (one page, then
// an empty page) and the recorded crt.sh search.
func fakeCTServices(t *testing.T) (certspotter, crtsh *httptest.Server) {
	t.Helper()
	cs, err := os.ReadFile(fixtures + "certspotter/issuances-uvam.ai.json")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := os.ReadFile(fixtures + "crtsh/search-uvam.ai.json")
	if err != nil {
		t.Fatal(err)
	}
	certspotter = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write(cs)
	}))
	crtsh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(crt) }))
	t.Cleanup(certspotter.Close)
	t.Cleanup(crtsh.Close)
	return certspotter, crtsh
}

func testDeps(core *http.Client) ctDeps {
	return ctDeps{
		core:  core,
		clk:   clock.NewFake(time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)),
		creds: func(func(string) string) credential.Source { return credential.None{} },
	}
}

func TestCTPollSubmitsAndSavesProgress(t *testing.T) {
	cs, _ := fakeCTServices(t)
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	state := filepath.Join(t.TempDir(), "ct-state.json")
	env := map[string]string{
		"MEISCOPE_CORE_URL":           core.URL,
		"MEISCOPE_CT_DOMAINS":         "uvam.ai",
		"MEISCOPE_CT_CERTSPOTTER_URL": cs.URL,
		"MEISCOPE_CT_CRTSH_FALLBACK":  "false",
		"MEISCOPE_CT_STATE_FILE":      state,
	}
	getenv := func(k string) string { return env[k] }
	for i := 0; i < 2; i++ {
		var out, errb bytes.Buffer
		if err := ctPollCmd(context.Background(), nil, &out, &errb, getenv, testDeps(core.Client())); err != nil {
			t.Fatalf("run %d: %v\n%s", i, err, errb.String())
		}
	}
	// The second run finds nothing new (state saved), so one batch only.
	if n := len(core.Batches()); n != 1 || len(core.Errors()) != 0 {
		t.Fatalf("%d batches, errors %v", n, core.Errors())
	}
	var batch submit.ObservationBatch
	if err := json.Unmarshal(core.Batches()[0], &batch); err != nil || len(batch.Observations) != 4 {
		t.Fatalf("batch of %d, %v", len(batch.Observations), err)
	}
	b, err := os.ReadFile(filepath.Clean(state))
	if err != nil || !strings.Contains(string(b), `"uvam.ai": "17495069787"`) {
		t.Fatalf("state %s, %v", b, err)
	}
}

func TestCTPollWithoutCoreWritesBatch(t *testing.T) {
	cs, _ := fakeCTServices(t)
	state := filepath.Join(t.TempDir(), "ct-state.json")
	env := map[string]string{
		"MEISCOPE_CT_DOMAINS":         "uvam.ai",
		"MEISCOPE_CT_CERTSPOTTER_URL": cs.URL,
		"MEISCOPE_CT_CRTSH_FALLBACK":  "false",
		"MEISCOPE_CT_STATE_FILE":      state,
	}
	var out, errb bytes.Buffer
	if err := ctPollCmd(context.Background(), nil, &out, &errb, func(k string) string { return env[k] }, testDeps(nil)); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	var batch submit.ObservationBatch
	if err := json.Unmarshal(out.Bytes(), &batch); err != nil || len(batch.Observations) != 4 {
		t.Fatalf("stdout batch of %d, %v", len(batch.Observations), err)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("progress must not be saved when nothing was submitted")
	}
	if !strings.Contains(errb.String(), "not submitted") {
		t.Fatalf("expected a warning, got %s", errb.String())
	}
}

func TestCTPollNeedsDomains(t *testing.T) {
	var out, errb bytes.Buffer
	err := ctPollCmd(context.Background(), nil, &out, &errb, func(string) string { return "" }, testDeps(nil))
	if err == nil || !strings.Contains(err.Error(), "MEISCOPE_CT_DOMAINS") {
		t.Fatalf("got %v", err)
	}
}

func TestCTBaseline(t *testing.T) {
	cs, crt := fakeCTServices(t)
	env := map[string]string{"MEISCOPE_CT_CERTSPOTTER_URL": cs.URL, "MEISCOPE_CT_CRTSH_URL": crt.URL}
	var out, errb bytes.Buffer
	if err := ctBaselineCmd(context.Background(), []string{"--domain", "uvam.ai"}, &out, &errb, func(k string) string { return env[k] }, testDeps(nil)); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	if !strings.Contains(out.String(), "certificates:  2 of 10 crt.sh baseline (20.0 %)") {
		t.Fatalf("report:\n%s", out.String())
	}
	out.Reset()
	if err := ctBaselineCmd(context.Background(), []string{"--domain", "uvam.ai", "--json"}, &out, &errb, func(k string) string { return env[k] }, testDeps(nil)); err != nil {
		t.Fatal(err)
	}
	var v struct{ CertPercent float64 }
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.CertPercent != 20 {
		t.Fatalf("json %s, %v", out.String(), err)
	}
	if code, _, _ := runArgs(t, "ct-baseline"); code != 1 {
		t.Fatalf("missing --domain: code %d", code)
	}
}
