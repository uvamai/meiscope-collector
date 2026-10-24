package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

func credEnv(dir string) func(string) string {
	return envOf(map[string]string{
		"MEISCOPE_CREDENTIAL_FILE":     filepath.Join(dir, "c.age"),
		"MEISCOPE_CREDENTIAL_KEY_FILE": filepath.Join(dir, "id.txt"),
	})
}

func TestCredentialCmdInProcess(t *testing.T) {
	dir := t.TempDir()
	getenv := credEnv(dir)
	var out, errb bytes.Buffer
	call := func(stdin string, args ...string) error {
		out.Reset()
		errb.Reset()
		return credentialCmd(args, strings.NewReader(stdin), &out, &errb, getenv)
	}
	if err := call("", "init"); err != nil || !strings.Contains(out.String(), "identity file") {
		t.Fatalf("init: %v %s", err, out.String())
	}
	if err := call("", "init"); err == nil {
		t.Fatal("init overwrote the identity")
	}
	if err := call("synthetic-value-1\r\n", "set", "fleet_api_token"); err != nil || strings.Contains(out.String(), "synthetic-value-1") {
		t.Fatalf("set: %v %s", err, out.String())
	}
	if err := call("", "list"); err != nil || strings.TrimSpace(out.String()) != "fleet_api_token" {
		t.Fatalf("list: %v %q", err, out.String())
	}
	src, ok := fileSource(getenv)
	if !ok {
		t.Fatal("file source not configured")
	}
	if s, err := src.Get(context.Background(), "fleet_api_token"); err != nil || s.Reveal() != "synthetic-value-1" {
		t.Fatalf("value stored with the CRLF stripped: %v", err)
	}
	for name, args := range map[string][]string{
		"no subcommand": {}, "unknown": {"frobnicate"}, "set without ref": {"set"}, "set bad ref": {"set", "Bad Ref"},
	} {
		if err := call("v\n", args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := call("", "set", "empty_value"); err == nil {
		t.Error("an empty value was stored")
	}
	// Not configured.
	if err := credentialCmd([]string{"list"}, strings.NewReader(""), &out, &errb, envOf(nil)); err == nil || !strings.Contains(err.Error(), "MEISCOPE_CREDENTIAL_FILE") {
		t.Errorf("unconfigured: %v", err)
	}
}

func TestDefaultCredentialSourceUsesTheFileWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	getenv := credEnv(dir)
	if err := credential.InitIdentity(filepath.Join(dir, "id.txt")); err != nil {
		t.Fatal(err)
	}
	src, _ := fileSource(getenv)
	if err := src.Set("api_token", "v1"); err != nil {
		t.Fatal(err)
	}
	if s, err := defaultCredentialSource(getenv).Get(context.Background(), "api_token"); err != nil || s.Reveal() != "v1" {
		t.Fatalf("%v", err)
	}
	// The development build falls back to the environment; a release build to nothing.
	if _, err := defaultCredentialSource(envOf(nil)).Get(context.Background(), "api_token"); err == nil {
		t.Fatal("a credential came from nowhere")
	}
}

func TestReceiverCmd(t *testing.T) {
	var errb bytes.Buffer
	deps := adapterTestDeps(nil)
	if err := receiverCmd(context.Background(), []string{"run"}, &errb, envOf(nil), deps); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("the receiver must be disabled by default: %v", err)
	}
	if err := receiverCmd(context.Background(), nil, &errb, envOf(nil), deps); err == nil {
		t.Fatal("no subcommand accepted")
	}
	bad := envOf(map[string]string{"MEISCOPE_RECEIVER_ENABLED": "true", "MEISCOPE_RECEIVER_ADDR": "0.0.0.0:9100", "MEISCOPE_RECEIVER_DIR": t.TempDir(), "MEISCOPE_RECEIVER_TOKEN_REF": "push_token"})
	if err := receiverCmd(context.Background(), []string{"run"}, &errb, bad, deps); err == nil || !strings.Contains(err.Error(), "every interface") {
		t.Fatalf("0.0.0.0 must be refused at config load: %v", err)
	}
	if code := run(context.Background(), []string{"receiver", "run"}, &bytes.Buffer{}, &errb, envOf(nil)); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

// TestAdapterRunSubmitsDirectlyWithoutABuffer covers the no-buffer path.
func TestAdapterRunSubmitsDirectlyWithoutABuffer(t *testing.T) {
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pemCert(core.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envOf(map[string]string{
		"MEISCOPE_CORE_URL": core.URL, "MEISCOPE_CA_BUNDLE": ca, "MEISCOPE_LOG_FORMAT": "text",
		"MEISCOPE_ADAPTER_STATE_FILE": filepath.Join(t.TempDir(), "cursors.json"), "MEISCOPE_FEATURE_LOCAL_STORE_V1": "true",
	})
	var out, errb bytes.Buffer
	if err := adapterCmd(context.Background(), []string{"run", "--config", writeConfig(t)}, &out, &errb, env, adapterTestDeps(nil)); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	if !strings.Contains(errb.String(), "MEISCOPE_BUFFER_DIR is not set") || len(core.Batches()) == 0 {
		t.Fatalf("direct submission: batches %d\n%s", len(core.Batches()), errb.String())
	}
	var total int
	for _, b := range core.Batches() {
		var batch struct {
			Observations []json.RawMessage `json:"observations"`
		}
		_ = json.Unmarshal(b, &batch)
		total += len(batch.Observations)
	}
	if total != 125 {
		t.Fatalf("%d observations, want 125", total)
	}
	// An unknown adapter name or instance fails clearly.
	if err := adapterCmd(context.Background(), []string{"run", "--config", writeConfig(t), "nope"}, &out, &errb, env, adapterTestDeps(nil)); err == nil {
		t.Fatal("unknown instance accepted")
	}
	_ = adapter.Names()
}

// TestReceiverCmdServesAndStops starts the enabled receiver on a free
// loopback port, pushes one event with the bearer token, and stops it.
func TestReceiverCmdServesAndStops(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	spool := t.TempDir()
	env := envOf(map[string]string{
		"MEISCOPE_RECEIVER_ENABLED": "true", "MEISCOPE_RECEIVER_ADDR": addr, "MEISCOPE_RECEIVER_DIR": spool,
		"MEISCOPE_RECEIVER_TOKEN_REF": "push_token", "MEISCOPE_LOG_FORMAT": "text",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var errb bytes.Buffer
	go func() {
		done <- receiverCmd(ctx, []string{"run"}, &errb, env, adapterTestDeps(staticCreds{"push_token": "synthetic-push-token"}))
	}()
	ev := `{"name":"pack_meiscope_meiscope_keystores_posix","hostIdentifier":"app01.example.test","columns":{"path":"/opt/a.pfx","size":"1","sha256":"` + strings.Repeat("a", 64) + `"}}`
	var status int
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr, strings.NewReader(ev))
		req.Header.Set("Authorization", "Bearer synthetic-push-token")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("receiver: %v\n%s", err, errb.String())
	}
	if status != http.StatusNoContent {
		t.Fatalf("status %d\n%s", status, errb.String())
	}
	if ents, _ := os.ReadDir(spool); len(ents) != 1 {
		t.Fatalf("spool %v", ents)
	}
	if strings.Contains(errb.String(), "synthetic-push-token") {
		t.Fatal("the token is in the log")
	}
}
