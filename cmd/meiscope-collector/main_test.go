package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/platform"
)

func runArgs(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runArgs(t, "version")
	if code != 0 || !strings.HasPrefix(out, "meiscope-collector "+platform.Version) {
		t.Fatalf("code %d, out %q", code, out)
	}
}

func TestNoArgsAndUnknown(t *testing.T) {
	if code, _, _ := runArgs(t); code != 2 {
		t.Fatalf("no args: code %d, want 2", code)
	}
	if code, _, _ := runArgs(t, "scan-everything"); code != 2 {
		t.Fatalf("unknown: code %d, want 2", code)
	}
}

func TestEnrolNeedsToken(t *testing.T) {
	if code, _, errOut := runArgs(t, "enrol"); code != 1 || !strings.Contains(errOut, "a token is required") {
		t.Fatalf("missing token: code %d, stderr %q", code, errOut)
	}
}

func TestRunInvalidConfig(t *testing.T) {
	var out, errb bytes.Buffer
	getenv := func(k string) string {
		if k == "MEISCOPE_LOG_LEVEL" {
			return "loud"
		}
		return ""
	}
	if code := run(context.Background(), []string{"run"}, &out, &errb, getenv); code != 1 {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
}

func TestServeHealthzAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, ln, slog.New(slog.NewTextHandler(io.Discard, nil)), 10*time.Millisecond, nil)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/healthz", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	var h platform.Health
	decErr := json.NewDecoder(resp.Body).Decode(&h)
	_ = resp.Body.Close()
	if decErr != nil || resp.StatusCode != http.StatusOK || h.Status != "ok" {
		t.Fatalf("status %d, body %+v, err %v", resp.StatusCode, h, decErr)
	}

	time.Sleep(30 * time.Millisecond) // let the idle ticker fire at least once
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after cancel")
	}
}
