package buffer_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/buffer"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, buffer.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func obs(i int) submit.Observation {
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindFile, Host: "app01.example.test", Path: "/opt/app/k" + strconv.Itoa(i) + ".jks"},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeReached,
		Adapter:    &submit.AdapterEvidence{Source: "osquery", File: &submit.FileDigest{SHA256: strings.Repeat("0a", 32)}},
	}
}

func open(t *testing.T, dir string, k []byte, clk clock.Clock, mod func(*buffer.Options)) *buffer.Buffer {
	t.Helper()
	o := buffer.Options{Dir: dir, Key: k, Clock: clk}
	if mod != nil {
		mod(&o)
	}
	b, err := buffer.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
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

func noRetry(core *submittest.Core, clk clock.Clock) *submit.Client {
	c, _ := submit.New(core.URL, core.Client(), submit.WithClock(clk), submit.WithRetry(retry.Policy{Attempts: 0}))
	return c
}

func paths(t *testing.T, core *submittest.Core) []string {
	t.Helper()
	var out []string
	for _, raw := range core.Batches() {
		var b submit.ObservationBatch
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		for _, o := range b.Observations {
			out = append(out, o.Target.Path)
		}
	}
	return out
}

func wantPaths(n, from int) []string {
	var w []string
	for i := from; i < from+n; i++ {
		w = append(w, "/opt/app/k"+strconv.Itoa(i)+".jks")
	}
	return w
}

func equal(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// TestSurvivesRestartAndReplaysInOrder: observations buffered while the
// core is down, a restart in between, then replay in order, each once.
func TestSurvivesRestartAndReplaysInOrder(t *testing.T) {
	core := newCore(t)
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	sub := noRetry(core, clk)

	b := open(t, dir, k, clk, nil)
	for i := 0; i < 5; i++ {
		if err := b.Enqueue(context.Background(), []submit.Observation{obs(i)}); err != nil {
			t.Fatal(err)
		}
	}
	core.FailNext(http.StatusServiceUnavailable)
	if _, err := b.Flush(context.Background(), sub, 2); err == nil {
		t.Fatal("flush succeeded against a failing core")
	}
	if b.Depth() != 5 || len(core.Batches()) != 0 {
		t.Fatalf("depth %d, batches %d", b.Depth(), len(core.Batches()))
	}
	_ = b.Close() // the process dies; the buffer is reopened from disk
	b = open(t, dir, k, clk, nil)
	if b.Depth() != 5 {
		t.Fatalf("depth after restart %d", b.Depth())
	}
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(5), obs(6)}); err != nil {
		t.Fatal(err)
	}
	res, err := b.Flush(context.Background(), sub, 2)
	if err != nil || res.Sent != 7 || res.Accepted != 7 || res.Duplicates != 0 || res.Remaining != 0 {
		t.Fatalf("flush %+v, %v", res, err)
	}
	if got := paths(t, core); !equal(got, wantPaths(7, 0)) {
		t.Fatalf("core received %v", got)
	}
	_ = b.Close()
	b = open(t, dir, k, clk, nil)
	if b.Depth() != 0 {
		t.Fatalf("depth after ack and restart %d", b.Depth())
	}
	res, err = b.Flush(context.Background(), sub, 0)
	if err != nil || res.Sent != 0 || len(paths(t, core)) != 7 {
		t.Fatalf("second flush %+v, %v, %d observations at the core", res, err, len(paths(t, core)))
	}
}

type failAfter struct {
	sub *submit.Client
	ok  int
}

func (f *failAfter) Submit(ctx context.Context, o []submit.Observation) (submit.Result, error) {
	if f.ok == 0 {
		return submit.Result{}, errors.New("core unreachable")
	}
	f.ok--
	return f.sub.Submit(ctx, o)
}

// TestPartialFlushThenRestart: the core accepts the first batch and then
// goes away; after a restart only the unaccepted remainder is replayed.
func TestPartialFlushThenRestart(t *testing.T) {
	core := newCore(t)
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	sub := noRetry(core, clk)
	b := open(t, dir, k, clk, nil)
	var all []submit.Observation
	for i := 0; i < 6; i++ {
		all = append(all, obs(i))
	}
	if err := b.Enqueue(context.Background(), all); err != nil {
		t.Fatal(err)
	}
	res, err := b.Flush(context.Background(), &failAfter{sub: sub, ok: 1}, 2)
	if err == nil || res.Sent != 2 || res.Remaining != 4 {
		t.Fatalf("flush %+v, %v", res, err)
	}
	_ = b.Close()
	b = open(t, dir, k, clk, nil)
	if res, err = b.Flush(context.Background(), sub, 2); err != nil || res.Sent != 4 {
		t.Fatalf("resume %+v, %v", res, err)
	}
	if got := paths(t, core); !equal(got, wantPaths(6, 0)) {
		t.Fatalf("core received %v (want each once, in order)", got)
	}
}

// TestOutage24h takes the core away for 24 hours of (fake) time while
// adapters keep producing, with a collector restart in the middle; after
// recovery the core holds exactly what was produced, in order.
func TestOutage24h(t *testing.T) {
	core := newCore(t)
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	sub := noRetry(core, clk)
	b := open(t, dir, k, clk, nil)
	produced := 0
	for hour := 0; hour < 24; hour++ {
		var batch []submit.Observation
		for j := 0; j < 50; j++ {
			batch = append(batch, obs(produced))
			produced++
		}
		if err := b.Enqueue(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
		core.FailNext(http.StatusBadGateway)
		if _, err := b.Flush(context.Background(), sub, 100); err == nil {
			t.Fatal("flush succeeded during the outage")
		}
		clk.Advance(time.Hour)
		if hour == 11 {
			_ = b.Close()
			b = open(t, dir, k, clk, nil)
		}
	}
	if b.Depth() != produced || b.Expired() != 0 {
		t.Fatalf("depth %d expired %d, produced %d", b.Depth(), b.Expired(), produced)
	}
	res, err := b.Flush(context.Background(), sub, 100)
	if err != nil || res.Sent != produced || res.Accepted != produced || res.Rejected != 0 || res.Remaining != 0 {
		t.Fatalf("recovery %+v, %v", res, err)
	}
	if got := paths(t, core); !equal(got, wantPaths(produced, 0)) {
		t.Fatalf("core holds %d observations, want %d in order", len(got), produced)
	}
}

func TestExpiresAfter72h(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, nil)
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(0)}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(71 * time.Hour)
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(1)}); err != nil {
		t.Fatal(err)
	}
	if b.Depth() != 2 || b.Expired() != 0 {
		t.Fatalf("depth %d expired %d at 71h", b.Depth(), b.Expired())
	}
	clk.Advance(2 * time.Hour) // the first is now 73h old
	core := newCore(t)
	res, err := b.Flush(context.Background(), noRetry(core, clk), 10)
	if err != nil || res.Sent != 1 || b.Expired() != 1 {
		t.Fatalf("flush %+v %v expired %d", res, err, b.Expired())
	}
	if got := paths(t, core); !equal(got, wantPaths(1, 1)) {
		t.Fatalf("core received %v", got)
	}
}

func TestBoundedAndCompacts(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, func(o *buffer.Options) { o.MaxBytes = 4000 })
	n := 0
	var err error
	for ; err == nil && n < 100; n++ {
		err = b.Enqueue(context.Background(), []submit.Observation{obs(n)})
	}
	if !errors.Is(err, buffer.ErrFull) || b.Depth() != n-1 {
		t.Fatalf("err %v depth %d n %d", err, b.Depth(), n)
	}
	core := newCore(t)
	if _, err := b.Flush(context.Background(), noRetry(core, clk), 3); err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(1000)}); err != nil {
		t.Fatalf("enqueue after drain: %v", err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "buffer.log"))
	if fi.Size() > 4000 {
		t.Fatalf("log is %d bytes, over the bound", fi.Size())
	}
}

func TestCompactionKeepsOrderWithPending(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	core := newCore(t)
	sub := noRetry(core, clk)
	mod := func(o *buffer.Options) { o.MaxBytes = 3000 }
	b := open(t, dir, k, clk, mod)
	var first []submit.Observation
	for i := 0; i < 6; i++ {
		first = append(first, obs(i))
	}
	if err := b.Enqueue(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Flush(context.Background(), &failAfter{sub: sub, ok: 1}, 4); err == nil {
		t.Fatal("expected the second batch to fail")
	}
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(6), obs(7)}); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	b = open(t, dir, k, clk, mod)
	if _, err := b.Flush(context.Background(), sub, 100); err != nil {
		t.Fatal(err)
	}
	if got := paths(t, core); !equal(got, wantPaths(8, 0)) {
		t.Fatalf("core received %v", got)
	}
}

func TestTornTailAndWrongKey(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, nil)
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(0), obs(1)}); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	f, err := os.OpenFile(filepath.Join(dir, "buffer.log"), os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test-only, synthetic value
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 1, 0, 'x', 'y'}) // a crash mid-write
	_ = f.Close()
	b = open(t, dir, k, clk, nil)
	if b.Depth() != 2 {
		t.Fatalf("depth %d after a torn tail", b.Depth())
	}
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(2)}); err != nil || b.Depth() != 3 {
		t.Fatalf("enqueue after recovery: %v depth %d", err, b.Depth())
	}
	_ = b.Close()
	if _, err := buffer.Open(buffer.Options{Dir: dir, Key: key(t), Clock: clk}); err == nil || !strings.Contains(err.Error(), "wrong buffer key") {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := buffer.Open(buffer.Options{Dir: dir, Key: []byte("short")}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEncryptedAtRest(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, nil)
	o := obs(0)
	o.Target.Host = "plaintext-marker.example.test"
	if err := b.Enqueue(context.Background(), []submit.Observation{o}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "buffer.log")) //nolint:gosec // test-only, synthetic value
	if len(raw) == 0 || strings.Contains(string(raw), "plaintext-marker") || strings.Contains(string(raw), "keystore") {
		t.Fatal("buffer content is readable on disk")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		if c, _ := os.ReadFile(f); strings.Contains(string(c), string(k)) { //nolint:gosec // test-only
			t.Fatalf("key written to %s", f)
		}
	}
	_ = b.Close()
	if err := b.Enqueue(context.Background(), nil); err == nil {
		t.Fatal("enqueue on a closed buffer")
	}
}

func TestRejectedObservationsAreAcknowledged(t *testing.T) {
	core := newCore(t)
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, nil)
	bad := obs(1)
	bad.Target.Port = 443 // a file target has no port: the core rejects it
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(0), bad}); err != nil {
		t.Fatal(err)
	}
	res, err := b.Flush(context.Background(), noRetry(core, clk), 10)
	if err != nil || res.Accepted != 1 || res.Rejected != 1 || res.Remaining != 0 {
		t.Fatalf("flush %+v, %v", res, err)
	}
}
