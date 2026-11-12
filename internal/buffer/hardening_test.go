package buffer_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/buffer"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// fiveRecords writes obs(0..4) and returns the log path and the size of one
// record (all five have the same size: their paths differ by one digit).
func fiveRecords(t *testing.T, dir string, k []byte, clk clock.Clock) (string, int64) {
	t.Helper()
	b := open(t, dir, k, clk, nil)
	var batch []submit.Observation
	for i := range 5 {
		batch = append(batch, obs(i))
	}
	if err := b.Enqueue(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	p := filepath.Join(dir, "buffer.log")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size()%5 != 0 {
		t.Fatalf("records differ in size (%d bytes for 5)", st.Size())
	}
	return p, st.Size() / 5
}

func patch(t *testing.T, path string, off int64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) //nolint:gosec // test-only path
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func logTo(buf *bytes.Buffer) func(*buffer.Options) {
	return func(o *buffer.Options) { o.Log = slog.New(slog.NewTextHandler(buf, nil)) }
}

// TestCorruptMiddleRecordIsSkipped: one record that no longer authenticates
// is skipped by its length; the valid records after it are kept and
// replayed in order.
func TestCorruptMiddleRecordIsSkipped(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	p, size := fiveRecords(t, dir, k, clk)
	patch(t, p, 2*size+30, []byte{0xff, 0x00, 0xff}) // inside record 2's ciphertext

	var logs bytes.Buffer
	b := open(t, dir, k, clk, logTo(&logs))
	if b.Depth() != 4 || b.Corrupt() != 1 {
		t.Fatalf("depth %d, corrupt %d; want 4 and 1", b.Depth(), b.Corrupt())
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "records=1") {
		t.Fatalf("not logged loudly: %s", logs.String())
	}
	if st, _ := os.Stat(p); st.Size() != 5*size {
		t.Fatalf("log truncated to %d bytes; the records after the corrupt one must stay", st.Size())
	}
	// New records still append after the skipped one, and the replay order holds.
	if err := b.Enqueue(context.Background(), []submit.Observation{obs(5)}); err != nil {
		t.Fatal(err)
	}
	core := newCore(t)
	if _, err := b.Flush(context.Background(), noRetry(core, clk), 1000); err != nil {
		t.Fatal(err)
	}
	got := paths(t, core)
	want := []string{"/opt/app/k0.jks", "/opt/app/k1.jks", "/opt/app/k3.jks", "/opt/app/k4.jks", "/opt/app/k5.jks"}
	if !equal(got, want) {
		t.Fatalf("replayed %v, want %v", got, want)
	}
}

// TestCorruptLastRecordIsTruncated: a corrupt record at the end is dropped
// with the tail, as before.
func TestCorruptLastRecordIsTruncated(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	p, size := fiveRecords(t, dir, k, clk)
	patch(t, p, 4*size+30, []byte{0xff, 0x00, 0xff})
	b := open(t, dir, k, clk, nil)
	if b.Depth() != 4 || b.Corrupt() != 1 {
		t.Fatalf("depth %d, corrupt %d", b.Depth(), b.Corrupt())
	}
	if st, _ := os.Stat(p); st.Size() != 4*size {
		t.Fatalf("size %d, want %d", st.Size(), 4*size)
	}
}

// TestBrokenFramingKeepsOldBehaviour: a header with an impossible length
// cannot be skipped; the rest of the log is dropped (as a torn tail is) and
// the loss is logged as an error.
func TestBrokenFramingKeepsOldBehaviour(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	p, size := fiveRecords(t, dir, k, clk)
	bad := make([]byte, 4)
	binary.BigEndian.PutUint32(bad, 0xffffffff)
	patch(t, p, 2*size+8, bad) // record 2's length field

	var logs bytes.Buffer
	b := open(t, dir, k, clk, logTo(&logs))
	if b.Depth() != 2 {
		t.Fatalf("depth %d, want 2", b.Depth())
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "unreadable") {
		t.Fatalf("not logged loudly: %s", logs.String())
	}
	if st, _ := os.Stat(p); st.Size() != 2*size {
		t.Fatalf("size %d, want %d", st.Size(), 2*size)
	}
}

// TestFirstRecordCorruptIsNotAWrongKey: a damaged first record followed by
// valid ones is skipped; only a log where nothing authenticates is a wrong
// key.
func TestFirstRecordCorruptIsNotAWrongKey(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	p, _ := fiveRecords(t, dir, k, clk)
	patch(t, p, 30, []byte{0xff, 0x00, 0xff})
	b := open(t, dir, k, clk, nil)
	if b.Depth() != 4 || b.Corrupt() != 1 {
		t.Fatalf("depth %d, corrupt %d", b.Depth(), b.Corrupt())
	}
	_ = b.Close()
	if _, err := buffer.Open(buffer.Options{Dir: dir, Key: key(t), Clock: clk}); err == nil || !strings.Contains(err.Error(), "wrong buffer key") {
		t.Fatalf("wrong key: %v", err)
	}
}

// TestEnqueueRefusesPrivateKeyMaterial: an observation with PEM private-key
// armour in a field is refused and nothing of the call is written.
func TestEnqueueRefusesPrivateKeyMaterial(t *testing.T) {
	dir, k, clk := t.TempDir(), key(t), clock.NewFake(t0)
	b := open(t, dir, k, clk, nil)
	for _, armour := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		bad := obs(1)
		bad.Target.Path = "/opt/app/" + armour + "\nMIIEvQ..."
		err := b.Enqueue(context.Background(), []submit.Observation{obs(0), bad})
		if !errors.Is(err, submit.ErrPrivateKeyMaterial) || !strings.Contains(err.Error(), "observation 1") || strings.Contains(err.Error(), "MIIE") {
			t.Fatalf("%s: err %v", armour, err)
		}
	}
	if b.Depth() != 0 {
		t.Fatalf("depth %d after refused calls", b.Depth())
	}
	if st, _ := os.Stat(filepath.Join(dir, "buffer.log")); st.Size() != 0 {
		t.Fatalf("%d bytes written", st.Size())
	}
}
