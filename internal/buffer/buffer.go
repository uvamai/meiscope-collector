// Package buffer is the collector's local observation buffer (FR-DISC-033,
// NFR-AVAIL-003): when the core is unreachable, observations are kept on
// disk, encrypted, for up to 72 hours and replayed in order when it is back.
//
// Layout in Dir:
//
//	buffer.log  append-only records: seq (8 bytes, big endian), length
//	            (4 bytes), then nonce and AES-256-GCM ciphertext of the JSON
//	            record; the seq is the additional data, so records cannot be
//	            reordered or swapped undetected
//	acked.json  the highest seq the core has accepted, written atomically
//
// Delivery is at least once and in order: a batch is acknowledged on disk
// right after the core accepts it, so a restart replays only what the core
// has not accepted. Only a crash between the core's answer and that write
// resends one batch, which the core counts as duplicates.
package buffer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/fsutil"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Defaults.
const (
	DefaultMaxAge   = 72 * time.Hour
	DefaultMaxBytes = 512 << 20
	KeySize         = 32
	headerSize      = 12
	maxRecord       = 16 << 20
	logName         = "buffer.log"
	ackName         = "acked.json"
)

// ErrFull is returned by Enqueue when the buffer is at its size bound; the
// caller keeps its data (an adapter does not advance its cursor) and tries
// again later.
var ErrFull = errors.New("observation buffer is full")

// Options configure a buffer.
type Options struct {
	Dir string
	// Key is the 32-byte AES-256-GCM key; it comes from the credential
	// source and is never written to disk by the buffer.
	Key      []byte
	MaxAge   time.Duration
	MaxBytes int64
	Clock    clock.Clock
	Log      *slog.Logger
}

// Submitter sends observations to the core (submit.Client).
type Submitter interface {
	Submit(ctx context.Context, obs []submit.Observation) (submit.Result, error)
}

type entry struct {
	seq uint64
	at  time.Time
	off int64 // record start
	n   int64 // record length including header
}

type record struct {
	Seq uint64             `json:"seq"`
	At  time.Time          `json:"at"`
	Obs submit.Observation `json:"obs"`
}

// Buffer is a durable, bounded, encrypted FIFO of observations.
type Buffer struct {
	opts Options
	aead cipher.AEAD

	mu      sync.Mutex
	f       *os.File
	size    int64
	pending []entry
	acked   uint64
	nextSeq uint64
	expired int
}

// Open opens or creates the buffer in opts.Dir, recovering from a torn
// final record left by a crash.
func Open(opts Options) (*Buffer, error) {
	if len(opts.Key) != KeySize {
		return nil, fmt.Errorf("buffer key must be %d bytes", KeySize)
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	blk, err := aes.NewCipher(opts.Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("buffer dir: %w", err)
	}
	b := &Buffer{opts: opts, aead: aead}
	if err := b.loadAck(); err != nil {
		return nil, err
	}
	if err := b.scan(); err != nil {
		if b.f != nil {
			_ = b.f.Close()
		}
		return nil, err
	}
	return b, nil
}

// Close closes the buffer file.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f == nil {
		return nil
	}
	err := b.f.Close()
	b.f = nil
	return err
}

// Depth returns the number of observations waiting for the core.
func (b *Buffer) Depth() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// Expired returns how many observations were dropped for age since Open.
func (b *Buffer) Expired() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.expired
}

func (b *Buffer) path(name string) string { return filepath.Join(b.opts.Dir, name) }

func (b *Buffer) loadAck() error {
	raw, err := os.ReadFile(b.path(ackName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("buffer: %w", err)
	}
	var a struct {
		Acked uint64 `json:"acked"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return fmt.Errorf("buffer %s: %w", ackName, err)
	}
	b.acked = a.Acked
	return nil
}

// scan reads the record headers, authenticating every unacknowledged
// record, and truncates a torn or corrupt tail. A first record that does
// not authenticate means a wrong key: Open fails rather than discard data.
func (b *Buffer) scan() error {
	f, err := os.OpenFile(b.path(logName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("buffer: %w", err)
	}
	b.f = f
	b.nextSeq = b.acked + 1
	var off int64
	hdr := make([]byte, headerSize)
	first := true
	for {
		if _, err := f.ReadAt(hdr, off); err != nil {
			break // EOF or a torn header
		}
		seq := binary.BigEndian.Uint64(hdr[:8])
		n := int64(binary.BigEndian.Uint32(hdr[8:]))
		if n <= 0 || n > maxRecord {
			break
		}
		body := make([]byte, n)
		if _, err := f.ReadAt(body, off+headerSize); err != nil {
			break
		}
		rec, err := b.open(seq, body)
		if err != nil {
			if first {
				return fmt.Errorf("buffer: the first record does not decrypt (wrong buffer key?): %w", err)
			}
			break
		}
		first = false
		if seq > b.acked {
			b.pending = append(b.pending, entry{seq: seq, at: rec.At, off: off, n: headerSize + n})
		}
		if seq >= b.nextSeq {
			b.nextSeq = seq + 1
		}
		off += headerSize + n
	}
	if fi, err := f.Stat(); err == nil && fi.Size() > off {
		b.opts.Log.Warn("buffer: dropping a torn or corrupt tail", "bytes", fi.Size()-off)
		if err := f.Truncate(off); err != nil {
			return fmt.Errorf("buffer: %w", err)
		}
	}
	b.size = off
	return nil
}

func aad(seq uint64) []byte {
	a := make([]byte, 8, 8+18)
	binary.BigEndian.PutUint64(a, seq)
	return append(a, "meiscope-buffer-v1"...)
}

func (b *Buffer) seal(rec record) ([]byte, error) {
	pt, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := b.aead.Seal(nonce, nonce, pt, aad(rec.Seq))
	if len(ct) > maxRecord {
		return nil, fmt.Errorf("observation too large to buffer (%d bytes)", len(ct))
	}
	out := make([]byte, headerSize, headerSize+len(ct))
	binary.BigEndian.PutUint64(out[:8], rec.Seq)
	binary.BigEndian.PutUint32(out[8:], uint32(len(ct))) //nolint:gosec // bounded by maxRecord
	return append(out, ct...), nil
}

func (b *Buffer) open(seq uint64, body []byte) (record, error) {
	ns := b.aead.NonceSize()
	if len(body) < ns {
		return record{}, errors.New("short record")
	}
	pt, err := b.aead.Open(nil, body[:ns], body[ns:], aad(seq))
	if err != nil {
		return record{}, err
	}
	var rec record
	if err := json.Unmarshal(pt, &rec); err != nil {
		return record{}, err
	}
	if rec.Seq != seq {
		return record{}, errors.New("sequence mismatch")
	}
	return rec, nil
}

// Enqueue appends observations durably (written and synced) in order.
func (b *Buffer) Enqueue(_ context.Context, obs []submit.Observation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f == nil {
		return errors.New("buffer is closed")
	}
	b.expireLocked()
	now := b.opts.Clock.Now().UTC()
	recs := make([][]byte, 0, len(obs))
	total := int64(0)
	for i, o := range obs {
		r, err := b.seal(record{Seq: b.nextSeq + uint64(i), At: now, Obs: o}) //nolint:gosec // i >= 0
		if err != nil {
			return err
		}
		recs = append(recs, r)
		total += int64(len(r))
	}
	if b.size+total > b.opts.MaxBytes {
		if err := b.compactLocked(); err != nil {
			return err
		}
		if b.size+total > b.opts.MaxBytes {
			return fmt.Errorf("%w (%d observations, %d bytes)", ErrFull, len(b.pending), b.size)
		}
	}
	data := make([]byte, 0, total)
	ents := make([]entry, 0, len(recs))
	off := b.size
	for i, r := range recs {
		ents = append(ents, entry{seq: b.nextSeq + uint64(i), at: now, off: off, n: int64(len(r))}) //nolint:gosec // i >= 0
		data = append(data, r...)
		off += int64(len(r))
	}
	if _, err := b.f.WriteAt(data, b.size); err != nil {
		_ = b.f.Truncate(b.size)
		return fmt.Errorf("buffer write: %w", err)
	}
	if err := b.f.Sync(); err != nil {
		_ = b.f.Truncate(b.size)
		return fmt.Errorf("buffer sync: %w", err)
	}
	b.size = off
	b.nextSeq += uint64(len(recs))
	b.pending = append(b.pending, ents...)
	return nil
}

// expireLocked drops observations buffered longer than MaxAge (a prefix,
// as records are in time order).
func (b *Buffer) expireLocked() {
	cut := b.opts.Clock.Now().Add(-b.opts.MaxAge)
	i := 0
	for i < len(b.pending) && b.pending[i].at.Before(cut) {
		i++
	}
	if i == 0 {
		return
	}
	last := b.pending[i-1].seq
	if err := b.ackLocked(last); err != nil {
		b.opts.Log.Error("buffer: could not drop expired observations", "error", err)
		return
	}
	b.expired += i
	b.opts.Log.Warn("buffer: dropped observations older than the buffer window", "observations", i, "max_age", b.opts.MaxAge.String())
}

func (b *Buffer) ackLocked(seq uint64) error {
	raw, err := json.Marshal(map[string]uint64{"acked": seq})
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(b.path(ackName), raw); err != nil {
		return err
	}
	b.acked = seq
	i := 0
	for i < len(b.pending) && b.pending[i].seq <= seq {
		i++
	}
	b.pending = b.pending[i:]
	return nil
}

// compactLocked rewrites the log with only the unacknowledged records.
func (b *Buffer) compactLocked() error {
	start := b.size
	if len(b.pending) > 0 {
		start = b.pending[0].off
	}
	if start == 0 {
		return nil
	}
	rest := make([]byte, b.size-start)
	if _, err := b.f.ReadAt(rest, start); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("buffer compact: %w", err)
	}
	if err := b.f.Close(); err != nil {
		return err
	}
	b.f = nil
	if err := fsutil.WriteFileAtomic(b.path(logName), rest); err != nil {
		return fmt.Errorf("buffer compact: %w", err)
	}
	f, err := os.OpenFile(b.path(logName), os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("buffer compact: %w", err)
	}
	b.f = f
	for i := range b.pending {
		b.pending[i].off -= start
	}
	b.size -= start
	return nil
}

// FlushResult sums what a Flush delivered.
type FlushResult struct {
	Sent       int
	Accepted   int
	Duplicates int
	Rejected   int
	Remaining  int
}

// Flush replays the buffered observations in order, at most batch (1..1000)
// per request, acknowledging each batch on disk as soon as the core accepts
// it. It stops at the first failure (after the submitter's own retries),
// keeping that batch and everything after it. Observations the core
// rejects individually are acknowledged too: resending them cannot succeed.
func (b *Buffer) Flush(ctx context.Context, sub Submitter, batch int) (FlushResult, error) {
	if batch <= 0 || batch > submit.MaxBatch {
		batch = submit.MaxBatch
	}
	var res FlushResult
	for {
		b.mu.Lock()
		b.expireLocked()
		n := min(batch, len(b.pending))
		ents := append([]entry(nil), b.pending[:n]...)
		obs, err := b.readLocked(ents)
		b.mu.Unlock()
		if err != nil {
			return res, err
		}
		if n == 0 {
			break
		}
		r, err := sub.Submit(ctx, obs)
		if err != nil {
			res.Remaining = b.Depth()
			return res, fmt.Errorf("buffer flush: %w", err)
		}
		for _, rj := range r.Rejected {
			b.opts.Log.Warn("observation rejected by the core", "code", rj.Code, "message", rj.Message)
		}
		b.mu.Lock()
		err = b.ackLocked(ents[len(ents)-1].seq)
		if err == nil && (len(b.pending) == 0 || b.pending[0].off > b.size/2) {
			err = b.compactLocked()
		}
		b.mu.Unlock()
		if err != nil {
			return res, fmt.Errorf("buffer ack: %w", err)
		}
		res.Sent += n
		res.Accepted += r.Accepted
		res.Duplicates += r.Duplicates
		res.Rejected += len(r.Rejected)
	}
	res.Remaining = b.Depth()
	return res, nil
}

func (b *Buffer) readLocked(ents []entry) ([]submit.Observation, error) {
	out := make([]submit.Observation, 0, len(ents))
	for _, e := range ents {
		body := make([]byte, e.n-headerSize)
		if _, err := b.f.ReadAt(body, e.off+headerSize); err != nil {
			return nil, fmt.Errorf("buffer read: %w", err)
		}
		rec, err := b.open(e.seq, body)
		if err != nil {
			return nil, fmt.Errorf("buffer read seq %d: %w", e.seq, err)
		}
		out = append(out, rec.Obs)
	}
	return out, nil
}
