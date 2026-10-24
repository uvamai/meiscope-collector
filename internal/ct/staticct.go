package ct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Static CT API (tiled logs), read side, per https://c2sp.org/static-ct-api.
// certificate-transparency-go v1.4.0 lists tiled logs in loglist3 but has no
// client for them, so the minimal read API (checkpoint, data tiles, issuers)
// is implemented here with the standard library.

// TileWidth is the number of entries in a full data tile.
const TileWidth = 256

// Checkpoint is the parsed body of <prefix>/checkpoint (a signed note).
type Checkpoint struct {
	Origin   string
	TreeSize uint64
	RootHash [32]byte
}

// ParseCheckpoint parses the checkpoint text: origin, tree size and root
// hash lines, then a blank line and signatures. The note signature is not
// verified here (that needs the log's key and the c2sp signed-note
// verifier); the data is fetched over HTTPS.
func ParseCheckpoint(b []byte) (Checkpoint, error) {
	body, _, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return Checkpoint{}, errors.New("checkpoint: no signature block")
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, errors.New("checkpoint: fewer than three lines")
	}
	var cp Checkpoint
	cp.Origin = lines[0]
	if cp.Origin == "" {
		return Checkpoint{}, errors.New("checkpoint: empty origin")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: tree size: %w", err)
	}
	cp.TreeSize = size
	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != 32 {
		return Checkpoint{}, fmt.Errorf("checkpoint: root hash is not 32 base64 bytes")
	}
	copy(cp.RootHash[:], h)
	return cp, nil
}

// TilePath returns the path of data tile n; width < TileWidth names a
// partial tile.
func TilePath(n uint64, width int) string {
	p := "tile/data/" + tileIndex(n)
	if width > 0 && width < TileWidth {
		p += ".p/" + strconv.Itoa(width)
	}
	return p
}

// tileIndex encodes n in groups of three decimal digits, all but the last
// prefixed with "x" (1234067 -> x001/x234/067).
func tileIndex(n uint64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/%s", n%1000, s)
	}
	return s
}

// StaticLog reads a static-ct (tiled) log.
type StaticLog struct {
	prefix string
	hc     *http.Client
	clk    clock.Clock
	logID  []byte

	mu      sync.Mutex
	issuers map[[32]byte][]byte
	size    uint64 // tree size of the last checkpoint read
}

// NewStaticLog returns a reader for the log with this monitoring prefix.
// logID (SHA-256 of the log key) is optional.
func NewStaticLog(prefix string, logID []byte, rt http.RoundTripper, clk clock.Clock, p Politeness, userAgent string) *StaticLog {
	return &StaticLog{
		prefix:  strings.TrimRight(prefix, "/"),
		hc:      newHTTPClient(rt, clk, p, userAgent),
		clk:     clk,
		logID:   logID,
		issuers: map[[32]byte][]byte{},
	}
}

// URL returns the monitoring prefix.
func (l *StaticLog) URL() string { return l.prefix }

// Source returns submit.SourceStaticCT.
func (l *StaticLog) Source() string { return submit.SourceStaticCT }

// LogID returns the log id when known.
func (l *StaticLog) LogID() []byte { return l.logID }

// Checkpoint fetches and parses the latest checkpoint.
func (l *StaticLog) Checkpoint(ctx context.Context) (Checkpoint, error) {
	b, err := getBytes(ctx, l.hc, l.clk, l.prefix+"/checkpoint", nil, 1<<20)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("static log %s: %w", l.prefix, err)
	}
	cp, err := ParseCheckpoint(b)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("static log %s: %w", l.prefix, err)
	}
	l.mu.Lock()
	l.size = cp.TreeSize
	l.mu.Unlock()
	return cp, nil
}

// TreeSize returns the checkpoint's tree size.
func (l *StaticLog) TreeSize(ctx context.Context) (uint64, error) {
	cp, err := l.Checkpoint(ctx)
	return cp.TreeSize, err
}

// Entries reads the data tile holding start and returns the entries from
// start up to end (exclusive) within that tile. A partial tile exists only
// at the right edge of the tree, so the tile width comes from the tree size
// of the last checkpoint (TreeSize), not from end.
func (l *StaticLog) Entries(ctx context.Context, start, end uint64) ([]LogEntry, error) {
	if start >= end {
		return nil, nil
	}
	l.mu.Lock()
	size := max(l.size, end)
	l.mu.Unlock()
	tile := start / TileWidth
	width := int(min(size-tile*TileWidth, TileWidth)) //nolint:gosec // at most TileWidth
	data, err := l.dataTile(ctx, tile, width)
	if err != nil {
		return nil, err
	}
	var out []LogEntry
	for i := 0; i < width; i++ {
		idx := tile*TileWidth + uint64(i)
		e, rest, err := parseTileLeaf(data)
		if err != nil {
			return nil, fmt.Errorf("static log %s: tile %d entry %d: %w", l.prefix, tile, i, err)
		}
		data = rest
		if e.Index != idx {
			return nil, fmt.Errorf("static log %s: entry at position %d has leaf_index %d", l.prefix, idx, e.Index)
		}
		if idx >= start && idx < end {
			out = append(out, e)
		}
	}
	return out, nil
}

// dataTile fetches a data tile of the given width. A partial tile that has
// since been completed may be gone, so a 404 (or the 403 that object stores
// answer for a missing object) falls back to the full tile, whose first
// entries are the same.
func (l *StaticLog) dataTile(ctx context.Context, tile uint64, width int) ([]byte, error) {
	b, err := getBytes(ctx, l.hc, l.clk, l.prefix+"/"+TilePath(tile, width), nil, 64<<20)
	if err != nil && width < TileWidth && (IsStatus(err, http.StatusNotFound) || IsStatus(err, http.StatusForbidden)) {
		b, err = getBytes(ctx, l.hc, l.clk, l.prefix+"/"+TilePath(tile, TileWidth), nil, 64<<20)
	}
	if err != nil {
		return nil, fmt.Errorf("static log %s: %w", l.prefix, err)
	}
	return b, nil
}

// ResolveChain fetches the entry's issuers (cached by fingerprint) and
// checks each against its fingerprint.
func (l *StaticLog) ResolveChain(ctx context.Context, e *LogEntry) error {
	if len(e.Chain) > 0 || len(e.chainFPs) == 0 {
		return nil
	}
	for _, fp := range e.chainFPs {
		der, err := l.issuer(ctx, fp)
		if err != nil {
			return err
		}
		e.Chain = append(e.Chain, der)
	}
	return nil
}

func (l *StaticLog) issuer(ctx context.Context, fp [32]byte) ([]byte, error) {
	l.mu.Lock()
	der, ok := l.issuers[fp]
	l.mu.Unlock()
	if ok {
		return der, nil
	}
	der, err := getBytes(ctx, l.hc, l.clk, l.prefix+"/issuer/"+hex.EncodeToString(fp[:]), nil, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("static log %s: %w", l.prefix, err)
	}
	if sha256.Sum256(der) != fp {
		return nil, fmt.Errorf("static log %s: issuer %x: content does not match its fingerprint", l.prefix, fp[:8])
	}
	l.mu.Lock()
	l.issuers[fp] = der
	l.mu.Unlock()
	return der, nil
}

// tileReader reads TLS presentation-language fields.
type tileReader struct {
	b   []byte
	err error
}

func (r *tileReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errors.New("truncated")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *tileReader) uint(n int) uint64 {
	var v uint64
	for _, c := range r.take(n) {
		v = v<<8 | uint64(c)
	}
	return v
}

func (r *tileReader) vector(lenBytes int) []byte {
	return r.take(int(r.uint(lenBytes))) //nolint:gosec // length prefixes are at most 3 bytes
}

// parseTileLeaf parses one TileLeaf:
//
//	struct {
//	    TimestampedEntry timestamped_entry;
//	    select (entry_type) {
//	        case x509_entry: Empty;
//	        case precert_entry: ASN.1Cert pre_certificate;
//	    };
//	    Fingerprint certificate_chain<0..2^16-1>;
//	} TileLeaf;
//
// The TimestampedEntry extensions carry the leaf_index extension (type 0,
// a 40-bit index).
func parseTileLeaf(b []byte) (LogEntry, []byte, error) {
	r := &tileReader{b: b}
	ts := r.uint(8)
	etype := r.uint(2)
	var e LogEntry
	e.Timestamp = msToTime(ts)
	switch etype {
	case 0:
		e.Type = submit.EntryX509
		e.Cert = r.vector(3)
	case 1:
		e.Type = submit.EntryPrecert
		r.take(32)  // issuer_key_hash
		r.vector(3) // tbs_certificate
	default:
		if r.err == nil {
			return LogEntry{}, nil, fmt.Errorf("unknown entry type %d", etype)
		}
	}
	exts := r.vector(2)
	if r.err != nil {
		return LogEntry{}, nil, fmt.Errorf("timestamped_entry: %w", r.err)
	}
	te := b[:len(b)-len(r.b)]
	if etype == 1 {
		e.Cert = r.vector(3)
	}
	chain := r.vector(2)
	if r.err != nil {
		return LogEntry{}, nil, fmt.Errorf("tile leaf: %w", r.err)
	}
	if len(chain)%32 != 0 {
		return LogEntry{}, nil, errors.New("certificate_chain is not a list of SHA-256 fingerprints")
	}
	for i := 0; i < len(chain); i += 32 {
		var fp [32]byte
		copy(fp[:], chain[i:i+32])
		e.chainFPs = append(e.chainFPs, fp)
	}
	idx, err := leafIndex(exts)
	if err != nil {
		return LogEntry{}, nil, err
	}
	e.Index = idx
	// MerkleTreeLeaf: version v1 (0), leaf_type timestamped_entry (0).
	e.LeafInput = append([]byte{0, 0}, te...)
	return e, r.b, nil
}

func leafIndex(exts []byte) (uint64, error) {
	r := &tileReader{b: exts}
	for len(r.b) > 0 && r.err == nil {
		typ := r.uint(1)
		data := r.vector(2)
		if r.err == nil && typ == 0 {
			if len(data) != 5 {
				return 0, errors.New("leaf_index extension is not 5 bytes")
			}
			var buf [8]byte
			copy(buf[3:], data)
			return binary.BigEndian.Uint64(buf[:]), nil
		}
	}
	if r.err != nil {
		return 0, fmt.Errorf("extensions: %w", r.err)
	}
	return 0, errors.New("no leaf_index extension")
}

// compile-time interface checks
var (
	_ Log = (*StaticLog)(nil)
	_ Log = (*RFC6962Log)(nil)
)
