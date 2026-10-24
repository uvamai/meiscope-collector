package ct

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"

	"github.com/uvamai/meiscope-collector/internal/clock"
)

// LogEntry is one entry read from a CT log.
type LogEntry struct {
	Index     uint64
	Timestamp time.Time
	Type      string // EntryX509 or EntryPrecert
	// Cert is the certificate, or the precertificate as submitted.
	Cert      []byte
	Chain     [][]byte
	LeafInput []byte
	ExtraData []byte
	// chainFPs are the issuer fingerprints of a static-ct entry, resolved
	// into Chain by ResolveChain only for entries that match.
	chainFPs [][32]byte
}

// Log is a CT log the poller tails.
type Log interface {
	// URL is the log's base (RFC 6962) or monitoring prefix (static-ct).
	URL() string
	Source() string
	// LogID is the SHA-256 of the log's public key, or nil when not known.
	LogID() []byte
	TreeSize(ctx context.Context) (uint64, error)
	// Entries returns entries from start (inclusive) up to end (exclusive);
	// it may return fewer, but at least one when start < end.
	Entries(ctx context.Context, start, end uint64) ([]LogEntry, error)
	// ResolveChain fills e.Chain when the log stores issuers separately.
	ResolveChain(ctx context.Context, e *LogEntry) error
}

// RFC6962Log reads an RFC 6962 log with certificate-transparency-go.
type RFC6962Log struct {
	url   string
	lc    *client.LogClient
	logID []byte
	batch uint64
}

// NewRFC6962Log returns a reader for the log at url. keyDER, when given, is
// the log's public key: the STH signature is then verified and the log id
// is known.
func NewRFC6962Log(url string, keyDER []byte, rt http.RoundTripper, clk clock.Clock, p Politeness, userAgent string) (*RFC6962Log, error) {
	url = strings.TrimRight(url, "/")
	lc, err := client.New(url, newHTTPClient(rt, clk, p, userAgent), jsonclient.Options{PublicKeyDER: keyDER, UserAgent: userAgent})
	if err != nil {
		return nil, fmt.Errorf("log %s: %w", url, err)
	}
	l := &RFC6962Log{url: url, lc: lc, batch: 256}
	if len(keyDER) > 0 {
		sum := sha256.Sum256(keyDER)
		l.logID = sum[:]
	}
	return l, nil
}

// URL returns the log URL.
func (l *RFC6962Log) URL() string { return l.url }

// Source returns SourceRFC6962.
func (l *RFC6962Log) Source() string { return SourceRFC6962 }

// LogID returns the log id when the key is known.
func (l *RFC6962Log) LogID() []byte { return l.logID }

// TreeSize returns the size of the latest STH.
func (l *RFC6962Log) TreeSize(ctx context.Context) (uint64, error) {
	sth, err := l.lc.GetSTH(ctx)
	if err != nil {
		return 0, fmt.Errorf("log %s: get-sth: %w", l.url, err)
	}
	return sth.TreeSize, nil
}

// Entries reads get-entries for [start, end).
func (l *RFC6962Log) Entries(ctx context.Context, start, end uint64) ([]LogEntry, error) {
	if start >= end {
		return nil, nil
	}
	last := min(end, start+l.batch) - 1
	resp, err := l.lc.GetRawEntries(ctx, int64(start), int64(last)) //nolint:gosec // indices are far below 2^63
	if err != nil {
		return nil, fmt.Errorf("log %s: get-entries %d-%d: %w", l.url, start, last, err)
	}
	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("log %s: get-entries %d-%d returned no entries", l.url, start, last)
	}
	if uint64(len(resp.Entries)) > last-start+1 {
		return nil, fmt.Errorf("log %s: get-entries returned %d entries for %d requested", l.url, len(resp.Entries), last-start+1)
	}
	out := make([]LogEntry, 0, len(resp.Entries))
	for i := range resp.Entries {
		idx := start + uint64(i)
		raw, err := ctgo.RawLogEntryFromLeaf(int64(idx), &resp.Entries[i]) //nolint:gosec // see above
		if err != nil {
			return nil, fmt.Errorf("log %s: entry %d: %w", l.url, idx, err)
		}
		e := LogEntry{
			Index:     idx,
			Timestamp: msToTime(raw.Leaf.TimestampedEntry.Timestamp),
			Cert:      raw.Cert.Data,
			LeafInput: resp.Entries[i].LeafInput,
			ExtraData: resp.Entries[i].ExtraData,
		}
		switch raw.Leaf.TimestampedEntry.EntryType {
		case ctgo.X509LogEntryType:
			e.Type = EntryX509
		case ctgo.PrecertLogEntryType:
			e.Type = EntryPrecert
		default:
			return nil, fmt.Errorf("log %s: entry %d: unknown entry type %d", l.url, idx, raw.Leaf.TimestampedEntry.EntryType)
		}
		for _, c := range raw.Chain {
			e.Chain = append(e.Chain, c.Data)
		}
		out = append(out, e)
	}
	return out, nil
}

// ResolveChain is a no-op: RFC 6962 entries carry their chain.
func (l *RFC6962Log) ResolveChain(context.Context, *LogEntry) error { return nil }
