// Package ct is the collector's Certificate Transparency poller (WP0.4,
// FR-DISC-020): for the tenant's owned domains it pulls issuance from the
// Cert Spotter API, tails selected CT logs directly (RFC 6962 through
// certificate-transparency-go, and static-ct tiled logs), falls back to
// crt.sh with a conservative rate limit, dedupes by SHA-256 fingerprint and
// builds observations with method ct: target kind ct_log (the log or
// service that was read), the logged certificate or precertificate first in
// served_chain, and ct_entry (source, log id, entry index, SCT timestamp).
//
// It only reads public CT data over HTTPS. It never connects to a host of
// the customer.
package ct

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Default per-poll budgets.
const (
	DefaultMaxEntriesPerLog = 50_000
	DefaultMaxCrtShFetches  = 30
)

// Poller runs CT poll cycles.
type Poller struct {
	Domains Domains
	// CertSpotter is the primary source; nil disables it.
	CertSpotter *CertSpotter
	// CrtSh is used for a domain only when Cert Spotter failed for it; nil
	// disables the fallback.
	CrtSh *CrtSh
	Logs  []Log
	// MaxEntriesPerLog bounds the entries read from one log per cycle.
	MaxEntriesPerLog uint64
	// MaxCrtShFetches bounds certificate downloads from crt.sh per cycle
	// (each one waits for the crt.sh rate limit).
	MaxCrtShFetches int
	// StartAtHead makes a log without saved progress start at its current
	// tree size (only new entries); otherwise it starts at index 0.
	StartAtHead bool
	Clock       clock.Clock
	Log         *slog.Logger
}

// SourceStats counts one source's results in a cycle.
type SourceStats struct {
	Scanned int // log entries read (logs only)
	Matched int // certificates for owned domains returned by the source
	New     int // of which not seen before (after dedupe)
	Errors  int
}

// Cycle is the result of one poll: new certificates and the progress to
// commit once they are submitted.
type Cycle struct {
	Found  []Found
	Stats  map[string]*SourceStats
	Errors []error
	at     time.Time

	csAfter map[string]string
	logNext map[string]uint64
}

// Observations builds the observations of the cycle.
func (c *Cycle) Observations() []submit.Observation {
	out := make([]submit.Observation, 0, len(c.Found))
	for _, f := range c.Found {
		out = append(out, f.Observation(c.at))
	}
	return out
}

// Commit records the cycle's progress in st: cursors move on and the new
// fingerprints join the dedupe set. Call it only after the observations
// were accepted by the core.
func (c *Cycle) Commit(st *State) {
	for d, a := range c.csAfter {
		st.CertSpotterAfter[d] = a
	}
	for u, n := range c.logNext {
		st.LogNext[u] = n
	}
	for _, f := range c.Found {
		st.Seen[f.Fingerprint] = c.at
		if f.Serial != "" {
			st.SeenSerials[f.Serial] = c.at
		}
	}
	st.prune(c.at)
}

type dedupe struct {
	st     *State
	cycle  *Cycle
	fps    map[string]bool
	serial map[string]bool
}

func (d *dedupe) add(source string, f Found) {
	s := d.cycle.stat(source)
	s.Matched++
	if _, ok := d.st.Seen[f.Fingerprint]; ok || d.fps[f.Fingerprint] {
		return
	}
	d.fps[f.Fingerprint] = true
	if f.Serial != "" {
		d.serial[f.Serial] = true
	}
	s.New++
	d.cycle.Found = append(d.cycle.Found, f)
}

func (d *dedupe) knownSerial(serial string) bool {
	if _, ok := d.st.SeenSerials[serial]; ok {
		return true
	}
	return d.serial[serial]
}

func (c *Cycle) stat(source string) *SourceStats {
	s, ok := c.Stats[source]
	if !ok {
		s = &SourceStats{}
		c.Stats[source] = s
	}
	return s
}

func (c *Cycle) fail(source string, err error) {
	c.stat(source).Errors++
	c.Errors = append(c.Errors, err)
}

func (p *Poller) logger() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Poll runs one cycle against st (which it does not modify).
func (p *Poller) Poll(ctx context.Context, st *State) *Cycle {
	if p.Clock == nil {
		p.Clock = clock.System{}
	}
	c := &Cycle{Stats: map[string]*SourceStats{}, at: p.Clock.Now().UTC(), csAfter: map[string]string{}, logNext: map[string]uint64{}}
	dd := &dedupe{st: st, cycle: c, fps: map[string]bool{}, serial: map[string]bool{}}
	log := p.logger()

	var fallback []string
	for _, d := range p.Domains {
		if p.CertSpotter == nil {
			fallback = append(fallback, d)
			continue
		}
		if err := p.pollCertSpotter(ctx, st, c, dd, d); err != nil {
			c.fail(SourceCertSpotter, err)
			log.Warn("cert spotter failed", "domain", d, "error", err)
			fallback = append(fallback, d)
		}
		if ctx.Err() != nil {
			return c
		}
	}
	for _, l := range p.Logs {
		if err := p.tail(ctx, st, c, dd, l); err != nil {
			c.fail(l.Source(), err)
			log.Warn("CT log tail failed", "log", l.URL(), "error", err)
		}
		if ctx.Err() != nil {
			return c
		}
	}
	if p.CrtSh != nil {
		budget := p.MaxCrtShFetches
		if budget <= 0 {
			budget = DefaultMaxCrtShFetches
		}
		for _, d := range fallback {
			n, err := p.pollCrtSh(ctx, c, dd, d, budget)
			budget -= n
			if err != nil {
				c.fail(SourceCrtSh, err)
				log.Warn("crt.sh fallback failed", "domain", d, "error", err)
			}
			if ctx.Err() != nil || budget <= 0 {
				break
			}
		}
	}
	return c
}

func (p *Poller) pollCertSpotter(ctx context.Context, st *State, c *Cycle, dd *dedupe, domain string) error {
	items, cursor, err := p.CertSpotter.Issuances(ctx, domain, st.CertSpotterAfter[domain])
	for _, it := range items {
		f, ok, perr := newFound(p.Domains, it.CertDER, nil, Evidence{Source: SourceCertSpotter, Endpoint: p.CertSpotter.base, SourceID: it.ID})
		if perr != nil {
			c.fail(SourceCertSpotter, fmt.Errorf("cert spotter issuance %s: %w", it.ID, perr))
			continue
		}
		if ok {
			dd.add(SourceCertSpotter, f)
		}
	}
	if cursor != "" {
		c.csAfter[domain] = cursor
	}
	return err
}

func (p *Poller) tail(ctx context.Context, st *State, c *Cycle, dd *dedupe, l Log) error {
	size, err := l.TreeSize(ctx)
	if err != nil {
		return err
	}
	next, ok := st.LogNext[l.URL()]
	if !ok {
		if p.StartAtHead {
			next = size
		}
		c.logNext[l.URL()] = next
	}
	if next > size {
		return fmt.Errorf("log %s: saved position %d is beyond the tree size %d", l.URL(), next, size)
	}
	budget := p.MaxEntriesPerLog
	if budget == 0 {
		budget = DefaultMaxEntriesPerLog
	}
	end := min(size, next+budget)
	for next < end {
		entries, err := l.Entries(ctx, next, end)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return fmt.Errorf("log %s: no entries at %d", l.URL(), next)
		}
		c.stat(l.Source()).Scanned += len(entries)
		for i := range entries {
			e := &entries[i]
			if err := p.consider(ctx, c, dd, l, e); err != nil {
				return err
			}
			next = e.Index + 1
			c.logNext[l.URL()] = next
		}
	}
	return nil
}

// consider matches one log entry against the owned domains.
func (p *Poller) consider(ctx context.Context, c *Cycle, dd *dedupe, l Log, e *LogEntry) error {
	pc, err := parseCert(e.Cert)
	if err != nil {
		// Unparseable entries exist in real logs; they cannot match a domain.
		c.stat(l.Source()).Errors++
		return nil
	}
	if p.Domains.MatchAny(pc.names) == "" {
		return nil
	}
	if err := l.ResolveChain(ctx, e); err != nil {
		return err
	}
	idx := int64(e.Index) //nolint:gosec // indices are far below 2^63
	ts := e.Timestamp
	ev := Evidence{
		Source:     l.Source(),
		Endpoint:   l.URL(),
		EntryType:  e.Type,
		LogID:      l.LogID(),
		EntryIndex: &idx,
		Timestamp:  &ts,
	}
	f, ok, err := newFound(p.Domains, e.Cert, e.Chain, ev)
	if err != nil || !ok {
		return nil
	}
	dd.add(l.Source(), f)
	return nil
}

// pollCrtSh is the fallback for one domain. It returns how many certificates
// it downloaded.
func (p *Poller) pollCrtSh(ctx context.Context, c *Cycle, dd *dedupe, domain string, budget int) (int, error) {
	rows, err := p.CrtSh.Search(ctx, domain)
	if err != nil {
		return 0, err
	}
	fetched := 0
	for _, r := range rows {
		if p.Domains.MatchAny(r.Names()) == "" || dd.knownSerial(normalizeSerial(r.SerialNumber)) {
			continue
		}
		if fetched >= budget {
			p.logger().Info("crt.sh download budget reached; the rest follows next cycle", "domain", domain)
			break
		}
		der, err := p.CrtSh.Certificate(ctx, r.ID)
		fetched++
		if err != nil {
			return fetched, err
		}
		f, ok, err := newFound(p.Domains, der, nil, Evidence{Source: SourceCrtSh, Endpoint: p.CrtSh.base, SourceID: fmt.Sprint(r.ID)})
		if err != nil {
			c.fail(SourceCrtSh, fmt.Errorf("crt.sh %d: %w", r.ID, err))
			continue
		}
		if ok {
			dd.add(SourceCrtSh, f)
		}
	}
	return fetched, nil
}
