package ct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ctgo "github.com/google/certificate-transparency-go"

	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

const csFixture = "testdata/certspotter/issuances-owned.example.json"

type staticCreds map[string]string

func (s staticCreds) Get(_ context.Context, ref string) (credential.Secret, error) {
	if v, ok := s[ref]; ok {
		return credential.NewSecret(v), nil
	}
	return credential.Secret{}, credential.ErrNotFound
}

func TestCertSpotterPagination(t *testing.T) {
	srv := newFakeCertSpotter(t, csFixture, 1)
	cs := NewCertSpotter(srv.URL, nil, clock.NewFake(t0), CertSpotterPoliteness, "test", nil)
	items, cursor, err := cs.Issuances(context.Background(), "owned.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 || cursor != "17495069787" {
		t.Fatalf("got %d items, cursor %q", len(items), cursor)
	}
	var afters []string
	for _, r := range srv.reqs() {
		q := r.URL.Query()
		afters = append(afters, q.Get("after"))
		if r.Header.Get("Authorization") != "" {
			t.Fatal("no key configured: no Authorization header expected (free tier)")
		}
		if q.Get("include_subdomains") != "true" || !reflect.DeepEqual(q["expand"], []string{"dns_names", "cert_der"}) {
			t.Fatalf("query %v", q)
		}
	}
	// One page per issuance, then an empty page ends the pagination.
	want := []string{"", "17283841456", "17389535029", "17404892526", "17495069787"}
	if !reflect.DeepEqual(afters, want) {
		t.Fatalf("after cursors %v, want %v", afters, want)
	}

	// Resuming from the cursor asks for newer issuances only.
	items, _, err = cs.Issuances(context.Background(), "owned.example", cursor)
	if err != nil || len(items) != 0 {
		t.Fatalf("resume: %d items, %v", len(items), err)
	}
}

func TestCertSpotterKeyFromCredentialSource(t *testing.T) {
	srv := newFakeCertSpotter(t, csFixture, 100)
	cs := NewCertSpotter(srv.URL, nil, clock.NewFake(t0), CertSpotterPoliteness, "test", staticCreds{CertSpotterKeyRef: "k-1"})
	if _, _, err := cs.Issuances(context.Background(), "owned.example", ""); err != nil {
		t.Fatal(err)
	}
	for _, r := range srv.reqs() {
		if r.Header.Get("Authorization") != "Bearer k-1" {
			t.Fatalf("Authorization %q", r.Header.Get("Authorization"))
		}
		if strings.Contains(r.URL.RawQuery, "k-1") {
			t.Fatal("the key must not travel in the URL")
		}
	}
}

func TestCertSpotterRejectsHashMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"1","cert_sha256":"00","cert_der":"MAA="}]`))
	}))
	defer srv.Close()
	cs := NewCertSpotter(srv.URL, nil, clock.NewFake(t0), CertSpotterPoliteness, "test", nil)
	if _, _, err := cs.Issuances(context.Background(), "owned.example", ""); err == nil || !strings.Contains(err.Error(), "cert_sha256") {
		t.Fatalf("want hash mismatch, got %v", err)
	}
}

// TestPollDedupesByFingerprint: hive.owned.example's certificate is returned for
// both owned domains (owned.example includes its subdomains) and is reported once;
// after Commit, the same certificates are not reported again.
func TestPollDedupesByFingerprint(t *testing.T) {
	srv := newFakeCertSpotter(t, csFixture, 2)
	clk := clock.NewFake(t0)
	ds, _ := ParseDomains([]string{"owned.example", "hive.owned.example"})
	p := &Poller{Domains: ds, CertSpotter: NewCertSpotter(srv.URL, nil, clk, CertSpotterPoliteness, "test", nil), Clock: clk}
	st := NewState()
	c := p.Poll(context.Background(), st)
	if len(c.Errors) != 0 {
		t.Fatal(c.Errors)
	}
	s := c.Stats[SourceCertSpotter]
	if s.Matched != 5 || s.New != 4 || len(c.Found) != 4 {
		t.Fatalf("matched %d new %d found %d; want 5, 4, 4", s.Matched, s.New, len(c.Found))
	}
	fps := map[string]bool{}
	for _, f := range c.Found {
		if fps[f.Fingerprint] {
			t.Fatal("duplicate fingerprint in one cycle")
		}
		fps[f.Fingerprint] = true
		sum := sha256.Sum256(f.Chain[0])
		if f.Fingerprint != hex.EncodeToString(sum[:]) {
			t.Fatal("fingerprint is not the SHA-256 of the leaf")
		}
	}
	c.Commit(st)
	if st.CertSpotterAfter["owned.example"] != "17495069787" || len(st.Seen) != 4 {
		t.Fatalf("state %+v", st)
	}
	// Even from scratch (cursors lost), seen fingerprints are not resent.
	st.CertSpotterAfter = map[string]string{}
	c = p.Poll(context.Background(), st)
	if len(c.Found) != 0 || c.Stats[SourceCertSpotter].Matched != 5 {
		t.Fatalf("second cycle found %d", len(c.Found))
	}
}

func TestPollTailsRFC6962Log(t *testing.T) {
	ca := newTestCA(t)
	a := ca.leaf(t, 10, false, "a.owned.example")
	b := ca.leaf(t, 11, true, "b.owned.example")
	entries := []ctgo.LeafEntry{
		fakeLogEntry(t, ca, ca.leaf(t, 9, false, "other.example.org"), false, 1000),
		fakeLogEntry(t, ca, a, false, 2000),
		fakeLogEntry(t, ca, b, true, 3000),
		fakeLogEntry(t, ca, ca.leaf(t, 12, false, "owned.example.example.net"), false, 4000),
		fakeLogEntry(t, ca, a, false, 5000), // the same certificate logged again
	}
	srv := fakeRFC6962(t, entries, 2)
	clk := clock.NewFake(t0)
	l, err := NewRFC6962Log(srv.URL, nil, nil, clk, LogPoliteness, "test")
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := ParseDomains([]string{"owned.example"})
	p := &Poller{Domains: ds, Logs: []Log{l}, Clock: clk}
	st := NewState()
	c := p.Poll(context.Background(), st)
	if len(c.Errors) != 0 {
		t.Fatal(c.Errors)
	}
	if len(c.Found) != 2 {
		t.Fatalf("found %d, want 2", len(c.Found))
	}
	wantIdx := []int64{1, 2}
	wantType := []string{EntryX509, EntryPrecert}
	wantLeaf := [][]byte{a, b}
	for i, f := range c.Found {
		ev := f.Evidence
		if ev.Source != SourceRFC6962 || *ev.EntryIndex != wantIdx[i] || ev.EntryType != wantType[i] || ev.Endpoint != srv.URL {
			t.Errorf("found %d: evidence %+v", i, ev)
		}
		// The logged certificate or precertificate comes first, then the
		// chain the entry carried.
		if len(f.Chain) != 2 || !bytes.Equal(f.Chain[0], wantLeaf[i]) || !bytes.Equal(f.Chain[1], ca.der) {
			t.Errorf("found %d: chain of %d, not the logged entry first", i, len(f.Chain))
		}
		if !ev.Timestamp.Equal(time.UnixMilli(int64(1000 * (wantIdx[i] + 1)))) {
			t.Errorf("found %d: timestamp %v", i, ev.Timestamp)
		}
	}
	if s := c.Stats[SourceRFC6962]; s.Matched != 3 || s.New != 2 {
		t.Fatalf("stats %+v", s)
	}
	c.Commit(st)
	if st.LogNext[srv.URL] != 5 {
		t.Fatalf("next index %d, want 5", st.LogNext[srv.URL])
	}
}

func TestPollStartsNewLogAtHead(t *testing.T) {
	ca := newTestCA(t)
	srv := fakeRFC6962(t, []ctgo.LeafEntry{fakeLogEntry(t, ca, ca.leaf(t, 2, false, "a.owned.example"), false, 1)}, 10)
	clk := clock.NewFake(t0)
	l, _ := NewRFC6962Log(srv.URL, nil, nil, clk, LogPoliteness, "test")
	ds, _ := ParseDomains([]string{"owned.example"})
	p := &Poller{Domains: ds, Logs: []Log{l}, Clock: clk, StartAtHead: true}
	st := NewState()
	c := p.Poll(context.Background(), st)
	c.Commit(st)
	if len(c.Found) != 0 || st.LogNext[srv.URL] != 1 {
		t.Fatalf("found %d, next %d", len(c.Found), st.LogNext[srv.URL])
	}
}

func TestPollTailsStaticCTLog(t *testing.T) {
	srv := newFakeStatic(t, false)
	clk := clock.NewFake(t0)
	ds, _ := ParseDomains([]string{"flowers-to-the-world.com"})
	p := &Poller{Domains: ds, Logs: []Log{NewStaticLog(srv.URL+"/log", nil, nil, clk, LogPoliteness, "test")}, Clock: clk}
	c := p.Poll(context.Background(), NewState())
	if len(c.Errors) != 0 {
		t.Fatal(c.Errors)
	}
	if len(c.Found) != 4 {
		t.Fatalf("found %d, want 4", len(c.Found))
	}
	for i, f := range c.Found {
		if f.Evidence.Source != SourceStaticCT || *f.Evidence.EntryIndex != int64(i) || len(f.Chain) != 3 {
			t.Errorf("entry %d: %+v chain %d", i, f.Evidence, len(f.Chain))
		}
	}
}

// fakeCrtSh answers the search with the recorded crt.sh fixture and every
// download with one of the recorded Cert Spotter certificates (as PEM).
func fakeCrtSh(t *testing.T, ders [][]byte) *httptest.Server {
	t.Helper()
	search := mustRead(t, "testdata/crtsh/search-owned.example.json")
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("d") != "" {
			i := n.Add(1) - 1
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: ders[int(i)%len(ders)]})
			return
		}
		_, _ = w.Write(search)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fixtureDERs(t *testing.T) [][]byte {
	t.Helper()
	var items []Issuance
	if err := json.Unmarshal(mustRead(t, csFixture), &items); err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, it := range items {
		out = append(out, it.CertDER)
	}
	return out
}

// TestCrtShOnlyAsFallback: crt.sh is not queried while Cert Spotter works,
// and is queried (rate limited) when Cert Spotter is out of quota.
func TestCrtShOnlyAsFallback(t *testing.T) {
	cs := newFakeCertSpotter(t, csFixture, 100)
	var crtHits atomic.Int64
	crt := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { crtHits.Add(1) }))
	defer crt.Close()
	clk := clock.NewFake(t0)
	ds, _ := ParseDomains([]string{"owned.example"})
	p := &Poller{Domains: ds, CertSpotter: NewCertSpotter(cs.URL, nil, clk, CertSpotterPoliteness, "test", nil), CrtSh: NewCrtSh(crt.URL, nil, clk, CrtShPoliteness, "test"), Clock: clk}
	if c := p.Poll(context.Background(), NewState()); len(c.Found) != 4 || crtHits.Load() != 0 {
		t.Fatalf("found %d, crt.sh hits %d", len(c.Found), crtHits.Load())
	}

	cs.mu.Lock()
	cs.status, cs.retryAfter = http.StatusTooManyRequests, "3600"
	cs.mu.Unlock()
	crtFake := fakeCrtSh(t, fixtureDERs(t)[:2])
	clk = clock.NewFake(t0)
	p = &Poller{
		Domains:         ds,
		CertSpotter:     NewCertSpotter(cs.URL, nil, clk, CertSpotterPoliteness, "test", nil),
		CrtSh:           NewCrtSh(crtFake.URL, nil, clk, CrtShPoliteness, "test"),
		MaxCrtShFetches: 3,
		Clock:           clk,
	}
	c := p.Poll(context.Background(), NewState())
	if c.Stats[SourceCertSpotter].Errors != 1 {
		t.Fatalf("cert spotter errors %d", c.Stats[SourceCertSpotter].Errors)
	}
	s := c.Stats[SourceCrtSh]
	// Three downloads (budget), two distinct certificates: deduped by fingerprint.
	if s.Matched != 3 || s.New != 2 {
		t.Fatalf("crt.sh stats %+v", s)
	}
	// search + 3 downloads, each at least 10 s apart.
	if got, want := clk.Sleeps(), []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sleeps %v, want %v", got, want)
	}
}

func TestComputeCoverage(t *testing.T) {
	var rows []CrtShEntry
	if err := json.Unmarshal(mustRead(t, "testdata/crtsh/search-owned.example.json"), &rows); err != nil {
		t.Fatal(err)
	}
	srv := newFakeCertSpotter(t, csFixture, 100)
	clk := clock.NewFake(t0)
	ds, _ := ParseDomains([]string{"owned.example"})
	p := &Poller{Domains: ds, CertSpotter: NewCertSpotter(srv.URL, nil, clk, CertSpotterPoliteness, "test", nil), Clock: clk}
	c := p.Poll(context.Background(), NewState())
	cov := ComputeCoverage("owned.example", c.Found, rows)
	// The recorded crt.sh answer lists 10 unexpired certificates (17 rows:
	// precertificate and certificate rows share a serial); two of the four
	// recorded Cert Spotter issuances are among them (serials compare equal
	// despite crt.sh's leading zeros) and two are newer than crt.sh's data.
	if cov.BaselineCerts != 10 || cov.CoveredCerts != 2 || cov.ExtraCerts != 2 || cov.BaselineNames != 10 || cov.CoveredNames != 5 {
		t.Fatalf("coverage %+v", cov)
	}
	if cov.CertPercent() != 20 || cov.NamePercent() != 50 {
		t.Fatalf("percentages %.1f %.1f", cov.CertPercent(), cov.NamePercent())
	}
	full := ComputeCoverage("owned.example", nil, nil)
	if full.CertPercent() != 100 {
		t.Fatal("an empty baseline is fully covered")
	}
	var buf bytes.Buffer
	cov.Write(&buf)
	if !strings.Contains(buf.String(), "certificates:  2 of 10 crt.sh baseline (20.0 %)") {
		t.Fatalf("report %q", buf.String())
	}
}

// TestObservationsSubmittedToFakeCore is the end-to-end check: certificates
// from every source type (Cert Spotter, an RFC 6962 log, a static-ct log
// and the crt.sh fallback) become observations in the core's contract
// shape, batched and gzip-submitted to a fake core that validates them
// against the vendored collector.yaml and accepts every one of them.
func TestObservationsSubmittedToFakeCore(t *testing.T) {
	ca := newTestCA(t)
	cs := newFakeCertSpotter(t, csFixture, 2)
	newCert := ca.leaf(t, 20, false, "new.owned.example")
	preCert := ca.leaf(t, 21, true, "pre.owned.example")
	log := fakeRFC6962(t, []ctgo.LeafEntry{
		fakeLogEntry(t, ca, newCert, false, 1),
		fakeLogEntry(t, ca, preCert, true, 2),
	}, 10)
	static := newFakeStatic(t, false)
	crt := fakeCrtSh(t, fixtureDERs(t)[:2])
	core, err := submittest.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	clk := clock.NewFake(t0)
	rl, _ := NewRFC6962Log(log.URL, nil, nil, clk, LogPoliteness, "test")
	staticLogID := sha256.Sum256([]byte("static log key"))
	ds, _ := ParseDomains([]string{"owned.example", "flowers-to-the-world.com"})
	p := &Poller{
		Domains:     ds,
		CertSpotter: NewCertSpotter(cs.URL, nil, clk, CertSpotterPoliteness, "test", nil),
		Logs:        []Log{rl, NewStaticLog(static.URL+"/log", staticLogID[:], nil, clk, LogPoliteness, "test")},
		Clock:       clk,
	}
	st := NewState()
	cycle := p.Poll(context.Background(), st)
	if len(cycle.Errors) != 0 {
		t.Fatal(cycle.Errors)
	}
	// crt.sh is a fallback only: a second poller without Cert Spotter uses it.
	fallback := &Poller{Domains: Domains{"owned.example"}, CrtSh: NewCrtSh(crt.URL, nil, clk, CrtShPoliteness, "test"), MaxCrtShFetches: 2, Clock: clk}
	crtCycle := fallback.Poll(context.Background(), NewState())
	if len(crtCycle.Errors) != 0 {
		t.Fatal(crtCycle.Errors)
	}
	obs := append(cycle.Observations(), crtCycle.Observations()...)
	if len(obs) != 4+2+4+2 {
		t.Fatalf("%d observations, want 12", len(obs))
	}
	sub, err := submit.New(core.URL, core.Client(), submit.WithClock(clk), submit.WithBatchSize(5))
	if err != nil {
		t.Fatal(err)
	}
	res, err := sub.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("submit: %v (core errors %v)", err, core.Errors())
	}
	if res.Batches != 3 || res.Accepted != 12 || len(res.Rejected) != 0 || len(core.Errors()) != 0 {
		t.Fatalf("result %+v, core errors %v", res, core.Errors())
	}

	// Each source's target is the host and port of the service that was read.
	hostPort := func(u string) string { return strings.TrimPrefix(u, "http://") }
	sources := map[string]int{}
	for _, b := range core.Batches() {
		var batch submit.ObservationBatch
		if err := json.Unmarshal(b, &batch); err != nil {
			t.Fatal(err)
		}
		for _, o := range batch.Observations {
			e := o.CTEntry
			if o.Method != submit.MethodCT || o.Outcome != submit.OutcomeCertSeen || o.Target.Kind != submit.KindCTLog || o.Target.SNI != "" || e == nil {
				t.Fatalf("observation %+v", o)
			}
			target := o.Target.Host + ":" + strconv.Itoa(o.Target.Port)
			sources[e.Source+" "+target]++
			if len(o.ServedChain) == 0 {
				t.Fatal("no served_chain")
			}
			switch e.Source {
			case submit.CTSourceLog:
				if e.EntryIndex == nil || e.Timestamp == nil {
					t.Fatalf("log entry without index or timestamp: %+v", e)
				}
				switch target {
				case hostPort(static.URL):
					if !bytes.Equal(e.LogID, staticLogID[:]) || len(o.ServedChain) != 3 {
						t.Fatalf("static-ct entry: log id %x, chain %d", e.LogID, len(o.ServedChain))
					}
				case hostPort(log.URL):
					// The log key is not configured: no log id.
					if e.LogID != nil || len(o.ServedChain) != 2 || !bytes.Equal(o.ServedChain[1], ca.der) {
						t.Fatalf("RFC 6962 entry: log id %x, chain %d", e.LogID, len(o.ServedChain))
					}
					if want := map[int64][]byte{0: newCert, 1: preCert}[*e.EntryIndex]; !bytes.Equal(o.ServedChain[0], want) {
						t.Fatalf("RFC 6962 entry %d: the logged (pre)certificate is not first", *e.EntryIndex)
					}
				default:
					t.Fatalf("log target %s", target)
				}
			case submit.CTSourceCertSpotter, submit.CTSourceCrtSh:
				// A search service names no log entry.
				if e.LogID != nil || e.EntryIndex != nil || e.Timestamp != nil || len(o.ServedChain) != 1 {
					t.Fatalf("search-service entry %+v, chain %d", e, len(o.ServedChain))
				}
			default:
				t.Fatalf("source %q", e.Source)
			}
		}
	}
	want := map[string]int{
		"cert_spotter " + hostPort(cs.URL): 4,
		"log " + hostPort(log.URL):         2,
		"log " + hostPort(static.URL):      4,
		"crt_sh " + hostPort(crt.URL):      2,
	}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("sources %v, want %v", sources, want)
	}
	cycle.Commit(st)
	if again := p.Poll(context.Background(), st); len(again.Found) != 0 {
		t.Fatalf("second cycle found %d new", len(again.Found))
	}
}

func TestEndpointTarget(t *testing.T) {
	for in, want := range map[string]submit.Target{
		"https://api.certspotter.com":                  {Kind: submit.KindCTLog, Host: "api.certspotter.com", Port: 443},
		"https://ct.googleapis.com/logs/us1/argon2026": {Kind: submit.KindCTLog, Host: "ct.googleapis.com", Port: 443},
		"http://127.0.0.1:8080/log":                    {Kind: submit.KindCTLog, Host: "127.0.0.1", Port: 8080},
		"http://crt.example":                           {Kind: submit.KindCTLog, Host: "crt.example", Port: 80},
	} {
		if got := endpointTarget(in); got != want {
			t.Errorf("endpointTarget(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestDomains(t *testing.T) {
	ds, err := ParseDomains([]string{"Owned.EXAMPLE.", " partner.example", "owned.example", ""})
	if err != nil || !reflect.DeepEqual(ds, Domains{"owned.example", "partner.example"}) {
		t.Fatalf("%v %v", ds, err)
	}
	for name, want := range map[string]string{
		"owned.example": "owned.example", "WWW.owned.example": "owned.example", "*.x.owned.example": "owned.example",
		"notowned.example": "", "owned.example.evil.example": "", "partner.example": "partner.example",
	} {
		if got := ds.Match(name); got != want {
			t.Errorf("Match(%q) = %q, want %q", name, got, want)
		}
	}
	for _, bad := range []string{"*.owned.example", "localhost", "a b.com", "https://x.com"} {
		if _, err := ParseDomains([]string{bad}); err == nil {
			t.Errorf("ParseDomains(%q) accepted", bad)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := t.TempDir() + "/ct/state.json"
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	st.CertSpotterAfter["owned.example"] = "42"
	st.LogNext["https://log.example/"] = 7
	st.Seen["ab"] = t0
	st.Seen["old"] = t0.Add(-500 * 24 * time.Hour)
	st.prune(t0)
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertSpotterAfter["owned.example"] != "42" || got.LogNext["https://log.example/"] != 7 || len(got.Seen) != 1 {
		t.Fatalf("state %+v", got)
	}
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{
		"MEISCOPE_CT_DOMAINS":        "owned.example, partner.example",
		"MEISCOPE_CT_LOGS":           "rfc6962=https://ct.example/log/,static=https://mon.example/2026h2/",
		"MEISCOPE_CT_CRTSH_FALLBACK": "false",
		"MEISCOPE_CT_CONTACT":        "ops@example.com",
	}
	cfg, err := LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 2 || len(cfg.Logs) != 2 || cfg.CrtShFallback || !cfg.CertSpotter || !strings.Contains(cfg.UserAgent(), "ops@example.com") {
		t.Fatalf("config %+v", cfg)
	}
	p, err := cfg.NewPoller(nil, clock.NewFake(t0), credential.None{})
	if err != nil || len(p.Logs) != 2 || p.CrtSh != nil || p.CertSpotter == nil {
		t.Fatalf("poller %+v, %v", p, err)
	}
	for k, v := range map[string]string{"MEISCOPE_CT_LOGS": "tiled=https://x", "MEISCOPE_CT_DOMAINS": "*.x.com", "MEISCOPE_CT_MAX_ENTRIES_PER_LOG": "0", "MEISCOPE_CT_CERTSPOTTER_URL": "ftp://x"} {
		if _, err := LoadConfig(func(key string) string {
			if key == k {
				return v
			}
			return ""
		}); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}

func TestRFC6962EntriesRefuseOutOfRangeIndex(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer srv.Close()
	l, err := NewRFC6962Log(srv.URL, nil, nil, clock.NewFake(t0), LogPoliteness, "test")
	if err != nil {
		t.Fatal(err)
	}
	// A hostile log can report any tree size; indices above 2^63-1 must be refused, not wrapped.
	for _, start := range []uint64{1 << 63, math.MaxUint64 - 1} {
		if _, err := l.Entries(context.Background(), start, math.MaxUint64); err == nil {
			t.Errorf("start %d: want an error, got nil", start)
		}
	}
	if requests != 0 {
		t.Errorf("the log was contacted %d times; want 0", requests)
	}
}
