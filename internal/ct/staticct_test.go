package ct

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/clock"
)

const willow = "testdata/staticct/willow2026h2/"

func TestParseCheckpointRecorded(t *testing.T) {
	cp, err := ParseCheckpoint(mustRead(t, willow+"checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != "log.willow.ct.letsencrypt.org/2026h2" || cp.TreeSize != 992849523 {
		t.Fatalf("checkpoint %+v", cp)
	}
	for _, bad := range []string{"", "origin\n12\n", "origin\nx\nAAAA\n\n— sig\n", "origin\n1\nAAAA\n\n— sig\n"} {
		if _, err := ParseCheckpoint([]byte(bad)); err == nil {
			t.Errorf("ParseCheckpoint(%q) accepted", bad)
		}
	}
}

func TestTilePath(t *testing.T) {
	cases := map[string]string{
		TilePath(0, 256):       "tile/data/000",
		TilePath(0, 4):         "tile/data/000.p/4",
		TilePath(1234067, 0):   "tile/data/x001/x234/067",
		TilePath(1000, 255):    "tile/data/x001/000.p/255",
		TilePath(3878318, 256): "tile/data/x003/x878/318",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

// fakeStatic serves a static-ct log from the recorded fixtures: a checkpoint
// of size 4, the first four real entries of Willow 2026h2 tile 0 as the
// partial tile 000.p/4 (or, with fullOnly, as tile 000 with a 404 on the
// partial path), and the two recorded issuers.
type fakeStatic struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newFakeStatic(t *testing.T, fullOnly bool) *fakeStatic {
	t.Helper()
	tile := mustRead(t, willow+"tile-data-000-first4.bin")
	issuers := map[string][]byte{}
	for _, fp := range []string{"86d8219c7e2b6009e37eb14356268489b81379e076e8f372e3dde8c162a34134", "adb4a7e96552b132901fa13917b030bb8e0f9afe391416c4abd6598a63d09925"} {
		issuers["/log/issuer/"+fp] = mustRead(t, willow+"issuer/"+fp)
	}
	f := &fakeStatic{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		switch p := r.URL.Path; {
		case p == "/log/checkpoint":
			_, _ = w.Write([]byte("log.willow.ct.letsencrypt.org/2026h2\n4\n/QT4DHdl8uYZ92Zw/eUsI5857Dt1wPP/dtdWW0S6XJ4=\n\n— log.willow.ct.letsencrypt.org/2026h2 AAAA\n"))
		case p == "/log/tile/data/000.p/4" && !fullOnly, p == "/log/tile/data/000" && fullOnly:
			_, _ = w.Write(tile)
		case p == "/log/tile/data/000.p/4" && fullOnly:
			// Object stores answer 403 for a missing object.
			http.Error(w, "AccessDenied", http.StatusForbidden)
		case issuers[p] != nil:
			_, _ = w.Write(issuers[p])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeStatic) requested(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if p == path {
			n++
		}
	}
	return n
}

func TestStaticCTReadsRecordedTile(t *testing.T) {
	for _, fullOnly := range []bool{false, true} {
		srv := newFakeStatic(t, fullOnly)
		l := NewStaticLog(srv.URL+"/log/", nil, nil, clock.NewFake(t0), Politeness{}, "test")
		size, err := l.TreeSize(context.Background())
		if err != nil || size != 4 {
			t.Fatalf("tree size %d, %v", size, err)
		}
		entries, err := l.Entries(context.Background(), 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 3 {
			t.Fatalf("got %d entries, want 3 (indices 1..3)", len(entries))
		}
		wantTypes := []string{EntryX509, EntryPrecert, EntryX509}
		for i, e := range entries {
			if e.Index != uint64(i+1) || e.Type != wantTypes[i] {
				t.Errorf("entry %d: index %d type %s", i, e.Index, e.Type)
			}
			if !bytes.HasPrefix(e.LeafInput, []byte{0, 0}) || len(e.chainFPs) != 2 {
				t.Errorf("entry %d: leaf input or chain fingerprints wrong", i)
			}
			if err := l.ResolveChain(context.Background(), &e); err != nil {
				t.Fatal(err)
			}
			if len(e.Chain) != 2 {
				t.Errorf("entry %d: chain of %d", i, len(e.Chain))
			}
		}
		for _, fp := range []string{"86d8219c7e2b6009e37eb14356268489b81379e076e8f372e3dde8c162a34134", "adb4a7e96552b132901fa13917b030bb8e0f9afe391416c4abd6598a63d09925"} {
			if n := srv.requested("/log/issuer/" + fp); n != 1 {
				t.Errorf("issuer %s fetched %d times, want 1 (cached)", fp[:8], n)
			}
		}
		if fullOnly && srv.requested("/log/tile/data/000.p/4") != 1 {
			t.Error("expected the partial tile to be tried first")
		}
		// A poll budget that ends inside the tile still reads the tile as
		// published (.p/4 at tree size 4), never a partial tile that does
		// not exist (.p/2).
		two, err := l.Entries(context.Background(), 0, 2)
		if err != nil || len(two) != 2 || two[1].Index != 1 {
			t.Fatalf("Entries(0, 2): %d entries, %v", len(two), err)
		}
		if srv.requested("/log/tile/data/000.p/2") != 0 {
			t.Error("requested a partial tile that was never published")
		}
	}
}

func TestStaticCTRejectsBadData(t *testing.T) {
	tile := mustRead(t, willow+"tile-data-000-first4.bin")
	if _, _, err := parseTileLeaf(tile[:100]); err == nil {
		t.Error("truncated leaf accepted")
	}
	// A wrong issuer body must not match its fingerprint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not the issuer")) }))
	defer srv.Close()
	l := NewStaticLog(srv.URL, nil, nil, clock.NewFake(t0), Politeness{}, "test")
	e, _, err := parseTileLeaf(tile)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ResolveChain(context.Background(), &e); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint mismatch, got %v", err)
	}
}
