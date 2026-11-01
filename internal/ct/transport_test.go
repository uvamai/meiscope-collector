package ct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/clock"
)

// scripted answers requests from a list of (status, Retry-After, body) and
// records the fake-clock time of each request.
type scripted struct {
	*httptest.Server
	mu    sync.Mutex
	times []time.Time
	paths []string
}

type answer struct {
	status     int
	retryAfter string
	body       string
}

func newScripted(t *testing.T, clk clock.Clock, answers ...answer) *scripted {
	t.Helper()
	s := &scripted{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		n := len(s.times)
		s.times = append(s.times, clk.Now())
		s.paths = append(s.paths, r.URL.RequestURI())
		s.mu.Unlock()
		a := answers[min(n, len(answers)-1)]
		if a.retryAfter != "" {
			w.Header().Set("Retry-After", a.retryAfter)
		}
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *scripted) offsets() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Duration, len(s.times))
	for i, tm := range s.times {
		out[i] = tm.Sub(t0)
	}
	return out
}

const pemCert = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"

// TestCrtShBacksOffOn429 proves the crt.sh fallback's politeness with a fake
// clock: Retry-After is honoured, a 429 without it backs off exponentially,
// and requests are never closer than 10 s.
func TestCrtShBacksOffOn429(t *testing.T) {
	clk := clock.NewFake(t0)
	srv := newScripted(t, clk,
		answer{status: 429, retryAfter: "45"},
		answer{status: 429},
		answer{status: 200, body: `[{"id":1,"serial_number":"0a","name_value":"a.owned.example","common_name":"a.owned.example"}]`},
		answer{status: 200, body: pemCert},
	)
	c := NewCrtSh(srv.URL, nil, clk, CrtShPoliteness, "test")
	rows, err := c.Search(context.Background(), "owned.example")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v, err %v", rows, err)
	}
	if _, err := c.Certificate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	// Request 1 at 0 s; 429 with Retry-After 45 s (> the 30 s base) -> 45 s;
	// 429 without Retry-After -> second back-off step 60 s; 200. The
	// certificate download then waits the 10 s minimum interval.
	wantSleeps := []time.Duration{45 * time.Second, 60 * time.Second, 10 * time.Second}
	if got := clk.Sleeps(); !reflect.DeepEqual(got, wantSleeps) {
		t.Fatalf("sleeps %v, want %v", got, wantSleeps)
	}
	wantAt := []time.Duration{0, 45 * time.Second, 105 * time.Second, 115 * time.Second}
	if got := srv.offsets(); !reflect.DeepEqual(got, wantAt) {
		t.Fatalf("requests at %v, want %v", got, wantAt)
	}
}

func TestCrtShGivesUpAfterRetries(t *testing.T) {
	clk := clock.NewFake(t0)
	srv := newScripted(t, clk, answer{status: 429})
	c := NewCrtSh(srv.URL, nil, clk, CrtShPoliteness, "test")
	_, err := c.Search(context.Background(), "owned.example")
	if !IsStatus(err, 429) {
		t.Fatalf("want a 429 StatusError, got %v", err)
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute}
	if got := clk.Sleeps(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sleeps %v, want %v", got, want)
	}
	if n := len(srv.offsets()); n != 5 {
		t.Fatalf("%d requests, want 1 + 4 retries", n)
	}
}

func TestLongRetryAfterEndsTheAttempt(t *testing.T) {
	clk := clock.NewFake(t0)
	// The Cert Spotter free tier answers 429 with Retry-After up to an hour;
	// the poll does not hang for it (crt.sh is tried instead).
	srv := newScripted(t, clk, answer{status: 429, retryAfter: "3600"})
	c := NewCrtSh(srv.URL, nil, clk, CertSpotterPoliteness, "test")
	_, err := c.Search(context.Background(), "owned.example")
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != 429 || se.RetryAfter != time.Hour {
		t.Fatalf("want 429 with retry after 1h, got %v", err)
	}
	if len(clk.Sleeps()) != 0 || len(srv.offsets()) != 1 {
		t.Fatalf("sleeps %v, requests %d", clk.Sleeps(), len(srv.offsets()))
	}
}

func TestRetryAfterHTTPDateWithUTC(t *testing.T) {
	clk := clock.NewFake(t0)
	// A static-ct log was seen sending "UTC" instead of "GMT".
	srv := newScripted(t, clk,
		answer{status: 503, retryAfter: t0.Add(20*time.Second).Format("Mon, 02 Jan 2006 15:04:05") + " UTC"},
		answer{status: 200, body: "[]"},
	)
	c := NewCrtSh(srv.URL, nil, clk, LogPoliteness, "test")
	if _, err := c.Search(context.Background(), "owned.example"); err != nil {
		t.Fatal(err)
	}
	if got := clk.Sleeps(); !reflect.DeepEqual(got, []time.Duration{20 * time.Second}) {
		t.Fatalf("sleeps %v", got)
	}
}

func TestTransportIsReadOnlyAndSetsUserAgent(t *testing.T) {
	uas := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { uas <- r.Header.Get("User-Agent") }))
	defer srv.Close()
	hc := newHTTPClient(nil, clock.NewFake(t0), Politeness{}, "meiscope-collector/test")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, http.NoBody)
	if resp, err := hc.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("POST through the CT transport must fail")
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ua := <-uas; ua != "meiscope-collector/test" {
		t.Fatalf("User-Agent %q", ua)
	}
}
