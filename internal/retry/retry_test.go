package retry

import (
	"net/http"
	"testing"
	"time"
)

func TestDelayDoublesAndCaps(t *testing.T) {
	p := Policy{Base: time.Second, Max: 10 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for n, w := range want {
		if got := p.Delay(n); got != w {
			t.Errorf("Delay(%d) = %s, want %s", n, got, w)
		}
	}
}

func TestWaitHonoursRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	p := Policy{Base: time.Second, Max: time.Minute, MaxRetryAfter: 2 * time.Minute}
	cases := []struct {
		h    string
		want time.Duration
		ok   bool
	}{
		{"", time.Second, true},
		{"30", 30 * time.Second, true},
		{"0", time.Second, true}, // never sooner than our own back-off
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{"Sat, 24 Oct 2026 10:00:20 UTC", 20 * time.Second, true},
		{"3600", time.Hour, false},
		{"soon", time.Second, true}, // unparseable: ignored
	}
	for _, c := range cases {
		h := http.Header{}
		if c.h != "" {
			h.Set("Retry-After", c.h)
		}
		got, ok := p.Wait(0, h, now)
		if got != c.want || ok != c.ok {
			t.Errorf("Retry-After %q: got %s %v, want %s %v", c.h, got, ok, c.want, c.ok)
		}
	}
}

func TestRetryable(t *testing.T) {
	for code, want := range map[int]bool{200: false, 400: false, 404: false, 429: true, 500: true, 501: false, 502: true, 503: true, 504: true} {
		if Retryable(code) != want {
			t.Errorf("Retryable(%d) != %v", code, want)
		}
	}
}
