package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/retry"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// Fleet REST endpoints used (Fleet 4.x, /api/v1/fleet): the saved-query
// list and each saved query's report (the latest result rows per host).
const (
	// Fleet 4.93 deprecates the saved-query endpoints in favour of /reports
	// (same shapes); the adapter prefers /reports and falls back to /queries
	// on a Fleet without it.
	fleetReportsPath = "/api/v1/fleet/reports"
	fleetQueriesPath = "/api/v1/fleet/queries"
	maxFleetBody     = 256 << 20
)

var fleetRetry = retry.Policy{Attempts: 3, Base: time.Second, Max: 30 * time.Second, MaxRetryAfter: 2 * time.Minute}

// fleetCursor holds, per query and host, the last_fetched time already
// ingested; a report row is new when Fleet fetched it later.
type fleetCursor struct {
	Fetched map[string]time.Time `json:"fetched"`
}

type fleetQueryList struct {
	Queries []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"queries"`
	Meta *struct {
		HasNextResults bool `json:"has_next_results"`
	} `json:"meta"`
}

type fleetReport struct {
	QueryID       int64 `json:"query_id"`
	ReportClipped bool  `json:"report_clipped"`
	Results       []struct {
		HostID      int64          `json:"host_id"`
		HostName    string         `json:"host_name"`
		LastFetched *time.Time     `json:"last_fetched"`
		Columns     map[string]any `json:"columns"`
	} `json:"results"`
}

// ErrFleetAPI marks a Fleet that lacks the saved-query report API.
var ErrFleetAPI = errors.New("this Fleet does not offer the saved-query report API (GET /api/v1/fleet/queries/{id}/report, Fleet 4.4x and later)")

func fleetQueries(cfg adapter.Config) []string {
	if qs := splitList(cfg.Setting("queries", "")); len(qs) > 0 {
		return qs
	}
	return QueryNames(limitsOf(cfg))
}

type fleetClient struct {
	base  *url.URL
	hc    *http.Client
	token credential.Secret
	lim   *adapter.Limiter
	a     *Adapter
	// family is the endpoint family in use, set by detectFamily.
	family string
}

// statusError is a non-retryable HTTP answer of Fleet.
type statusError struct {
	path   string
	status int
}

func (e *statusError) Error() string { return fmt.Sprintf("fleet: GET %s: HTTP %d", e.path, e.status) }

// detectFamily picks the reports endpoints when Fleet has them.
func (fc *fleetClient) detectFamily(ctx context.Context) error {
	var probe fleetQueryList
	err := fc.get(ctx, fleetReportsPath, url.Values{"page": {"0"}, "per_page": {"1"}}, &probe)
	var se *statusError
	switch {
	case err == nil:
		fc.family = fleetReportsPath
	case errors.As(err, &se) && se.status == http.StatusNotFound:
		fc.family = fleetQueriesPath
	default:
		return err
	}
	return nil
}

func (a *Adapter) syncFleet(ctx context.Context, cfg adapter.Config, since adapter.Cursor) (adapter.Result, error) {
	cur := fleetCursor{Fetched: map[string]time.Time{}}
	if err := adapter.DecodeCursor(since, &cur); err != nil {
		return adapter.Result{}, err
	}
	if cur.Fetched == nil {
		cur.Fetched = map[string]time.Time{}
	}
	base, err := url.Parse(cfg.Setting("url", ""))
	if err != nil {
		return adapter.Result{}, errors.New("fleet: invalid url")
	}
	// The token is read just in time and lives only for this sync (ADR-0009).
	token, err := cfg.Credential(ctx, a.env.Creds, "api_token")
	if err != nil {
		return adapter.Result{}, fmt.Errorf("fleet: %w", err)
	}
	hc := a.env.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	rate := 5.0
	if v, err := strconv.ParseFloat(cfg.Setting("rate_per_second", ""), 64); err == nil && v > 0 {
		rate = v
	}
	fc := &fleetClient{base: base, hc: hc, token: token, lim: adapter.NewLimiter(a.env.Clock, rate), a: a}

	if err := fc.detectFamily(ctx); err != nil {
		return adapter.Result{}, err
	}
	ids, err := fc.queryIDs(ctx, cfg)
	if err != nil {
		return adapter.Result{}, err
	}
	st := newStats()
	var obs []submit.Observation
	for _, name := range fleetQueries(cfg) {
		q, _ := queryOf(name)
		id, ok := ids[name]
		if !ok {
			return adapter.Result{}, fmt.Errorf("fleet: no saved query named %s; apply packs/osquery/fleet-queries.yml", name)
		}
		var rep fleetReport
		if err := fc.get(ctx, fc.family+"/"+strconv.FormatInt(id, 10)+"/report", nil, &rep); err != nil {
			return adapter.Result{}, err
		}
		if rep.ReportClipped && a.env.Log != nil {
			a.env.Log.Warn("Fleet clipped the query report; some hosts' rows are missing", "query", name)
		}
		// A host's rows share one last_fetched; take each host's newest.
		newest := map[int64]time.Time{}
		for _, r := range rep.Results {
			if r.LastFetched != nil && r.LastFetched.After(newest[r.HostID]) {
				newest[r.HostID] = *r.LastFetched
			}
		}
		for _, r := range rep.Results {
			if r.LastFetched == nil {
				st["no_last_fetched"]++
				continue
			}
			k := name + "|" + strconv.FormatInt(r.HostID, 10)
			if !r.LastFetched.After(cur.Fetched[k]) || !r.LastFetched.Equal(newest[r.HostID]) {
				continue
			}
			if o, ok := mapRow(q, r.HostName, *r.LastFetched, toRow(r.Columns), st); ok {
				obs = append(obs, o)
			}
		}
		for host, t := range newest {
			k := name + "|" + strconv.FormatInt(host, 10)
			if t.After(cur.Fetched[k]) {
				cur.Fetched[k] = t.UTC()
			}
		}
	}
	c, err := adapter.EncodeCursor(cur)
	if err != nil {
		return adapter.Result{}, err
	}
	return a.result(ModeFleet, cfg, obs, st, c, since)
}

// queryIDs pages through the saved queries and returns the IDs by name.
func (fc *fleetClient) queryIDs(ctx context.Context, cfg adapter.Config) (map[string]int64, error) {
	perPage := intSetting(cfg, "per_page", 100)
	team := cfg.Setting("team_id", "")
	type item struct {
		id   int64
		name string
	}
	items, err := adapter.Paginate(ctx, 0, func(ctx context.Context, token string) (adapter.Page[item], error) {
		page := 0
		if token != "" {
			page, _ = strconv.Atoi(token)
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}, "order_key": {"name"}}
		if team != "" {
			q.Set("team_id", team)
		}
		var l fleetQueryList
		if err := fc.get(ctx, fc.family, q, &l); err != nil {
			return adapter.Page[item]{}, err
		}
		p := adapter.Page[item]{}
		for _, x := range l.Queries {
			p.Items = append(p.Items, item{x.ID, x.Name})
		}
		// Older Fleets have no meta: a short page ends the listing.
		more := len(l.Queries) == perPage
		if l.Meta != nil {
			more = l.Meta.HasNextResults
		}
		if more {
			p.Next = strconv.Itoa(page + 1)
		}
		return p, nil
	})
	if err != nil {
		return nil, fmt.Errorf("fleet: list saved queries: %w", err)
	}
	out := map[string]int64{}
	for _, it := range items {
		out[it.name] = it.id
	}
	return out, nil
}

// get performs an authenticated GET with rate limiting and retries. Errors
// name the path and status only, never the token.
func (fc *fleetClient) get(ctx context.Context, path string, q url.Values, out any) error {
	u := fc.base.JoinPath(path)
	u.RawQuery = q.Encode()
	clk := fc.a.env.Clock
	for attempt := 0; ; attempt++ {
		if err := fc.lim.Wait(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+fc.token.Reveal())
		resp, err := fc.hc.Do(req)
		var hdr http.Header
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("fleet: GET %s: %s", path, adapter.Redact(err.Error(), fc.token.Reveal()))
		case resp.StatusCode == http.StatusOK:
			derr := json.NewDecoder(io.LimitReader(resp.Body, maxFleetBody)).Decode(out)
			_ = resp.Body.Close()
			if derr != nil {
				return fmt.Errorf("fleet: GET %s: decode: %w", path, derr)
			}
			return nil
		case retry.Retryable(resp.StatusCode):
			hdr = resp.Header
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			err = fmt.Errorf("fleet: GET %s: HTTP %d", path, resp.StatusCode)
		default:
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound && strings.HasSuffix(path, "/report") {
				return fmt.Errorf("fleet: GET %s: HTTP 404: %w", path, ErrFleetAPI)
			}
			return &statusError{path: path, status: resp.StatusCode}
		}
		if attempt >= fleetRetry.Attempts {
			return fmt.Errorf("giving up after %d attempts: %w", attempt+1, err)
		}
		wait, ok := fleetRetry.Wait(attempt, hdr, clk.Now())
		if !ok {
			return err
		}
		if err := clk.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}
