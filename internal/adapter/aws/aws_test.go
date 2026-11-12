package aws_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/aws"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/clock"
	"github.com/uvamai/meiscope-collector/internal/credential"
	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

// Synthetic, low-entropy test values (not credentials).
const (
	testAKID  = "AKIDSYNTHETIC00000001"
	testSK    = "synthetic-sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testST    = "synthetic-st-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	arnWWW    = "arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000001"
	arnNew    = "arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000002"
	arnAPI    = "arn:aws:acm:us-east-1:111122223333:certificate/00000000-0000-4000-8000-000000000004"
	arnIAM    = "arn:aws:iam::111122223333:server-certificate/legacy-example-test"
	arnALB443 = "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:listener/app/web/0123456789abcdef/1111111111111111"
	arnNLB    = "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:listener/net/tls/0123456789abcdee/3333333333333333"
	idClassic = "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:loadbalancer/legacy/listener/443"
)

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, ref string) (credential.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return credential.Secret{}, credential.ErrNotFound
	}
	return credential.NewSecret(v), nil
}

type testEnv struct {
	env  adapter.Env
	clk  *clock.Fake
	logs *bytes.Buffer
}

func newEnv(t *testing.T, rt http.RoundTripper) testEnv {
	t.Helper()
	var logs bytes.Buffer
	clk := clock.NewFake(t0)
	return testEnv{
		env: adapter.Env{
			HTTP:  &http.Client{Transport: rt},
			Creds: mapSource{"aws_akid": testAKID, "aws_sk": testSK, "aws_st": testST},
			Clock: clk,
			Log:   slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			// The tests exercise the proposed shape; TestFeatureOff covers the default.
			Features: adapter.Features{CloudResourceV1: true},
		},
		clk: clk, logs: &logs,
	}
}

func config(settings map[string]string) adapter.Config {
	s := map[string]string{"regions": "ap-southeast-2,us-east-1", "rate_per_second": "100"}
	for k, v := range settings {
		s[k] = v
	}
	return adapter.Config{
		Name: "aws-prod", Adapter: aws.Name, Settings: s,
		Credentials: map[string]string{"access_key_id": "aws_akid", "secret_access_key": "aws_sk", "session_token": "aws_st"},
	}
}

func load(t *testing.T, scenario string) *fixture.Transport {
	t.Helper()
	tr, err := fixture.Load(fixture.Dir("aws", scenario))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func newAdapter(env adapter.Env) adapter.Adapter {
	f, ok := adapter.Lookup(aws.Name)
	if !ok {
		panic("aws not registered")
	}
	return f(env)
}

func syncOK(t *testing.T, a adapter.Adapter, cfg adapter.Config, since adapter.Cursor) adapter.Result {
	t.Helper()
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), cfg, since)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byID(obs []submit.Observation) map[string]submit.Observation {
	m := map[string]submit.Observation{}
	for _, o := range obs {
		m[o.Target.Cloud.ResourceID] = o
	}
	return m
}

func TestFullSync(t *testing.T) {
	tr := load(t, "synthetic-full")
	te := newEnv(t, tr)
	res := syncOK(t, newAdapter(te.env), config(nil), "")
	if len(res.Observations) != 7 {
		t.Fatalf("%d observations, want 7", len(res.Observations))
	}
	m := byID(res.Observations)

	www := m[arnWWW]
	if www.Outcome != submit.OutcomeCertSeen || len(www.ServedChain) != 2 || www.Adapter.Certificate == nil {
		t.Fatalf("www: %+v", www)
	}
	if www.Adapter.Certificate.SHA1 != "4deead0e7ed9127c63d0ca7ff25497d52b04301c" || www.Adapter.Certificate.CommonName != "www.example.test" {
		t.Errorf("www metadata %+v", www.Adapter.Certificate)
	}
	if r := www.Adapter.Renewal; r == nil || r.Mode != submit.RenewalExternalAutomated || r.ManagedBy != "aws_acm" || r.Status != "SUCCESS" || r.Eligibility != "ELIGIBLE" {
		t.Errorf("www renewal %+v", www.Adapter.Renewal)
	}
	if len(www.Adapter.Bindings) != 2 || www.Adapter.Bindings[0].Service != "elasticloadbalancing" {
		t.Errorf("www bindings %+v", www.Adapter.Bindings)
	}
	if c := www.Target.Cloud; c.Provider != "aws" || c.Service != "acm" || c.Region != "ap-southeast-2" || c.Account != "111122223333" || www.Target.Host != "acm.ap-southeast-2.amazonaws.com" {
		t.Errorf("www target %+v %+v", www.Target, c)
	}
	if !slices.Equal(www.Adapter.Hostnames, []string{"*.www.example.test", "www.example.test"}) {
		t.Errorf("www hostnames %v", www.Adapter.Hostnames)
	}
	if na := www.Adapter.CloudCertificate.NotAfter; na == nil || na.Unix() != 1828965531 {
		t.Errorf("www not_after %v", na)
	}

	pending := m[arnNew]
	if pending.Outcome != submit.OutcomeReached || pending.ServedChain != nil || pending.Adapter.Renewal.Mode != submit.RenewalUnknown {
		t.Errorf("pending: %+v %+v", pending, pending.Adapter.Renewal)
	}

	api := m[arnAPI]
	if api.Adapter.Renewal.Mode != submit.RenewalManual || api.Target.Cloud.Region != "us-east-1" || len(api.Adapter.Bindings) != 1 || api.Adapter.Bindings[0].Service != "cloudfront" {
		t.Errorf("imported: %+v %+v", api.Adapter.Renewal, api.Adapter.Bindings)
	}

	alb := m[arnALB443]
	if alb.Outcome != submit.OutcomeReached || alb.Adapter.Endpoint == nil || alb.Adapter.Endpoint.Port != 443 || alb.Adapter.Endpoint.Protocol != "HTTPS" || alb.Adapter.Endpoint.Scheme != "internet-facing" {
		t.Fatalf("alb: %+v", alb.Adapter.Endpoint)
	}
	if b := alb.Adapter.Bindings; len(b) != 2 || b[0].ResourceID != arnWWW || !*b[0].IsDefault || b[1].ResourceID != arnIAM || *b[1].IsDefault || b[1].Service != "iam" {
		t.Errorf("alb bindings %+v", alb.Adapter.Bindings)
	}
	if alb.Target.Cloud.Service != "elbv2_listener" {
		t.Errorf("alb service %s", alb.Target.Cloud.Service)
	}
	if nlb := m[arnNLB]; nlb.Adapter.Endpoint.Port != 8443 || nlb.Adapter.Endpoint.Protocol != "TLS" || len(nlb.Adapter.Bindings) != 1 {
		t.Errorf("nlb %+v %+v", nlb.Adapter.Endpoint, nlb.Adapter.Bindings)
	}
	if cl, ok := m[idClassic]; !ok || cl.Target.Cloud.Service != "elb_listener" || cl.Adapter.Bindings[0].ResourceID != arnIAM {
		t.Errorf("classic listener %+v", cl)
	}

	iam := m[arnIAM]
	if iam.Outcome != submit.OutcomeCertSeen || iam.Target.Cloud.Region != "" || iam.Target.Host != "iam.amazonaws.com" || iam.Adapter.Renewal.Mode != submit.RenewalManual {
		t.Errorf("iam %+v", iam)
	}
	if !slices.Equal(iam.Adapter.Hostnames, []string{"*.legacy.example.test", "legacy.example.test"}) {
		t.Errorf("iam hostnames %v", iam.Adapter.Hostnames)
	}

	submitAll(t, res.Observations)
	checkRequests(t, tr)
	checkNoSecrets(t, res, te.logs)
}

// submitAll sends the observations to a fake core for the proposed
// contract 0.10.0 and requires every one to be accepted.
func submitAll(t *testing.T, obs []submit.Observation) {
	t.Helper()
	core, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, err := submit.New(core.URL, core.Client())
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.Submit(context.Background(), obs)
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	if res.Accepted != len(obs) || len(res.Rejected) > 0 {
		t.Fatalf("accepted %d of %d, rejected %+v (%v)", res.Accepted, len(obs), res.Rejected, core.Rejected())
	}
}

// checkRequests: every request is a signed read to an AWS API host, signed
// for the region of its host (multi-region), with the session token signed.
func checkRequests(t *testing.T, tr *fixture.Transport) {
	t.Helper()
	hosts := map[string]bool{}
	for _, r := range tr.Requests() {
		hosts[r.URL.Hostname()] = true
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.URL.Scheme != "https" || !strings.HasSuffix(r.URL.Hostname(), ".amazonaws.com") {
			t.Errorf("request to %s", r.URL)
		}
		auth := r.Header.Get("Authorization")
		region := "us-east-1"
		if p := strings.Split(r.URL.Hostname(), "."); len(p) == 4 {
			region = p[1]
		}
		if !strings.Contains(auth, "/"+region+"/") || !strings.Contains(auth, "x-amz-security-token") || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+testAKID+"/") {
			t.Errorf("%s: authorization %s", r.URL.Hostname(), auth)
		}
		if r.Header.Get("X-Amz-Security-Token") != testST {
			t.Errorf("%s: no session token", r.URL.Hostname())
		}
		if op := r.URL.Query().Get("Action"); op != "" && !slices.Contains([]string{"DescribeLoadBalancers", "DescribeListeners", "DescribeListenerCertificates", "ListServerCertificates", "GetServerCertificate"}, op) {
			t.Errorf("unexpected action %s", op)
		}
		if tgt := r.Header.Get("X-Amz-Target"); tgt != "" && !slices.Contains([]string{"CertificateManager.ListCertificates", "CertificateManager.DescribeCertificate", "CertificateManager.GetCertificate"}, tgt) {
			t.Errorf("unexpected target %s", tgt)
		}
	}
	for _, h := range []string{"acm.ap-southeast-2.amazonaws.com", "acm.us-east-1.amazonaws.com", "elasticloadbalancing.ap-southeast-2.amazonaws.com", "elasticloadbalancing.us-east-1.amazonaws.com", "iam.amazonaws.com"} {
		if !hosts[h] {
			t.Errorf("no request to %s", h)
		}
	}
}

// checkNoSecrets: no credential value, signature or session token reaches
// an observation, a cursor, a statistic or a log line.
func checkNoSecrets(t *testing.T, res adapter.Result, logs *bytes.Buffer) {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"result": string(b), "logs": logs.String()} {
		for _, leak := range []string{testAKID, testSK, testST, "Signature=", "AWS4-HMAC", "X-Amz-Security-Token"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s contains %q", name, leak)
			}
		}
		if hits := adapter.FindSecrets([]byte(text)); len(hits) > 0 {
			t.Errorf("%s matches secret patterns %v", name, hits)
		}
	}
}

func TestDelta(t *testing.T) {
	te := newEnv(t, load(t, "synthetic-full"))
	a := newAdapter(te.env)
	cfg := config(nil)
	first := syncOK(t, a, cfg, "")
	second := syncOK(t, a, cfg, first.Cursor)
	if len(second.Observations) != 0 || second.Stats[cloud.StatUnchanged] != 7 {
		t.Fatalf("unchanged resources were sent again: %d, stats %v", len(second.Observations), second.Stats)
	}
	te.clk.Advance(25 * time.Hour)
	third := syncOK(t, a, cfg, second.Cursor)
	if len(third.Observations) != 7 {
		t.Fatalf("refresh after 24 h sent %d, want 7", len(third.Observations))
	}
	cfg.Settings["refresh_hours"] = "0"
	te.clk.Advance(100 * 24 * time.Hour)
	if r := syncOK(t, a, cfg, third.Cursor); len(r.Observations) != 0 {
		t.Fatalf("refresh_hours 0 re-sent %d", len(r.Observations))
	}
}

// TestFeatureOff: with MEISCOPE_FEATURE_CLOUD_RESOURCE_V1 off (the default)
// nothing reaches the sink, so the core's current contract (0.9.0, which
// has no cloud_resource kind) is never broken, and the cursor stays put.
func TestFeatureOff(t *testing.T) {
	te := newEnv(t, load(t, "synthetic-full"))
	te.env.Features = adapter.Features{}
	core, err := submittest.NewCoreWithSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	sink := &submitSink{cl: cl}
	cursors, _ := adapter.LoadCursors("")
	rr, err := adapter.RunOnce(context.Background(), te.env, config(nil), cursors, sink)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Observations != 0 || sink.n != 0 || rr.Stats[cloud.StatSkippedFeatureDisabled] != 7 {
		t.Fatalf("flag off: %+v, sink got %d", rr, sink.n)
	}
	if cursors.Get("aws-prod") != "" {
		t.Fatal("cursor advanced with the feature off")
	}
	if len(core.Errors()) > 0 || len(core.Batches()) > 0 {
		t.Fatalf("the current core received something: %v", core.Errors())
	}
	if !strings.Contains(te.logs.String(), adapter.EnvCloudResourceV1) {
		t.Errorf("no warning naming %s: %s", adapter.EnvCloudResourceV1, te.logs.String())
	}
	// With the feature on, the same observations would break the current
	// contract, which is why the switch exists.
	te.env.Features.CloudResourceV1 = true
	res := syncOK(t, newAdapter(te.env), config(nil), "")
	if _, err := cl.Submit(context.Background(), res.Observations); !submit.IsPermanent(err) {
		t.Fatalf("the 0.9.0 core accepted cloud_resource observations: %v", err)
	}
}

type submitSink struct {
	cl *submit.Client
	n  int
}

func (s *submitSink) Enqueue(ctx context.Context, obs []submit.Observation) error {
	s.n += len(obs)
	_, err := s.cl.Submit(ctx, obs)
	return err
}

// throttler answers the first len(statuses) requests itself, then passes on.
type throttler struct {
	next     http.RoundTripper
	mu       sync.Mutex
	statuses []int
	calls    int
}

func (th *throttler) RoundTrip(r *http.Request) (*http.Response, error) {
	th.mu.Lock()
	th.calls++
	if len(th.statuses) > 0 {
		st := th.statuses[0]
		th.statuses = th.statuses[1:]
		th.mu.Unlock()
		h := http.Header{"Content-Type": {"application/x-amz-json-1.1"}}
		body := `{"__type":"ThrottlingException","message":"Rate exceeded"}`
		if st == http.StatusTooManyRequests {
			h.Set("Retry-After", "3")
			body = `{"__type":"TooManyRequestsException"}`
		}
		return &http.Response{StatusCode: st, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
	th.mu.Unlock()
	return th.next.RoundTrip(r)
}

func longSleeps(c *clock.Fake) []time.Duration {
	var out []time.Duration
	for _, d := range c.Sleeps() {
		if d >= time.Second {
			out = append(out, d)
		}
	}
	return out
}

func TestThrottling(t *testing.T) {
	th := &throttler{next: load(t, "synthetic-full"), statuses: []int{400, 400, 429}}
	te := newEnv(t, th)
	res := syncOK(t, newAdapter(te.env), config(nil), "")
	if len(res.Observations) != 7 {
		t.Fatalf("%d observations after throttling", len(res.Observations))
	}
	// Back-off 1 s, 2 s, then Retry-After 3 s but never sooner than the
	// schedule (4 s).
	if got := longSleeps(te.clk); !slices.Equal(got, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("sleeps %v", got)
	}

	always := &throttler{next: load(t, "synthetic-full"), statuses: slices.Repeat([]int{400}, 50)}
	te2 := newEnv(t, always)
	_, err := newAdapter(te2.env).Sync(context.Background(), config(nil), "")
	if err == nil || errors.Is(err, aws.ErrAuth) || !strings.Contains(err.Error(), "ThrottlingException") {
		t.Fatalf("persistent throttling: %v", err)
	}
	if always.calls != 6 {
		t.Fatalf("%d attempts, want 6", always.calls)
	}
}

func TestAuthFailure(t *testing.T) {
	for _, svc := range []string{"acm", "iam"} {
		tr := load(t, "synthetic-auth-failure")
		te := newEnv(t, tr)
		cfg := config(map[string]string{"services": svc, "regions": "ap-southeast-2"})
		_, err := newAdapter(te.env).Sync(context.Background(), cfg, "")
		if !errors.Is(err, aws.ErrAuth) {
			t.Fatalf("%s: want ErrAuth, got %v", svc, err)
		}
		if len(tr.Requests()) != 1 {
			t.Errorf("%s: an authentication failure was retried (%d requests)", svc, len(tr.Requests()))
		}
		for _, leak := range []string{testAKID, testSK, testST, "security token included"} {
			if strings.Contains(err.Error(), leak) || strings.Contains(te.logs.String(), leak) {
				t.Errorf("%s: error or logs contain %q: %v", svc, leak, err)
			}
		}
	}
}

func TestMissingCredential(t *testing.T) {
	tr := load(t, "synthetic-full")
	te := newEnv(t, tr)
	te.env.Creds = mapSource{"aws_akid": testAKID}
	if _, err := newAdapter(te.env).Sync(context.Background(), config(nil), ""); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if len(tr.Requests()) != 0 {
		t.Fatal("requests were sent without credentials")
	}
}

func TestValidate(t *testing.T) {
	a := newAdapter(adapter.Env{})
	if err := a.Validate(config(nil)); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*adapter.Config){
		"no regions":     func(c *adapter.Config) { c.Settings["regions"] = "" },
		"bad region":     func(c *adapter.Config) { c.Settings["regions"] = "Sydney" },
		"bad service":    func(c *adapter.Config) { c.Settings["services"] = "acm,s3" },
		"no secret ref":  func(c *adapter.Config) { delete(c.Credentials, "secret_access_key") },
		"bad rate":       func(c *adapter.Config) { c.Settings["rate_per_second"] = "-1" },
		"bad refresh":    func(c *adapter.Config) { c.Settings["refresh_hours"] = "x" },
		"bad page limit": func(c *adapter.Config) { c.Settings["max_pages"] = "0" },
	} {
		c := config(nil)
		mut(&c)
		if err := a.Validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := config(map[string]string{"secret_access_key": testSK})
	if err := c.Check(); !errors.Is(err, adapter.ErrSecretInSettings) {
		t.Errorf("a key in settings: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	d := newAdapter(adapter.Env{}).Describe()
	if d.Name != "aws" || d.Source != "aws" || len(d.Credentials) != 3 {
		t.Fatalf("%+v", d)
	}
}
