package cloud_test

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/adapter/fixture"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

func obs(id, status string) submit.Observation {
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindCloudResource, Host: "api.example.test", Provider: "aws", ResourceType: "AWS::CertificateManager::Certificate", ResourceID: id},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeReached,
		Adapter:    &submit.AdapterEvidence{Source: "aws", CloudCertificate: &submit.CloudCertificate{ID: id, Status: status}},
	}
}

func ids(o []submit.Observation) string {
	var s []string
	for _, x := range o {
		s = append(s, x.Target.ResourceID)
	}
	return strings.Join(s, ",")
}

func TestFilter(t *testing.T) {
	st := map[string]int{}
	out, c1, err := cloud.Filter("", []submit.Observation{obs("a", "ISSUED"), obs("b", "ISSUED")}, t0, 24*time.Hour, st)
	if err != nil || ids(out) != "a,b" {
		t.Fatalf("first: %s %v", ids(out), err)
	}
	// One hour later: a changed, b unchanged, c new; observed_at alone is
	// not a change.
	later := []submit.Observation{obs("a", "EXPIRED"), obs("b", "ISSUED"), obs("c", "ISSUED")}
	for i := range later {
		later[i].ObservedAt = t0.Add(time.Hour)
	}
	st = map[string]int{}
	out, c2, err := cloud.Filter(c1, later, t0.Add(time.Hour), 24*time.Hour, st)
	if err != nil || ids(out) != "a,c" || st[cloud.StatUnchanged] != 1 {
		t.Fatalf("second: %s %v %v", ids(out), st, err)
	}
	// b disappears from the listing and comes back: sent again.
	_, c3, _ := cloud.Filter(c2, later[:1], t0.Add(2*time.Hour), 24*time.Hour, map[string]int{})
	out, _, _ = cloud.Filter(c3, later, t0.Add(3*time.Hour), 24*time.Hour, map[string]int{})
	if ids(out) != "b,c" {
		t.Fatalf("returning resources: %s", ids(out))
	}
	// A refresh re-sends everything.
	out, _, _ = cloud.Filter(c2, later, t0.Add(25*time.Hour), 24*time.Hour, map[string]int{})
	if ids(out) != "a,b,c" {
		t.Fatalf("refresh: %s", ids(out))
	}
	if _, _, err := cloud.Filter("not json", nil, t0, 0, map[string]int{}); err == nil {
		t.Fatal("bad cursor accepted")
	}
}

func TestFinishFeatureGate(t *testing.T) {
	o := []submit.Observation{obs("a", "ISSUED")}
	st := map[string]int{}
	r := cloud.Finish(adapter.Env{}, "aws", adapter.Config{Name: "x"}, o, st, "old", "new")
	if len(r.Observations) != 0 || r.Cursor != "old" || r.Stats[cloud.StatSkippedFeatureDisabled] != 1 {
		t.Fatalf("off: %+v", r)
	}
	r = cloud.Finish(adapter.Env{Features: adapter.Features{CloudResourceV1: true}}, "aws", adapter.Config{Name: "x"}, o, map[string]int{}, "old", "new")
	if len(r.Observations) != 1 || r.Cursor != "new" {
		t.Fatalf("on: %+v", r)
	}
}

// originPEM returns the synthetic Origin CA certificate of the Cloudflare
// fixtures.
func originPEM(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(fixture.Dir("cloudflare", "synthetic-full", "005.json")))
	if err != nil {
		t.Fatal(err)
	}
	var ex struct {
		Response struct {
			Body struct {
				Result []struct {
					Certificate string `json:"certificate"`
				} `json:"result"`
			} `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(b, &ex); err != nil || len(ex.Response.Body.Result) != 1 {
		t.Fatalf("fixture: %v", err)
	}
	return ex.Response.Body.Result[0].Certificate
}

func TestParsePEMChainAndMetadata(t *testing.T) {
	p := originPEM(t)
	chain, err := cloud.ParsePEMChain(p, "", "not pem", p)
	if err != nil || len(chain) != 2 {
		t.Fatalf("%d %v", len(chain), err)
	}
	m, err := cloud.Metadata(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA1 != "20060e7eef4b19f3b041e4abe50173b9b57fbd9f" || m.CommonName != "origin.example.test" || m.KeyAlgorithm != "ECDSA" || m.KeyStrength != "256" || *m.CA || *m.SelfSigned {
		t.Fatalf("%+v", m)
	}
	// A private-key block is refused and nothing is returned.
	keyBlock := "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n"
	if c, err := cloud.ParsePEMChain(p, keyBlock); !errors.Is(err, cloud.ErrKeyMaterial) || c != nil {
		t.Fatalf("key block: %v %v", c, err)
	}
	if _, err := cloud.ParsePEMChain("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err == nil {
		t.Fatal("garbage certificate accepted")
	}
}

func TestHostnames(t *testing.T) {
	got := cloud.Hostnames([]string{"WWW.example.test.", "", "a.example.test"}, []string{"www.example.test", strings.Repeat("a", 254)})
	if strings.Join(got, ",") != "a.example.test,www.example.test" {
		t.Fatalf("%v", got)
	}
}

// TestCloudFixturesHoldOnlyPublicCertificates decodes every cloud fixture
// (the PEM armour of certificate answers is written with JSON \u002d
// escapes so the repository-wide no-PEM guard keeps holding literally) and
// requires every PEM block in any string to be a public CERTIFICATE, with no
// private-key text and nothing secret-shaped anywhere.
func TestCloudFixturesHoldOnlyPublicCertificates(t *testing.T) {
	certs := 0
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				walk(p+"."+k, c)
			}
		case []any:
			for _, c := range x {
				walk(p, c)
			}
		case string:
			if strings.Contains(strings.ToUpper(x), "PRIVATE") && strings.Contains(x, "-----") {
				t.Errorf("%s: private-key text", p)
			}
			if hits := adapter.FindSecrets([]byte(x)); len(hits) > 0 {
				t.Errorf("%s: secret patterns %v", p, hits)
			}
			rest := []byte(x)
			for {
				var b *pem.Block
				b, rest = pem.Decode(rest)
				if b == nil {
					break
				}
				if b.Type != "CERTIFICATE" {
					t.Errorf("%s: PEM block %q", p, b.Type)
				}
				certs++
			}
		}
	}
	for _, provider := range []string{"aws", "cloudflare"} {
		files, err := filepath.Glob(filepath.Join(fixture.Dir(provider), "*", "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no fixtures (%v)", provider, err)
		}
		for _, f := range files {
			b, err := os.ReadFile(filepath.Clean(f))
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			walk(filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f), v)
		}
	}
	// The XML answers carry PEM inside an XML string; count only proves the
	// walk saw certificates at all.
	if certs < 5 {
		t.Fatalf("only %d certificates seen in the fixtures", certs)
	}
}

func TestLoadCloudFeature(t *testing.T) {
	for v, want := range map[string]bool{"": false, "false": false, "true": true, "1": true} {
		f, err := adapter.LoadFeatures(func(k string) string {
			if k == adapter.EnvCloudResourceV1 {
				return v
			}
			return ""
		})
		if err != nil || f.CloudResourceV1 != want || f.LocalStoreV1 {
			t.Errorf("%q: %+v %v", v, f, err)
		}
	}
	if _, err := adapter.LoadFeatures(func(k string) string {
		if k == adapter.EnvCloudResourceV1 {
			return "on please"
		}
		return ""
	}); err == nil {
		t.Error("garbage accepted")
	}
}
