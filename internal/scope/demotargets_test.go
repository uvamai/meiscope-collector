package scope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// demoTargetsFile is the explicit target list for the demo estate: a
// byte-identical copy of the core's test/demo-estate/targets.json, which the
// core generates (test/demo-estate/gen). Refresh it from the core; never edit
// it here. Its category field is not read. This test proves every listed
// endpoint is a valid explicit target under the same rules the collector enforces on a signed
// scope, so the demo scope built from it cannot carry a target the probe
// would refuse.
const demoTargetsFile = "../../test/demo-estate/targets.json"

type demoTargets struct {
	Domain  string `json:"domain"`
	Targets []struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		SNI      string `json:"sni"`
	} `json:"targets"`
}

func loadDemoTargets(t *testing.T) demoTargets {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(demoTargetsFile))
	if err != nil {
		t.Fatalf("read %s: %v", demoTargetsFile, err)
	}
	var dt demoTargets
	if err := json.Unmarshal(b, &dt); err != nil {
		t.Fatalf("unmarshal %s: %v", demoTargetsFile, err)
	}
	return dt
}

func TestDemoTargetsFixture(t *testing.T) {
	dt := loadDemoTargets(t)

	const want = 25
	if len(dt.Targets) != want {
		t.Fatalf("demo targets: got %d, want %d (the EXPECTED.md Network endpoints)", len(dt.Targets), want)
	}
	if dt.Domain != "northwind.test" {
		t.Fatalf("demo domain: got %q, want northwind.test", dt.Domain)
	}

	for i, tg := range dt.Targets {
		if tg.SNI != tg.Host {
			t.Errorf("target %d (%s:%d): sni %q != host %q; every DNS target's SNI is its host", i, tg.Host, tg.Port, tg.SNI, tg.Host)
		}
		if !strings.HasSuffix(tg.Host, "."+dt.Domain) {
			t.Errorf("target %d: host %q is not under %q", i, tg.Host, dt.Domain)
		}
		if tg.Protocol != "" && !contains(Protocols, tg.Protocol) {
			t.Errorf("target %d (%s): unknown protocol %q", i, tg.Host, tg.Protocol)
		}
	}
}

// TestDemoTargetsValidateAsScope runs the fixture through the real scope
// validation the collector applies to every signed scope (explicit targets,
// ports in range, known protocols, domain containment, no reserved ranges).
func TestDemoTargetsValidateAsScope(t *testing.T) {
	dt := loadDemoTargets(t)

	sc := validScope()
	sc.Domains = []string{dt.Domain}
	sc.Targets = sc.Targets[:0]
	for _, tg := range dt.Targets {
		sc.Targets = append(sc.Targets, Target{Host: tg.Host, Port: tg.Port, Protocol: tg.Protocol})
	}

	if err := sc.validate(); err != nil {
		t.Fatalf("demo targets do not form a valid scope: %v", err)
	}
}
