package submit_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// The private-key guard below mirrors the core's NFR-SEC-002 CI guard
// (internal/schema/privatekey.go in the core): no schema property name,
// pattern, example or enum may look like private-key material.
var (
	keyPropertyName = regexp.MustCompile(`(?i)(private[_-]?key|priv[_-]?key|pem[_-]?key|key[_-]?pem|pkcs[_-]?8|pkcs[_-]?12|^pfx$|^p12$|pfx[_-]?(data|blob|file|bytes)|passw|secret|keystore[_-]?pass|alias)`)
	keyPEMArmour    = regexp.MustCompile(`(?i)BEGIN.*PRIVATE`)
)

type keyFinding struct{ path, reason string }

func findKeyFields(doc []byte) ([]keyFinding, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, err
	}
	var out []keyFinding
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, fmt.Sprintf("%s[%d]", path, i))
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i], n.Content[i+1]
				p := path + "." + key.Value
				switch key.Value {
				case "properties":
					for j := 0; j+1 < len(val.Content); j += 2 {
						if name := val.Content[j].Value; keyPropertyName.MatchString(name) {
							out = append(out, keyFinding{p + "." + name, "property name looks like key material"})
						}
					}
				case "pattern", "example", "default", "const":
					if keyPEMArmour.MatchString(val.Value) {
						out = append(out, keyFinding{p, key.Value + " matches a PEM private-key block"})
					}
				case "examples", "enum":
					for _, c := range val.Content {
						if keyPEMArmour.MatchString(c.Value) {
							out = append(out, keyFinding{p, key.Value + " contains a PEM private-key block"})
						}
					}
				}
				walk(val, p)
			}
		case yaml.ScalarNode, yaml.AliasNode:
			// Leaves are inspected by their parent mapping.
		}
	}
	walk(&root, "$")
	return out, nil
}

func TestKeyGuardOnContracts(t *testing.T) {
	for _, p := range []string{submittest.VendoredSpecPath(), submittest.ProposedSpecPath(), submittest.CloudProposedSpecPath()} {
		doc, err := os.ReadFile(p) //nolint:gosec // repository contract files
		if err != nil {
			t.Fatal(err)
		}
		if fs, err := findKeyFields(doc); err != nil || len(fs) > 0 {
			t.Errorf("%s: %v %v", p, err, fs)
		}
	}
}

func TestKeyGuardFindsWhatItShould(t *testing.T) {
	for name, doc := range map[string]string{ //nolint:gosec // test inputs, not credentials
		"snake":      "properties:\n  private_key: {type: string}\n",
		"pfx":        "properties:\n  pfx: {type: string}\n",
		"password":   "properties:\n  keystore_password: {type: string}\n",
		"alias":      "properties:\n  key_alias: {type: string}\n",
		"secret":     "properties:\n  client_secret: {type: string}\n",
		"pem armour": "properties:\n  x:\n    pattern: '^-----BEGIN RSA PRIVATE KEY-----'\n",
	} {
		if fs, err := findKeyFields([]byte(doc)); err != nil || len(fs) != 1 {
			t.Errorf("%s: %v %v", name, err, fs)
		}
	}
}

// schemaProps returns the property names of each schema in components.schemas
// and, separately, the schemas that set additionalProperties false.
func schemaProps(t *testing.T, path string) (props map[string][]string, strict map[string]bool) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // repository contract files
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties           map[string]yaml.Node `yaml:"properties"`
				AdditionalProperties *bool                `yaml:"additionalProperties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	props, strict = map[string][]string{}, map[string]bool{}
	for name, s := range doc.Components.Schemas {
		for p := range s.Properties {
			props[name] = append(props[name], p)
		}
		sort.Strings(props[name])
		strict[name] = s.AdditionalProperties != nil && !*s.AdditionalProperties
	}
	return props, strict
}

// TestAdoptedFieldsAreReviewed fixes the exact set of fields the 0.5.0
// proposal added and contract 0.9.0 adopted, so a new field cannot slip in
// without this list (and the key guard above, which covers every property
// name) seeing it. The adopted objects must not close themselves with
// additionalProperties false: they are additive, and the core must ignore
// unknown fields of them. The proposal and the vendored contract must agree
// on every field, so the proposal file stays a faithful record.
func TestAdoptedFieldsAreReviewed(t *testing.T) {
	vendored, strict := schemaProps(t, submittest.VendoredSpecPath())
	proposed, _ := schemaProps(t, submittest.ProposedSpecPath())
	want := map[string]string{
		"AdapterEvidence":     "certificate,custody,file,findings,source",
		"CertificateMetadata": "authority_key_id,ca,common_name,issuer,key_algorithm,key_strength,not_after,not_before,self_signed,serial,sha1,signing_algorithm,subject,subject_key_id",
		"FileDigest":          "mtime,owner,permissions,sha256,size,store_type",
		"Custody":             "key_custody",
		"Finding":             "code",
		"Target":              "host,kind,path,port,sni,store",
	}
	for name, fields := range want {
		if got := strings.Join(vendored[name], ","); got != fields {
			t.Errorf("%s fields %s, reviewed %s", name, got, fields)
		}
		if got := strings.Join(proposed[name], ","); got != fields {
			t.Errorf("proposal %s fields %s, reviewed %s", name, got, fields)
		}
		if name != "Target" && strict[name] {
			t.Errorf("%s sets additionalProperties false; additive objects must let readers ignore unknown fields", name)
		}
	}
	if !strings.Contains(","+strings.Join(vendored["Observation"], ",")+",", ",adapter,") {
		t.Errorf("Observation fields %v lack adapter", vendored["Observation"])
	}
}

// TestCoreAcceptsAdapterObservations: contract 0.9.0 adopted store and file
// targets and adapter evidence, so the current core accepts them. Sending
// them stays behind MEISCOPE_FEATURE_LOCAL_STORE_V1 until that flag is
// retired in its own change.
func TestCoreAcceptsAdapterObservations(t *testing.T) {
	core, err := submittest.NewCoreWithSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), []submit.Observation{storeObservation(), fileObservation()})
	if err != nil || res.Accepted != 2 {
		t.Fatalf("%+v %v (errors %v)", res, err, core.Errors())
	}
}

// TestFindingAndMetadataInTheProposal covers the file metadata and the
// keystore_not_parsed finding.
func TestFindingAndMetadataInTheProposal(t *testing.T) {
	core, err := submittest.NewProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	o := fileObservation()
	o.Adapter.File.Owner, o.Adapter.File.Permissions, o.Adapter.File.StoreType = "S-1-5-18", "0640", submit.StorePKCS12
	mt := t0
	o.Adapter.File.MTime = &mt
	o.Adapter.Findings = []submit.Finding{{Code: submit.FindingKeystoreNotParsed}}
	cl, _ := submit.New(core.URL, core.Client())
	if res, err := cl.Submit(context.Background(), []submit.Observation{o}); err != nil || res.Accepted != 1 {
		t.Fatalf("%+v %v %v", res, err, core.Errors())
	}
	bad := o
	bad.Adapter = &submit.AdapterEvidence{Source: "osquery", File: o.Adapter.File, Findings: []submit.Finding{{Code: "guessed_password"}}}
	if _, err := cl.Submit(context.Background(), []submit.Observation{bad}); !submit.IsPermanent(err) {
		t.Fatalf("unknown finding code accepted: %v", err)
	}
}
