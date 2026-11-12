package submit_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Tests of the PROPOSED contract 0.10.0 additions (cloud_resource targets
// and cloud evidence) that the WP1.2 cloud adapters need.

func cloudCertObservation() submit.Observation {
	notAfter := t0.Add(90 * 24 * 3600 * 1e9)
	return submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: "acm.ap-southeast-2.amazonaws.com",
			Cloud: &submit.CloudResource{
				Provider: "aws", Service: "acm", Region: "ap-southeast-2", Account: "111122223333",
				ResourceID: "arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000001",
			},
		},
		Method:      submit.MethodAdapter,
		ObservedAt:  t0,
		Outcome:     submit.OutcomeCertSeen,
		ServedChain: [][]byte{{0x30, 0x00}},
		Adapter: &submit.AdapterEvidence{
			Source:    "aws",
			Hostnames: []string{"www.example.test"},
			Bindings:  []submit.Binding{{ResourceID: "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:loadbalancer/app/web/0123456789abcdef", Service: "elasticloadbalancing"}},
			Renewal:   &submit.Renewal{Mode: submit.RenewalExternalAutomated, ManagedBy: "aws_acm", Status: "SUCCESS", Eligibility: "ELIGIBLE"},
			CloudCertificate: &submit.CloudCertificate{
				ID: "arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000001", Type: "AMAZON_ISSUED", Status: "ISSUED", NotAfter: &notAfter,
			},
		},
	}
}

func cloudListenerObservation() submit.Observation {
	def := true
	return submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: "elasticloadbalancing.ap-southeast-2.amazonaws.com",
			Cloud: &submit.CloudResource{Provider: "aws", Service: "elbv2_listener", Region: "ap-southeast-2", ResourceID: "arn:aws:elasticloadbalancing:ap-southeast-2:111122223333:listener/app/web/0123456789abcdef/fedcba9876543210"},
		},
		Method: submit.MethodAdapter, ObservedAt: t0, Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:   "aws",
			Endpoint: &submit.Endpoint{DNSName: "web-1.ap-southeast-2.elb.example.test", Port: 443, Protocol: "HTTPS", Scheme: "internet-facing"},
			Bindings: []submit.Binding{{ResourceID: "arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000001", Service: "acm", IsDefault: &def}},
		},
	}
}

func newCloudCore(t *testing.T) *submittest.Core {
	t.Helper()
	c, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestCloudProposedObservations(t *testing.T) {
	core := newCloudCore(t)
	cl, _ := submit.New(core.URL, core.Client())

	withPort := cloudCertObservation()
	withPort.Target.Port = 443
	noCloud := cloudCertObservation()
	noCloud.Target.Cloud = nil
	probe := cloudCertObservation()
	probe.Method, probe.Adapter = submit.MethodProbe, nil
	noEvidence := cloudCertObservation()
	noEvidence.Adapter = nil
	bareReached := cloudListenerObservation()
	bareReached.Adapter = &submit.AdapterEvidence{Source: "aws"}
	cloudOnStore := storeObservation()
	cloudOnStore.Target.Cloud = cloudCertObservation().Target.Cloud
	withSNI := cloudListenerObservation()
	withSNI.Target.SNI = "www.example.test"

	res, err := cl.Submit(context.Background(), []submit.Observation{
		cloudCertObservation(), cloudListenerObservation(), withPort, noCloud, probe, noEvidence, bareReached, cloudOnStore, withSNI,
	})
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	var codes []string
	for _, r := range res.Rejected {
		codes = append(codes, strconv.Itoa(r.Index)+":"+r.Code)
	}
	want := []string{"2:invalid_target", "3:invalid_target", "4:invalid_target", "5:invalid_target", "6:invalid_target", "7:invalid_target", "8:invalid_target"}
	if res.Accepted != 2 || !reflect.DeepEqual(codes, want) {
		t.Fatalf("accepted %d, rejected %v, want %v", res.Accepted, codes, want)
	}
}

// TestCloudResourceNotInCurrentContract: the vendored 0.9.0 contract (what
// the core runs today) refuses a cloud_resource target, which is why the
// adapters keep it behind MEISCOPE_FEATURE_CLOUD_RESOURCE_V1.
func TestCloudResourceNotInCurrentContract(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(submit.ObservationBatch{Observations: []submit.Observation{cloudCertObservation()}})
	if err := spec.Validate("ObservationBatch", b); err == nil {
		t.Fatal("the vendored contract accepted a cloud_resource target")
	}
}

func TestCloudProposedSchema(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	good, _ := json.Marshal(submit.ObservationBatch{Observations: []submit.Observation{cloudCertObservation(), cloudListenerObservation()}})
	doc := string(good)
	if err := spec.Validate("ObservationBatch", good); err != nil {
		t.Fatalf("valid cloud batch refused: %v", err)
	}
	// The 0.9.0 shapes stay valid under the proposal.
	old, _ := json.Marshal(submit.ObservationBatch{Observations: []submit.Observation{storeObservation(), fileObservation()}})
	if err := spec.Validate("ObservationBatch", old); err != nil {
		t.Fatalf("0.9.0 store batch refused by the proposal: %v", err)
	}
	bad := map[string]string{
		"unknown kind":       strings.Replace(doc, `"kind":"cloud_resource"`, `"kind":"cloud"`, 1),
		"bad provider":       strings.Replace(doc, `"provider":"aws"`, `"provider":"Amazon Web Services"`, 1),
		"bad service":        strings.Replace(doc, `"service":"acm"`, `"service":"ACM!"`, 1),
		"empty resource id":  strings.Replace(doc, `"resource_id":"arn:aws:acm:ap-southeast-2:111122223333:certificate/00000000-0000-4000-8000-000000000001"`, `"resource_id":""`, 1),
		"unknown cloud prop": strings.Replace(doc, `"provider":"aws"`, `"provider":"aws","tenant":"x"`, 1),
		"bad renewal mode":   strings.Replace(doc, `"mode":"external_automated"`, `"mode":"auto"`, 1),
		"bad managed_by":     strings.Replace(doc, `"managed_by":"aws_acm"`, `"managed_by":"AWS ACM"`, 1),
		"port out of range":  strings.Replace(doc, `"port":443`, `"port":0`, 1),
		"key material":       strings.Replace(doc, `"method":"adapter"`, `"private_key":"x","method":"adapter"`, 1),
	}
	for name, d := range bad {
		if d == doc {
			t.Errorf("%s: replacement did not apply", name)
			continue
		}
		if err := spec.Validate("ObservationBatch", []byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCloudProposalFieldsAreReviewed pins the exact fields the 0.10.0
// proposal adds, keeps the 0.9.0 fields unchanged, and checks that only the
// CloudResource locator is closed.
func TestCloudProposalFieldsAreReviewed(t *testing.T) {
	vendored, _ := schemaProps(t, submittest.VendoredSpecPath())
	proposed, strict := schemaProps(t, submittest.CloudProposedSpecPath())
	want := map[string]string{
		"Target":           "cloud,host,kind,path,port,sni,store",
		"CloudResource":    "account,provider,region,resource_id,service",
		"AdapterEvidence":  "bindings,certificate,cloud_certificate,custody,endpoint,file,findings,hostnames,renewal,source",
		"Binding":          "hostnames,is_default,port,protocol,region,resource_id,service",
		"Renewal":          "eligibility,managed_by,mode,status",
		"CloudCertificate": "id,issuer,not_after,not_before,serial,status,type",
		"Endpoint":         "dns_name,port,protocol,scheme",
	}
	for name, fields := range want {
		if got := strings.Join(proposed[name], ","); got != fields {
			t.Errorf("%s fields %s, reviewed %s", name, got, fields)
		}
		closed := name == "Target" || name == "CloudResource"
		if strict[name] != closed {
			t.Errorf("%s additionalProperties false = %v, want %v", name, strict[name], closed)
		}
	}
	for name, fields := range vendored {
		if _, changed := want[name]; changed {
			continue
		}
		if got := proposed[name]; !reflect.DeepEqual(got, fields) {
			t.Errorf("%s changed in the proposal: %v, vendored %v", name, got, fields)
		}
	}
}

func TestKeyGuardOnCloudProposal(t *testing.T) {
	doc, err := os.ReadFile(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	if fs, err := findKeyFields(doc); err != nil || len(fs) > 0 {
		t.Errorf("%v %v", err, fs)
	}
}
