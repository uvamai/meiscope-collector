package submit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Tests of the AWS and Cloudflare additions to the 0.10.0 proposal:
// AdapterEvidence.in_use_by and AdapterEvidence.cloud_certificate.

func edgeCertificateObservation() submit.Observation {
	notAfter := t0.AddDate(0, 3, 0)
	return submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: "api.cloudflare.com", Provider: "cloudflare",
			ResourceID: "0123456789abcdef0123456789abcdef/3822ff90-ea29-44df-9e55-21300bb9419b", ResourceType: "Cloudflare::CertificatePack",
		},
		Method: submit.MethodAdapter, ObservedAt: t0, Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:      "cloudflare",
			RenewalMode: submit.RenewalExternalAutomated,
			Bindings:    []submit.Binding{{Hostname: "www.example.test", ResourceID: "0123456789abcdef0123456789abcdef"}},
			InUseBy:     []string{"arn:aws:cloudfront::111122223333:distribution/EXAMPLE"},
			CloudCertificate: &submit.CloudCertificate{
				ID: "3822ff90-ea29-44df-9e55-21300bb9419b", Type: "universal", Status: "active",
				NotAfter: &notAfter, Hostnames: []string{"www.example.test"},
			},
		},
	}
}

func TestCloudExtrasAccepted(t *testing.T) {
	core, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), []submit.Observation{edgeCertificateObservation()})
	if err != nil || res.Accepted != 1 {
		t.Fatalf("%+v %v %v", res, err, core.Errors())
	}
}

func TestCloudExtrasSchema(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(submit.ObservationBatch{Observations: []submit.Observation{edgeCertificateObservation()}})
	doc := string(b)
	if err := spec.Validate("ObservationBatch", b); err != nil {
		t.Fatalf("valid batch refused: %v", err)
	}
	for name, d := range map[string]string{
		"certificate without id": strings.Replace(doc, `"id":"3822ff90-ea29-44df-9e55-21300bb9419b",`, ``, 1),
		"empty in_use_by entry":  strings.Replace(doc, `"arn:aws:cloudfront::111122223333:distribution/EXAMPLE"`, `""`, 1),
		"bad not_after":          strings.Replace(doc, `"not_after":"`, `"not_after":"soon`, 1),
	} {
		if d == doc {
			t.Errorf("%s: replacement did not apply", name)
			continue
		}
		if err := spec.Validate("ObservationBatch", []byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	vendored, err := submittest.LoadSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := vendored.Validate("ObservationBatch", b); err == nil {
		t.Error("the vendored 0.9.0 contract accepts the cloud observation")
	}
}
