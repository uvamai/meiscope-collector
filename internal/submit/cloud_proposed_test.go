package submit_test

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Tests of the PROPOSED contract 0.10.0 (cloud_resource targets, WP1.2),
// which the core has not adopted.

func cloudObservation() submit.Observation {
	exportable := false
	na := t0.AddDate(1, 0, 0)
	return submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: "kv-contoso.vault.azure.net", Provider: "azure",
			ResourceID: "https://kv-contoso.vault.azure.net/certificates/web", ResourceType: "Microsoft.KeyVault/vaults/certificates", Region: "australiaeast",
		},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeCertSeen,
		Adapter: &submit.AdapterEvidence{
			Source:      "azure_key_vault",
			Certificate: &submit.CertificateMetadata{SHA1: strings.Repeat("cd", 20), NotAfter: &na},
			Custody:     &submit.Custody{KeyCustody: submit.KeyPresent, KeyExportable: &exportable},
			RenewalMode: submit.RenewalExternalAutomated,
			Bindings:    []submit.Binding{{Hostname: "www.contoso.example.test", Port: 443, ResourceID: "/subscriptions/x/sites/y"}},
		},
	}
}

func expiryObservation() submit.Observation {
	na := t0.AddDate(0, 3, 0)
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindCloudResource, Host: "graph.microsoft.com", Provider: "azure", ResourceID: "/applications/a/passwordCredentials/b"},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{Source: "entra_id", Findings: []submit.Finding{{
			Code: submit.FindingSecretCredentialExpiry, NotAfter: &na, CredentialID: "b",
		}}},
	}
}

func TestCloudProposalObservations(t *testing.T) {
	core, err := submittest.NewCloudProposedCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	withPort := cloudObservation()
	withPort.Target.Port = 443
	noResource := cloudObservation()
	noResource.Target.ResourceID = ""
	probe := cloudObservation()
	probe.Method, probe.Adapter = submit.MethodProbe, nil
	noEvidence := cloudObservation()
	noEvidence.Adapter = nil
	providerOnStore := storeObservation()
	providerOnStore.Target.Provider = "azure"
	evidenceOnEndpoint := cloudObservation()
	evidenceOnEndpoint.Target = submit.Target{Kind: submit.KindHostPortSNI, Host: "www.contoso.example.test", Port: 443}
	res, err := cl.Submit(context.Background(), []submit.Observation{
		cloudObservation(), expiryObservation(), storeObservation(), withPort, noResource, probe, noEvidence, providerOnStore, evidenceOnEndpoint,
	})
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	var codes []string
	for _, r := range res.Rejected {
		codes = append(codes, strconv.Itoa(r.Index)+":"+r.Code)
	}
	want := []string{"3:invalid_target", "4:invalid_target", "5:invalid_target", "6:invalid_target", "7:invalid_target", "8:invalid_target"}
	if res.Accepted != 3 || !reflect.DeepEqual(codes, want) {
		t.Fatalf("accepted %d, rejected %v, want %v", res.Accepted, codes, want)
	}
}

func TestCloudProposalSchema(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"observations":[{"target":{"kind":"cloud_resource","host":"management.azure.com","provider":"azure","resource_id":"/subscriptions/s/x"},"method":"adapter","observed_at":"2026-11-13T00:00:00Z","outcome":"cert_seen","adapter":{"source":"azure_app_service","certificate":{"sha1":"` + strings.Repeat("ab", 20) + `"},"renewal_mode":"manual","bindings":[{"hostname":"a.example.test","port":443}]}}]}`
	if err := spec.Validate("ObservationBatch", []byte(doc)); err != nil {
		t.Fatalf("valid cloud batch refused: %v", err)
	}
	bad := map[string]string{
		"bad provider":     strings.Replace(doc, `"azure"`, `"Azure Cloud"`, 1),
		"empty resource":   strings.Replace(doc, `"/subscriptions/s/x"`, `""`, 1),
		"bad renewal":      strings.Replace(doc, `"manual"`, `"sometimes"`, 1),
		"binding port":     strings.Replace(doc, `"port":443`, `"port":0`, 1),
		"binding hostname": strings.Replace(doc, `{"hostname":"a.example.test","port":443}`, `{"port":443}`, 1),
		"unknown target":   strings.Replace(doc, `"provider":"azure"`, `"provider":"azure","account":"x"`, 1),
		"key material":     strings.Replace(doc, `"provider":"azure"`, `"provider":"azure","private_key":"x"`, 1),
	}
	for name, d := range bad {
		if err := spec.Validate("ObservationBatch", []byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	vendored, _ := submittest.LoadSpec(submittest.VendoredSpecPath())
	if err := vendored.Validate("ObservationBatch", []byte(doc)); err == nil {
		t.Error("the vendored 0.9.0 contract accepts cloud_resource; the proposal is then obsolete")
	}
}

// TestCloudProposalFieldsAreReviewed pins the exact fields of the 0.10.0
// proposal, and that it differs from the vendored 0.9.0 contract only by
// these additions.
func TestCloudProposalFieldsAreReviewed(t *testing.T) {
	vendored, vStrict := schemaProps(t, submittest.VendoredSpecPath())
	proposed, pStrict := schemaProps(t, submittest.CloudProposedSpecPath())
	added := map[string]string{
		"AdapterEvidence":  "bindings,cloud_certificate,in_use_by,renewal_mode",
		"CloudCertificate": "hostnames,id,issuer,not_after,not_before,serial,status,type",
		"Binding":          "hostname,port,resource_id",
		"Custody":          "key_exportable",
		"Finding":          "credential_id,not_after",
		"Target":           "provider,region,resource_id,resource_type",
	}
	for name, props := range proposed {
		var extra []string
		for _, p := range props {
			if !contains(vendored[name], p) {
				extra = append(extra, p)
			}
		}
		if got := strings.Join(extra, ","); got != added[name] {
			t.Errorf("%s adds %q, reviewed %q", name, got, added[name])
		}
		if name != "Target" && vStrict[name] != pStrict[name] {
			t.Errorf("%s changes additionalProperties", name)
		}
		if name == "Binding" && pStrict[name] {
			t.Error("Binding must let readers ignore unknown fields")
		}
	}
	for name, props := range vendored {
		for _, p := range props {
			if !contains(proposed[name], p) {
				t.Errorf("proposal drops %s.%s", name, p)
			}
		}
	}
	b, err := os.ReadFile(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"enum: [host_port_sni, ct_log, store, file, cloud_resource]", "enum: [keystore_not_parsed, secret_credential_expiry, secret_not_read]", "version: 0.10.0-proposed"} {
		if !strings.Contains(string(b), s) {
			t.Errorf("proposal lacks %q", s)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
