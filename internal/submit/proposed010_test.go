package submit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Tests of the PROPOSED contract 0.10.0 additions of WP1.3 (the shared
// proposal also carries the WP1.2 cloud additions, cloud_proposed_test.go): adapter evidence
// on host_port_sni targets, certificates identified by issuer and serial,
// and the kubernetes and scanner evidence objects.

func endpointObservation() submit.Observation {
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindHostPortSNI, Host: "192.0.2.10", Port: 443},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeCertSeen,
		Adapter: &submit.AdapterEvidence{
			Source:      "tenable",
			Certificate: &submit.CertificateMetadata{Issuer: "CN=Synthetic Test CA", Serial: "2a01", CommonName: "www.example.test"},
			Scanner:     &submit.ScannerEvidence{Check: "10863", DNSName: "www.example.test", File: "export.csv"},
		},
	}
}

func TestProposed010Schema(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	vendored, err := submittest.LoadSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	base := `{"observations":[{"target":{"kind":"host_port_sni","host":"192.0.2.10","port":443},"method":"adapter","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","adapter":{"source":"tenable","certificate":CERT}}]}`
	good := map[string]string{
		"issuer and serial": `{"issuer":"CN=CA","serial":"2a01"}`,
		"sha1 only":         `{"sha1":"` + strings.Repeat("ab", 20) + `"}`,
		"all":               `{"sha1":"` + strings.Repeat("ab", 20) + `","sha256":"` + strings.Repeat("cd", 32) + `","dns_names":["a.example.test"],"issuer":"CN=CA","serial":"01"}`,
	}
	for name, c := range good {
		if err := spec.Validate("ObservationBatch", []byte(strings.Replace(base, "CERT", c, 1))); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	// 0.9.0 requires sha1: the identity by issuer and serial needs the proposal.
	if err := vendored.Validate("ObservationBatch", []byte(strings.Replace(base, "CERT", good["issuer and serial"], 1))); err == nil {
		t.Error("0.9.0 accepted a certificate without sha1")
	}
	bad := map[string]string{
		"serial only":  `{"serial":"2a01"}`,
		"issuer only":  `{"issuer":"CN=CA"}`,
		"bad sha256":   `{"sha1":"` + strings.Repeat("ab", 20) + `","sha256":"XY"}`,
		"empty object": `{}`,
	}
	for name, c := range bad {
		if err := spec.Validate("ObservationBatch", []byte(strings.Replace(base, "CERT", c, 1))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	k8s := `{"observations":[{"target":{"kind":"store","host":"k8s.example.test","store":"kubernetes/prod/web/www-tls"},"method":"adapter","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","adapter":{"source":"kubernetes","renewal_mode":"external_automated","certificate":{"sha1":"` + strings.Repeat("ab", 20) + `"},"custody":{"key_custody":"present"},"kubernetes":{"cluster":"prod","namespace":"web","name":"www-tls","chain_length":2,"hostnames":["www.example.test"],"references":[{"kind":"Ingress","namespace":"web","name":"www"}],"cert_manager":{"name":"www","issuer_kind":"ClusterIssuer","issuer_name":"acme","ready":true,"revision":3}}}}]}`
	if err := spec.Validate("ObservationBatch", []byte(k8s)); err != nil {
		t.Fatalf("kubernetes evidence refused: %v", err)
	}
	// A 0.9.0 core accepts and ignores the new evidence properties.
	if err := vendored.Validate("ObservationBatch", []byte(k8s)); err != nil {
		t.Fatalf("0.9.0 refused unknown evidence properties: %v", err)
	}
	for name, doc := range map[string]string{
		"renewal mode": strings.Replace(k8s, `"external_automated"`, `"guessed"`, 1),
		"sha1 short":   strings.Replace(k8s, strings.Repeat("ab", 20), "abcd", 1),
		"no cluster":   strings.Replace(k8s, `"cluster":"prod",`, ``, 1),
	} {
		if err := spec.Validate("ObservationBatch", []byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestProposed010Core(t *testing.T) {
	core, err := submittest.NewCoreWithSpec(submittest.CloudProposedSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	cl, _ := submit.New(core.URL, core.Client())
	res, err := cl.Submit(context.Background(), []submit.Observation{endpointObservation(), storeObservation()})
	if err != nil || res.Accepted != 2 || len(res.Rejected) != 0 {
		t.Fatalf("%+v %v %v", res, err, core.Errors())
	}
	// The 0.9.0 core refuses adapter evidence on a host_port_sni target.
	vendored, err := submittest.NewCoreWithSpec(submittest.VendoredSpecPath())
	if err != nil {
		t.Fatal(err)
	}
	defer vendored.Close()
	o := endpointObservation()
	o.Adapter.Certificate.SHA1 = strings.Repeat("ab", 20)
	vcl, _ := submit.New(vendored.URL, vendored.Client())
	vres, err := vcl.Submit(context.Background(), []submit.Observation{o})
	if err != nil || len(vres.Rejected) != 1 || vres.Rejected[0].Code != "invalid_target" {
		t.Fatalf("0.9.0 core: %+v %v %v", vres, err, vendored.Errors())
	}
}

// TestProposed010FieldsAreReviewed fixes the fields the 0.10.0 proposal adds.
func TestProposed010FieldsAreReviewed(t *testing.T) {
	props, strict := schemaProps(t, submittest.CloudProposedSpecPath())
	want := map[string]string{
		"AdapterEvidence":        "bindings,certificate,custody,file,findings,kubernetes,renewal_mode,scanner,source",
		"CertificateMetadata":    "authority_key_id,ca,common_name,dns_names,issuer,key_algorithm,key_strength,not_after,not_before,self_signed,serial,sha1,sha256,signing_algorithm,subject,subject_key_id",
		"KubernetesEvidence":     "cert_manager,chain_length,cluster,hostnames,name,namespace,references",
		"KubernetesRef":          "kind,name,namespace",
		"CertManagerCertificate": "dns_names,issuer_group,issuer_kind,issuer_name,name,not_after,ready,renewal_time,revision",
		"ScannerEvidence":        "check,dns_name,file",
		"Target":                 "host,kind,path,port,provider,region,resource_id,resource_type,sni,store",
	}
	for name, fields := range want {
		if got := strings.Join(props[name], ","); got != fields {
			t.Errorf("%s fields %s, reviewed %s", name, got, fields)
		}
		if name != "Target" && strict[name] {
			t.Errorf("%s sets additionalProperties false", name)
		}
	}
}

// secretNotReadObservation is a Kubernetes TLS Secret reported from
// references and metadata only: its certificate was not read (the
// kubernetes adapter's default).
func secretNotReadObservation() submit.Observation {
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindStore, Host: "k8s.example.test", Store: "kubernetes/prod/web/www-tls"},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:     "kubernetes",
			Findings:   []submit.Finding{{Code: submit.FindingSecretNotRead}},
			Kubernetes: &submit.KubernetesEvidence{Cluster: "prod", Namespace: "web", Name: "www-tls", Hostnames: []string{"www.example.test"}},
		},
	}
}

// Under the 0.10.0 proposal a store target with kubernetes evidence and a
// secret_not_read finding may omit the certificate, with outcome reached.
// The 0.9.0 core refuses it, and so does 0.10.0 for any other shape.
func TestProposed010SecretNotRead(t *testing.T) {
	submitOne := func(spec string, o submit.Observation) (submit.Result, error) {
		t.Helper()
		core, err := submittest.NewCoreWithSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		defer core.Close()
		cl, _ := submit.New(core.URL, core.Client())
		return cl.Submit(context.Background(), []submit.Observation{o})
	}
	if res, err := submitOne(submittest.CloudProposedSpecPath(), secretNotReadObservation()); err != nil || res.Accepted != 1 || len(res.Rejected) != 0 {
		t.Fatalf("0.10.0 refused a Secret reported without its certificate: %+v %v", res, err)
	}
	// 0.9.0 does not know the finding code: the whole request is refused.
	if res, err := submitOne(submittest.VendoredSpecPath(), secretNotReadObservation()); err == nil && len(res.Rejected) == 0 {
		t.Fatalf("0.9.0 accepted a store target without a certificate: %+v", res)
	}
	bad := map[string]func(*submit.Observation){
		"outcome cert_seen": func(o *submit.Observation) { o.Outcome = submit.OutcomeCertSeen },
		"no finding":        func(o *submit.Observation) { o.Adapter.Findings = nil },
		"no kubernetes":     func(o *submit.Observation) { o.Adapter.Kubernetes = nil },
	}
	for name, mod := range bad {
		o := secretNotReadObservation()
		mod(&o)
		if res, err := submitOne(submittest.CloudProposedSpecPath(), o); err == nil && len(res.Rejected) != 1 {
			t.Errorf("%s accepted: %+v", name, res)
		}
	}
}
