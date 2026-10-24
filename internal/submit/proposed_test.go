package submit_test

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/internal/submit/submittest"
)

// Tests of the PROPOSED contract 0.5.0 additions (store and file targets,
// adapter evidence) that the WP1.1 adapters need.

func storeObservation() submit.Observation {
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindStore, Host: "web01.example.test", Store: "windows/LocalMachine/My"},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeCertSeen,
		Adapter: &submit.AdapterEvidence{
			Source:      "osquery",
			Certificate: &submit.CertificateMetadata{SHA1: strings.Repeat("ab", 20), CommonName: "web01.example.test"},
			Custody:     &submit.Custody{PrivateKey: submit.KeyUnknown},
		},
	}
}

func fileObservation() submit.Observation {
	size := int64(2048)
	return submit.Observation{
		Target:     submit.Target{Kind: submit.KindFile, Host: "app01.example.test", Path: "/opt/app/keystore.jks"},
		Method:     submit.MethodAdapter,
		ObservedAt: t0,
		Outcome:    submit.OutcomeReached,
		Adapter:    &submit.AdapterEvidence{Source: "osquery", File: &submit.FileDigest{SHA256: strings.Repeat("0f", 32), Size: &size}},
	}
}

func TestProposedAdapterObservations(t *testing.T) {
	core := newCore(t)
	cl, _ := submit.New(core.URL, core.Client())
	withPort := storeObservation()
	withPort.Target.Port = 443
	noStore := storeObservation()
	noStore.Target.Store = ""
	probeStore := storeObservation()
	probeStore.Method = submit.MethodProbe
	noEvidence := fileObservation()
	noEvidence.Adapter = nil
	noDigest := fileObservation()
	noDigest.Adapter.File = nil
	noCert := storeObservation()
	noCert.Adapter.Certificate = nil
	probeWithAdapter := submit.Observation{
		Target: submit.Target{Kind: submit.KindHostPortSNI, Host: "10.0.0.1", Port: 443},
		Method: submit.MethodProbe, ObservedAt: t0, Outcome: submit.OutcomeTimeout,
		Adapter: &submit.AdapterEvidence{Source: "osquery"},
	}
	res, err := cl.Submit(context.Background(), []submit.Observation{
		storeObservation(), fileObservation(), withPort, noStore, probeStore, noEvidence, noDigest, noCert, probeWithAdapter,
	})
	if err != nil {
		t.Fatalf("%v; core errors %v", err, core.Errors())
	}
	var codes []string
	for _, r := range res.Rejected {
		codes = append(codes, strconv.Itoa(r.Index)+":"+r.Code)
	}
	want := []string{"2:invalid_target", "3:invalid_target", "4:invalid_target", "5:invalid_adapter", "6:invalid_adapter", "7:invalid_adapter", "8:invalid_adapter"}
	if res.Accepted != 2 || !reflect.DeepEqual(codes, want) {
		t.Fatalf("accepted %d, rejected %v, want %v", res.Accepted, codes, want)
	}
}

func TestProposedSchema(t *testing.T) {
	spec, err := submittest.LoadSpec(submittest.SpecPath())
	if err != nil {
		t.Fatal(err)
	}
	store := `{"observations":[{"target":{"kind":"store","host":"h.example.test","store":"linux/system/ca-certificates"},"method":"adapter","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","adapter":{"source":"osquery","certificate":{"sha1":"` + strings.Repeat("ab", 20) + `"},"custody":{"private_key":"unknown"}}}]}`
	if err := spec.Validate("ObservationBatch", []byte(store)); err != nil {
		t.Fatalf("valid store batch refused: %v", err)
	}
	bad := map[string]string{
		"sha1 upper case":   strings.Replace(store, strings.Repeat("ab", 20), strings.Repeat("AB", 20), 1),
		"sha1 short":        strings.Replace(store, strings.Repeat("ab", 20), "abcd", 1),
		"bad custody":       strings.Replace(store, `"unknown"`, `"maybe"`, 1),
		"bad source":        strings.Replace(store, `"osquery"`, `"OS Query"`, 1),
		"unknown kind":      strings.Replace(store, `"kind":"store"`, `"kind":"cloud"`, 1),
		"key material":      strings.Replace(store, `"custody"`, `"private_key":"x","custody"`, 1),
		"empty store":       strings.Replace(store, `"linux/system/ca-certificates"`, `""`, 1),
		"ct_log needs port": `{"observations":[{"target":{"kind":"ct_log","host":"ct.example"},"method":"ct","observed_at":"2026-10-24T00:00:00Z","outcome":"cert_seen","served_chain":["MAA="],"ct_entry":{"source":"log"}}]}`,
	}
	for name, doc := range bad {
		if err := spec.Validate("ObservationBatch", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
