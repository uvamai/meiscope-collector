package aws

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// acmKeyTypes asks ListCertificates for every key type: without Includes it
// returns RSA_2048 certificates only.
var acmKeyTypes = []string{"RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"}

type acmListIn struct {
	MaxItems  int                 `json:"MaxItems"`
	NextToken string              `json:"NextToken,omitempty"`
	Includes  map[string][]string `json:"Includes"`
}

type acmListOut struct {
	CertificateSummaryList []struct {
		CertificateArn string `json:"CertificateArn"`
	} `json:"CertificateSummaryList"`
	NextToken string `json:"NextToken"`
}

type acmArnIn struct {
	CertificateArn string `json:"CertificateArn"`
}

// acmDetail is the part of DescribeCertificate the adapter maps. Times are
// epoch seconds.
type acmDetail struct {
	CertificateArn          string   `json:"CertificateArn"`
	DomainName              string   `json:"DomainName"`
	SubjectAlternativeNames []string `json:"SubjectAlternativeNames"`
	Serial                  string   `json:"Serial"`
	Issuer                  string   `json:"Issuer"`
	Status                  string   `json:"Status"`
	Type                    string   `json:"Type"`
	NotBefore               *float64 `json:"NotBefore"`
	NotAfter                *float64 `json:"NotAfter"`
	InUseBy                 []string `json:"InUseBy"`
	RenewalEligibility      string   `json:"RenewalEligibility"`
	RenewalSummary          *struct {
		RenewalStatus string `json:"RenewalStatus"`
	} `json:"RenewalSummary"`
}

type acmDescribeOut struct {
	Certificate acmDetail `json:"Certificate"`
}

// acmGetOut is GetCertificate's answer: the public certificate and its
// chain, PEM. GetCertificate never returns a private key.
type acmGetOut struct {
	Certificate      string `json:"Certificate"`
	CertificateChain string `json:"CertificateChain"`
}

// Resource types (CloudFormation type names) of the observed resources.
const (
	TypeACMCertificate       = "AWS::CertificateManager::Certificate"
	TypeIAMServerCertificate = "AWS::IAM::ServerCertificate"
)

func (s *syncer) syncACM(ctx context.Context, region string, binds listenerBindings) ([]submit.Observation, error) {
	arns, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, token string) (adapter.Page[string], error) {
		var out acmListOut
		in := acmListIn{MaxItems: 100, NextToken: token, Includes: map[string][]string{"keyTypes": acmKeyTypes}}
		if err := s.c.acm(ctx, region, "ListCertificates", in, &out); err != nil {
			return adapter.Page[string]{}, err
		}
		p := adapter.Page[string]{Next: out.NextToken}
		for _, c := range out.CertificateSummaryList {
			p.Items = append(p.Items, c.CertificateArn)
		}
		return p, nil
	})
	if err != nil {
		return nil, fmt.Errorf("acm %s: list certificates: %w", region, err)
	}
	var obs []submit.Observation
	for _, arn := range arns {
		var d acmDescribeOut
		if err := s.c.acm(ctx, region, "DescribeCertificate", acmArnIn{arn}, &d); err != nil {
			return nil, fmt.Errorf("acm %s: %w", region, err)
		}
		var chain [][]byte
		if d.Certificate.Status == "ISSUED" {
			var g acmGetOut
			if err := s.c.acm(ctx, region, "GetCertificate", acmArnIn{arn}, &g); err != nil {
				return nil, fmt.Errorf("acm %s: %w", region, err)
			}
			if chain, err = cloud.ParsePEMChain(g.Certificate, g.CertificateChain); err != nil {
				return nil, fmt.Errorf("acm %s: GetCertificate: %w", region, err)
			}
		}
		o, err := s.mapACM(region, d.Certificate, chain, binds)
		if err != nil {
			return nil, err
		}
		obs = append(obs, o)
	}
	return obs, nil
}

// acmRenewalMode says what ACM proves about renewal: ACM renews the
// certificates it issues (public and private) while they are eligible;
// it never renews imported ones. Anything else is unknown, never guessed.
func acmRenewalMode(d acmDetail) string {
	switch {
	case (d.Type == "AMAZON_ISSUED" || d.Type == "PRIVATE") && d.RenewalEligibility == "ELIGIBLE":
		return submit.RenewalExternalAutomated
	case d.Type == "IMPORTED":
		return submit.RenewalManual
	}
	return submit.RenewalUnknown
}

// acmStatus is the certificate status, with the renewal status when ACM
// reports one (for example "ISSUED; renewal SUCCESS").
func acmStatus(d acmDetail) string {
	st := d.Status
	if d.RenewalSummary != nil && d.RenewalSummary.RenewalStatus != "" {
		st += "; renewal " + d.RenewalSummary.RenewalStatus
	}
	return clip(st, 64)
}

func (s *syncer) mapACM(region string, d acmDetail, chain [][]byte, binds listenerBindings) (submit.Observation, error) {
	o := submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: s.c.endpoint("acm", region),
			Provider: Provider, ResourceID: d.CertificateArn, ResourceType: TypeACMCertificate, Region: region,
		},
		Method:     submit.MethodAdapter,
		ObservedAt: s.now,
		Outcome:    submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:      Source,
			RenewalMode: acmRenewalMode(d),
			Bindings:    takeBindings(binds, d.CertificateArn, s.st),
			InUseBy:     capList(d.InUseBy, cloud.MaxBindings),
			CloudCertificate: &submit.CloudCertificate{
				ID: d.CertificateArn, Type: d.Type, Status: acmStatus(d), Issuer: d.Issuer,
				Serial: clip(d.Serial, 128), NotBefore: epoch(d.NotBefore), NotAfter: epoch(d.NotAfter),
				Hostnames: cloud.Hostnames(d.SubjectAlternativeNames, []string{d.DomainName}),
			},
		},
	}
	if len(chain) > 0 {
		m, err := cloud.Metadata(chain[0])
		if err != nil {
			return submit.Observation{}, fmt.Errorf("acm %s: %w", region, err)
		}
		o.Outcome, o.ServedChain, o.Adapter.Certificate = submit.OutcomeCertSeen, chain, m
	}
	return o, nil
}

// takeBindings returns (and removes) the listener bindings of a
// certificate, at most cloud.MaxBindings.
func takeBindings(binds listenerBindings, arn string, st map[string]int) []submit.Binding {
	b := binds[arn]
	delete(binds, arn)
	if len(b) > cloud.MaxBindings {
		st[StatBindingsCapped] += len(b) - cloud.MaxBindings
		b = b[:cloud.MaxBindings]
	}
	return b
}

func capList(l []string, n int) []string {
	var out []string
	for _, s := range l {
		if s != "" && len(s) <= 2048 && len(out) < n {
			out = append(out, s)
		}
	}
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func epoch(f *float64) *time.Time {
	if f == nil || *f <= 0 {
		return nil
	}
	sec, frac := math.Modf(*f)
	return cloud.TimePtr(time.Unix(int64(sec), int64(frac*1e9)))
}

// ARN fields: arn:partition:service:region:account:resource.
func arnPart(arn string, i int) string {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" {
		return ""
	}
	return p[i]
}

func arnAccount(arn string) string { return arnPart(arn, 4) }
