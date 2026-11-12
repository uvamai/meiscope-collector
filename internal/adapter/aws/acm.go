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

func (s *syncer) syncACM(ctx context.Context, region string) ([]submit.Observation, error) {
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
		o, err := s.mapACM(region, d.Certificate, chain)
		if err != nil {
			return nil, err
		}
		obs = append(obs, o)
	}
	return obs, nil
}

// acmRenewal says what ACM proves about renewal: ACM renews the
// certificates it issues (public and private) while they are eligible;
// it never renews imported ones. Anything else is unknown, never guessed.
func acmRenewal(d acmDetail) *submit.Renewal {
	r := &submit.Renewal{Mode: submit.RenewalUnknown, Eligibility: d.RenewalEligibility}
	if d.RenewalSummary != nil {
		r.Status = d.RenewalSummary.RenewalStatus
	}
	switch {
	case (d.Type == "AMAZON_ISSUED" || d.Type == "PRIVATE") && d.RenewalEligibility == "ELIGIBLE":
		r.Mode, r.ManagedBy = submit.RenewalExternalAutomated, "aws_acm"
	case d.Type == "IMPORTED":
		r.Mode = submit.RenewalManual
	}
	return r
}

func (s *syncer) mapACM(region string, d acmDetail, chain [][]byte) (submit.Observation, error) {
	host := s.c.endpoint("acm", region)
	o := submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: host,
			Cloud: &submit.CloudResource{Provider: Provider, Service: "acm", ResourceID: d.CertificateArn, Region: region, Account: arnAccount(d.CertificateArn)},
		},
		Method:     submit.MethodAdapter,
		ObservedAt: s.now,
		Outcome:    submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{
			Source:    Source,
			Hostnames: cloud.Hostnames(d.SubjectAlternativeNames, []string{d.DomainName}),
			Renewal:   acmRenewal(d),
			CloudCertificate: &submit.CloudCertificate{
				ID: d.CertificateArn, Type: d.Type, Status: d.Status, Issuer: d.Issuer,
				Serial: d.Serial, NotBefore: epoch(d.NotBefore), NotAfter: epoch(d.NotAfter),
			},
		},
	}
	for _, u := range d.InUseBy {
		o.Adapter.Bindings = append(o.Adapter.Bindings, submit.Binding{ResourceID: u, Service: arnService(u), Region: arnRegion(u)})
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

func arnService(arn string) string { return arnPart(arn, 2) }
func arnRegion(arn string) string  { return arnPart(arn, 3) }
func arnAccount(arn string) string { return arnPart(arn, 4) }
