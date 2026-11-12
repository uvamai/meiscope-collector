package aws

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

const iamVersion = "2010-05-08"

// iamSignRegion is where the global IAM endpoint is signed (aws partition).
const iamSignRegion = "us-east-1"

type iamCertMeta struct {
	ServerCertificateName string    `xml:"ServerCertificateName"`
	ServerCertificateID   string    `xml:"ServerCertificateId"`
	Arn                   string    `xml:"Arn"`
	Expiration            time.Time `xml:"Expiration"`
}

type iamListOut struct {
	List        []iamCertMeta `xml:"ListServerCertificatesResult>ServerCertificateMetadataList>member"`
	IsTruncated bool          `xml:"ListServerCertificatesResult>IsTruncated"`
	Marker      string        `xml:"ListServerCertificatesResult>Marker"`
}

// iamGetOut is GetServerCertificate's answer: public certificate and chain
// only. IAM never returns the private key of a server certificate.
type iamGetOut struct {
	Body  string `xml:"GetServerCertificateResult>ServerCertificate>CertificateBody"`
	Chain string `xml:"GetServerCertificateResult>ServerCertificate>CertificateChain"`
}

// syncIAM reads IAM server certificates (global; used by Classic and
// Application Load Balancers and CloudFront in older setups).
func (s *syncer) syncIAM(ctx context.Context, binds listenerBindings) ([]submit.Observation, error) {
	host := s.c.endpoint("iam", "")
	metas, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, marker string) (adapter.Page[iamCertMeta], error) {
		var out iamListOut
		p := url.Values{"MaxItems": {"100"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		if err := s.c.query(ctx, iamSignRegion, "iam", host, "ListServerCertificates", iamVersion, p, &out); err != nil {
			return adapter.Page[iamCertMeta]{}, err
		}
		pg := adapter.Page[iamCertMeta]{Items: out.List}
		if out.IsTruncated {
			pg.Next = out.Marker
		}
		return pg, nil
	})
	if err != nil {
		return nil, fmt.Errorf("iam: list server certificates: %w", err)
	}
	var obs []submit.Observation
	for _, m := range metas {
		var g iamGetOut
		if err := s.c.query(ctx, iamSignRegion, "iam", host, "GetServerCertificate", iamVersion, url.Values{"ServerCertificateName": {m.ServerCertificateName}}, &g); err != nil {
			return nil, fmt.Errorf("iam: %w", err)
		}
		chain, err := cloud.ParsePEMChain(g.Body, g.Chain)
		if err != nil {
			return nil, fmt.Errorf("iam: GetServerCertificate: %w", err)
		}
		o := submit.Observation{
			Target: submit.Target{
				Kind: submit.KindCloudResource, Host: host,
				Provider: Provider, ResourceID: m.Arn, ResourceType: TypeIAMServerCertificate,
			},
			Method: submit.MethodAdapter, ObservedAt: s.now, Outcome: submit.OutcomeReached,
			Adapter: &submit.AdapterEvidence{
				Source: Source,
				// IAM stores uploaded certificates; nothing renews them.
				RenewalMode:      submit.RenewalManual,
				Bindings:         takeBindings(binds, m.Arn, s.st),
				CloudCertificate: &submit.CloudCertificate{ID: m.Arn, NotAfter: cloud.TimePtr(m.Expiration)},
			},
		}
		if len(chain) > 0 {
			md, err := cloud.Metadata(chain[0])
			if err != nil {
				return nil, fmt.Errorf("iam: %w", err)
			}
			leaf, _ := x509.ParseCertificate(chain[0])
			o.Outcome, o.ServedChain, o.Adapter.Certificate = submit.OutcomeCertSeen, chain, md
			o.Adapter.CloudCertificate.Hostnames = cloud.Hostnames(leaf.DNSNames)
		}
		obs = append(obs, o)
	}
	return obs, nil
}
