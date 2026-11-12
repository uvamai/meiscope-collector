package aws

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
	"github.com/uvamai/meiscope-collector/internal/adapter/cloud"
	"github.com/uvamai/meiscope-collector/internal/submit"
)

// API versions of the Query protocol services.
const (
	elbv2Version   = "2015-12-01"
	elbClassicVers = "2012-06-01"
)

type elbv2LB struct {
	LoadBalancerArn string `xml:"LoadBalancerArn"`
	DNSName         string `xml:"DNSName"`
	Scheme          string `xml:"Scheme"`
}

type elbv2LBsOut struct {
	LoadBalancers []elbv2LB `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
	NextMarker    string    `xml:"DescribeLoadBalancersResult>NextMarker"`
}

type elbv2Cert struct {
	CertificateArn string `xml:"CertificateArn"`
	IsDefault      bool   `xml:"IsDefault"`
}

type elbv2Listener struct {
	ListenerArn  string      `xml:"ListenerArn"`
	Port         int         `xml:"Port"`
	Protocol     string      `xml:"Protocol"`
	Certificates []elbv2Cert `xml:"Certificates>member"`
}

type elbv2ListenersOut struct {
	Listeners  []elbv2Listener `xml:"DescribeListenersResult>Listeners>member"`
	NextMarker string          `xml:"DescribeListenersResult>NextMarker"`
}

type elbv2ListenerCertsOut struct {
	Certificates []elbv2Cert `xml:"DescribeListenerCertificatesResult>Certificates>member"`
	NextMarker   string      `xml:"DescribeListenerCertificatesResult>NextMarker"`
}

type classicLB struct {
	LoadBalancerName string `xml:"LoadBalancerName"`
	DNSName          string `xml:"DNSName"`
	Scheme           string `xml:"Scheme"`
	Listeners        []struct {
		Protocol         string `xml:"Listener>Protocol"`
		LoadBalancerPort int    `xml:"Listener>LoadBalancerPort"`
		SSLCertificateID string `xml:"Listener>SSLCertificateId"`
	} `xml:"ListenerDescriptions>member"`
}

type classicLBsOut struct {
	LoadBalancers []classicLB `xml:"DescribeLoadBalancersResult>LoadBalancerDescriptions>member"`
	NextMarker    string      `xml:"DescribeLoadBalancersResult>NextMarker"`
}

// tlsProtocols are the listener protocols that present a certificate.
var tlsProtocols = map[string]bool{"HTTPS": true, "TLS": true, "SSL": true}

func (s *syncer) elbQuery(ctx context.Context, region, op, version string, params url.Values, out any) error {
	return s.c.query(ctx, region, "elasticloadbalancing", s.c.endpoint("elasticloadbalancing", region), op, version, params, out)
}

// syncELB reads Application and Network Load Balancer listeners (elbv2)
// and Classic Load Balancer listeners that present a certificate.
func (s *syncer) syncELB(ctx context.Context, region string) ([]submit.Observation, error) {
	lbs, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, marker string) (adapter.Page[elbv2LB], error) {
		var out elbv2LBsOut
		p := url.Values{"PageSize": {"400"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		if err := s.elbQuery(ctx, region, "DescribeLoadBalancers", elbv2Version, p, &out); err != nil {
			return adapter.Page[elbv2LB]{}, err
		}
		return adapter.Page[elbv2LB]{Items: out.LoadBalancers, Next: out.NextMarker}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("elbv2 %s: describe load balancers: %w", region, err)
	}
	var obs []submit.Observation
	for _, lb := range lbs {
		ls, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, marker string) (adapter.Page[elbv2Listener], error) {
			var out elbv2ListenersOut
			p := url.Values{"LoadBalancerArn": {lb.LoadBalancerArn}, "PageSize": {"400"}}
			if marker != "" {
				p.Set("Marker", marker)
			}
			if err := s.elbQuery(ctx, region, "DescribeListeners", elbv2Version, p, &out); err != nil {
				return adapter.Page[elbv2Listener]{}, err
			}
			return adapter.Page[elbv2Listener]{Items: out.Listeners, Next: out.NextMarker}, nil
		})
		if err != nil {
			return nil, fmt.Errorf("elbv2 %s: describe listeners: %w", region, err)
		}
		for _, l := range ls {
			if !tlsProtocols[l.Protocol] {
				continue
			}
			// DescribeListeners shows only the default certificate; the
			// listener's certificate list has the SNI certificates too.
			extra, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, marker string) (adapter.Page[elbv2Cert], error) {
				var out elbv2ListenerCertsOut
				p := url.Values{"ListenerArn": {l.ListenerArn}, "PageSize": {"400"}}
				if marker != "" {
					p.Set("Marker", marker)
				}
				if err := s.elbQuery(ctx, region, "DescribeListenerCertificates", elbv2Version, p, &out); err != nil {
					return adapter.Page[elbv2Cert]{}, err
				}
				return adapter.Page[elbv2Cert]{Items: out.Certificates, Next: out.NextMarker}, nil
			})
			if err != nil {
				return nil, fmt.Errorf("elbv2 %s: describe listener certificates: %w", region, err)
			}
			obs = append(obs, s.listenerObservation(region, "elbv2_listener", l.ListenerArn, lb.DNSName, lb.Scheme, l.Port, l.Protocol, append(l.Certificates, extra...)))
		}
	}

	classic, err := adapter.Paginate(ctx, s.maxPages, func(ctx context.Context, marker string) (adapter.Page[classicLB], error) {
		var out classicLBsOut
		p := url.Values{"PageSize": {"400"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		if err := s.elbQuery(ctx, region, "DescribeLoadBalancers", elbClassicVers, p, &out); err != nil {
			return adapter.Page[classicLB]{}, err
		}
		return adapter.Page[classicLB]{Items: out.LoadBalancers, Next: out.NextMarker}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("elb classic %s: describe load balancers: %w", region, err)
	}
	for _, lb := range classic {
		for _, l := range lb.Listeners {
			if !tlsProtocols[l.Protocol] || l.SSLCertificateID == "" {
				continue
			}
			// Classic listeners have no ARN of their own: the identifier is
			// the load balancer's ARN plus /listener/<port> (the account is
			// taken from the certificate's ARN).
			id := "arn:" + partitionOf(l.SSLCertificateID) + ":elasticloadbalancing:" + region + ":" + arnAccount(l.SSLCertificateID) +
				":loadbalancer/" + lb.LoadBalancerName + "/listener/" + strconv.Itoa(l.LoadBalancerPort)
			obs = append(obs, s.listenerObservation(region, "elb_listener", id, lb.DNSName, lb.Scheme, l.LoadBalancerPort, l.Protocol,
				[]elbv2Cert{{CertificateArn: l.SSLCertificateID, IsDefault: true}}))
		}
	}
	return obs, nil
}

func partitionOf(arn string) string {
	if p := arnPart(arn, 1); p != "" {
		return p
	}
	return "aws"
}

// listenerObservation maps a TLS listener: outcome reached (the listener was
// read; the certificate itself is observed through ACM or IAM), the
// endpoint, and a binding per certificate, default first.
func (s *syncer) listenerObservation(region, service, id, dns, scheme string, port int, protocol string, certs []elbv2Cert) submit.Observation {
	merged := map[string]bool{}
	var order []string
	for _, c := range certs {
		if c.CertificateArn == "" {
			continue
		}
		if _, seen := merged[c.CertificateArn]; !seen {
			order = append(order, c.CertificateArn)
		}
		merged[c.CertificateArn] = merged[c.CertificateArn] || c.IsDefault
	}
	sort.SliceStable(order, func(i, j int) bool {
		if merged[order[i]] != merged[order[j]] {
			return merged[order[i]]
		}
		return order[i] < order[j]
	})
	ep := &submit.Endpoint{DNSName: strings.ToLower(dns), Protocol: protocol, Scheme: scheme}
	if port >= 1 && port <= 65535 {
		ep.Port = port
	}
	o := submit.Observation{
		Target: submit.Target{
			Kind: submit.KindCloudResource, Host: s.c.endpoint("elasticloadbalancing", region),
			Cloud: &submit.CloudResource{Provider: Provider, Service: service, ResourceID: id, Region: region, Account: arnAccount(id)},
		},
		Method: submit.MethodAdapter, ObservedAt: s.now, Outcome: submit.OutcomeReached,
		Adapter: &submit.AdapterEvidence{Source: Source, Hostnames: cloud.Hostnames([]string{dns}), Endpoint: ep},
	}
	for _, arn := range order {
		svc := arnService(arn) // acm or iam
		o.Adapter.Bindings = append(o.Adapter.Bindings, submit.Binding{ResourceID: arn, Service: svc, Region: arnRegion(arn), IsDefault: cloud.Bool(merged[arn])})
	}
	return o
}
