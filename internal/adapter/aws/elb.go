package aws

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
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

// listenerBindings maps a certificate ARN to the TLS listeners that present
// it. Load balancer listeners are not observations of their own: in the
// 0.10.0 proposal a listener is a binding (host name, port, listener ID) of
// the certificate it serves.
type listenerBindings map[string][]submit.Binding

func (lb listenerBindings) add(certARN, dns string, port int, listenerID string) {
	dns = strings.TrimSuffix(strings.ToLower(dns), ".")
	if certARN == "" || dns == "" || len(dns) > 253 {
		return
	}
	b := submit.Binding{Hostname: dns, ResourceID: listenerID}
	if port >= 1 && port <= 65535 {
		b.Port = port
	}
	for _, x := range lb[certARN] {
		if x == b {
			return
		}
	}
	lb[certARN] = append(lb[certARN], b)
}

// syncELB reads Application and Network Load Balancer listeners (elbv2)
// and Classic Load Balancer listeners that present a certificate, and
// records them as bindings of their certificates (ACM or IAM).
func (s *syncer) syncELB(ctx context.Context, region string, out listenerBindings) error {
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
		return fmt.Errorf("elbv2 %s: describe load balancers: %w", region, err)
	}
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
			return fmt.Errorf("elbv2 %s: describe listeners: %w", region, err)
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
				return fmt.Errorf("elbv2 %s: describe listener certificates: %w", region, err)
			}
			for _, c := range append(l.Certificates, extra...) {
				out.add(c.CertificateArn, lb.DNSName, l.Port, l.ListenerArn)
			}
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
		return fmt.Errorf("elb classic %s: describe load balancers: %w", region, err)
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
			out.add(l.SSLCertificateID, lb.DNSName, l.LoadBalancerPort, id)
		}
	}
	return nil
}

func partitionOf(arn string) string {
	if p := arnPart(arn, 1); p != "" {
		return p
	}
	return "aws"
}
