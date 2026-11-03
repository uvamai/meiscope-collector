// Package runner probes the endpoints listed in a verified scope.
//
// Meiscope probes only the endpoints you list: every attempt is one of the
// scope's targets (host or IP, port), with the server name the scope gives
// for it. There is no range expansion and no port discovery beyond that one
// connection; a closed port is reported as a refused or timed-out attempt.
package runner

import (
	"net/netip"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/scope"
	"github.com/uvamai/meiscope-collector/pkg/probe"
)

// Job is one listed target with the server names to send on it, in order.
// A job's attempts run one after another, so a target never has two
// connections from this collector open at once.
type Job struct {
	Target scope.Target
	// IP is set when the target is an IP address.
	IP netip.Addr
	// SNIs are the names to send; "" means none (an IP target without
	// names_by_ip). A host-name target sends its own name.
	SNIs []string
}

// Plan lists the jobs for sc in target order, leaving out targets the
// scope's deny list covers. It never touches the network.
func Plan(sc *scope.Scope) (jobs []Job, denied []scope.Target) {
	d := parseDeny(sc.Policy.Deny)
	for _, t := range sc.Targets {
		j := Job{Target: t}
		if a, err := netip.ParseAddr(t.Host); err == nil {
			j.IP = a.Unmap()
			if d.addr(j.IP) {
				denied = append(denied, t)
				continue
			}
			j.SNIs = []string{""}
			if names := sc.NamesByIP[j.IP.String()]; len(names) > 0 {
				j.SNIs = nil
				for _, n := range names {
					if !d.name(strings.ToLower(n)) {
						j.SNIs = append(j.SNIs, strings.ToLower(n))
					}
				}
				if len(j.SNIs) == 0 {
					denied = append(denied, t)
					continue
				}
			}
		} else {
			if d.name(t.Host) {
				denied = append(denied, t)
				continue
			}
			j.SNIs = []string{t.Host}
		}
		jobs = append(jobs, j)
	}
	return jobs, denied
}

// Mode maps a target's protocol hint to the probe's STARTTLS mode; no hint
// lets the probe choose by port.
func Mode(protocol string) string {
	switch protocol {
	case scope.ProtocolTLS:
		return probe.StartTLSNone
	case scope.ProtocolSMTPStartTLS:
		return probe.StartTLSSMTP
	case scope.ProtocolIMAPStartTLS:
		return probe.StartTLSIMAP
	case scope.ProtocolPOP3StartTLS:
		return probe.StartTLSPOP3
	case scope.ProtocolLDAPStartTLS:
		return probe.StartTLSLDAP
	case scope.ProtocolRDP:
		return probe.StartTLSRDP
	case scope.ProtocolPostgres:
		return probe.StartTLSPostgres
	case scope.ProtocolMySQL:
		return probe.StartTLSMySQL
	case scope.ProtocolMSSQL:
		return probe.StartTLSMSSQL
	default:
		return probe.StartTLSAuto
	}
}

// deny is the scope's deny list: names (exact or DNS suffix) and addresses
// or prefixes.
type deny struct {
	names    []string
	prefixes []netip.Prefix
}

func parseDeny(entries []string) deny {
	var d deny
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case strings.Contains(e, "/"):
			if p, err := netip.ParsePrefix(e); err == nil {
				d.prefixes = append(d.prefixes, p.Masked())
			}
		default:
			if a, err := netip.ParseAddr(e); err == nil {
				d.prefixes = append(d.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
				continue
			}
			d.names = append(d.names, strings.TrimPrefix(strings.TrimSuffix(e, "."), "."))
		}
	}
	return d
}

func (d deny) name(n string) bool {
	for _, s := range d.names {
		if n == s || strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}

func (d deny) addr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range d.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
