package runner

import (
	"time"

	"github.com/uvamai/meiscope-collector/internal/submit"
	"github.com/uvamai/meiscope-collector/pkg/probe"
)

// PluginName is the TLSParams.plugin of every probe observation.
const PluginName = "probe"

// ContractOutcome maps a probe outcome to the collector contract's
// Observation.outcome (contract 0.8.1, unchanged): no_tls is "reached"
// (connected, no certificate offered) and handshake_failed is "tls_failed".
func ContractOutcome(o string) string {
	switch o {
	case probe.OutcomeOK:
		return submit.OutcomeCertSeen
	case probe.OutcomeRefused:
		return submit.OutcomeRefused
	case probe.OutcomeTimeout:
		return submit.OutcomeTimeout
	case probe.OutcomeNoTLS:
		return submit.OutcomeReached
	default:
		return submit.OutcomeTLSFailed
	}
}

// observation builds the observation of one attempt; res is nil unless the
// outcome is ok. Only certificates and negotiated parameters are carried:
// never server text.
func observation(j Job, sni string, at time.Time, outcome string, res *probe.Result) submit.Observation {
	mode := Mode(j.Target.Protocol)
	if res != nil {
		mode = res.StartTLS
	} else if t, err := probe.Validate(probe.Target{Host: j.Target.Host, Port: j.Target.Port, StartTLS: mode}); err == nil {
		mode = t.StartTLS // the mode the probe chose by port
	}
	o := submit.Observation{
		Target:     submit.Target{Kind: submit.KindHostPortSNI, Host: j.Target.Host, Port: j.Target.Port, SNI: sni},
		Method:     submit.MethodProbe,
		ObservedAt: at,
		Outcome:    ContractOutcome(outcome),
		TLS:        &submit.TLSParams{Protocol: protocolName(mode, j.Target.Port), Plugin: PluginName},
	}
	if res != nil {
		for _, c := range res.Chain {
			o.ServedChain = append(o.ServedChain, c.Raw)
		}
		stapled := res.OCSPStapled
		o.TLS.Version, o.TLS.CipherSuite, o.TLS.ALPN, o.TLS.OCSPStapled = res.TLSVersion, res.CipherSuite, res.ALPN, &stapled
	}
	return o
}

// protocolName is TLSParams.protocol: the application protocol, e.g.
// "https", "smtp-starttls", "ldaps".
func protocolName(mode string, port int) string {
	switch mode {
	case probe.StartTLSSMTP:
		return "smtp-starttls"
	case probe.StartTLSIMAP:
		return "imap-starttls"
	case probe.StartTLSPOP3:
		return "pop3-starttls"
	case probe.StartTLSLDAP:
		return "ldap-starttls"
	case probe.StartTLSRDP:
		return "rdp"
	case probe.StartTLSPostgres:
		return "postgres"
	case probe.StartTLSMySQL:
		return "mysql"
	case probe.StartTLSMSSQL:
		return "mssql"
	case probe.StartTLSNone, probe.StartTLSAuto:
		switch port {
		case 636:
			return "ldaps"
		case 465:
			return "smtps"
		case 993:
			return "imaps"
		case 995:
			return "pop3s"
		case 5986:
			return "winrm-https"
		case 443, 4443, 8443, 9443, 10443:
			return "https"
		}
	}
	return "tls"
}
