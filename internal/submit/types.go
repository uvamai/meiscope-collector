package submit

import "time"

// Wire types of the collector API (/collector/v1), hand-written from
// api/collector.yaml, which is vendored byte for byte from the core (core
// contract 0.4.0). Field names and JSON tags follow the schema; the fake
// core in submittest validates every request against the YAML.

// Method values (schema Observation.method).
const (
	MethodProbe   = "probe"
	MethodAdapter = "adapter"
	MethodCT      = "ct"
	MethodImport  = "import"
)

// Outcome values (schema Observation.outcome).
const (
	OutcomeReached   = "reached"
	OutcomeRefused   = "refused"
	OutcomeTimeout   = "timeout"
	OutcomeTLSFailed = "tls_failed"
	OutcomeCertSeen  = "cert_seen"
)

// Target kinds (schema Target.kind).
const (
	KindHostPortSNI = "host_port_sni"
	// KindCTLog is a CT log or search service that was read (method ct,
	// outcome cert_seen, no SNI). The core makes every certificate read
	// from it its own target.
	KindCTLog = "ct_log"
)

// MaxBatch is the largest batch the core accepts (ObservationBatch.maxItems).
const MaxBatch = 1000

// ObservationBatch is the request body.
type ObservationBatch struct {
	Observations []Observation `json:"observations"`
}

// Observation is one attempt to read a certificate from a target.
type Observation struct {
	Target     Target    `json:"target"`
	Method     string    `json:"method"`
	ObservedAt time.Time `json:"observed_at"`
	Outcome    string    `json:"outcome"`
	// ServedChain is leaf first, each certificate DER (base64 in JSON). For
	// method ct it is the logged certificate or precertificate, then the
	// chain the entry carried.
	ServedChain [][]byte   `json:"served_chain,omitempty"`
	TLS         *TLSParams `json:"tls,omitempty"`
	CTEntry     *CTEntry   `json:"ct_entry,omitempty"`
}

// Target is the locator of an observation.
type Target struct {
	Kind string `json:"kind"`
	// Host is the endpoint connected to; for ct_log the API host of the log
	// or service.
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

// TLSParams are negotiated connection parameters (probe observations).
type TLSParams struct {
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	OCSPStapled *bool  `json:"ocsp_stapled,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Plugin      string `json:"plugin,omitempty"`
}

// CT entry sources (schema CTEntry.source).
const (
	CTSourceLog         = "log"
	CTSourceCertSpotter = "cert_spotter"
	CTSourceCrtSh       = "crt_sh"
)

// CTEntry is where a ct observation's certificate was found (schema
// CTEntry); allowed with method ct only.
type CTEntry struct {
	Source string `json:"source"`
	// LogID is the 32-byte log ID (SHA-256 of the log key), base64 in JSON;
	// omitted when not known.
	LogID      []byte     `json:"log_id,omitempty"`
	EntryIndex *int64     `json:"entry_index,omitempty"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

// ObservationBatchResult is the 202 response.
type ObservationBatchResult struct {
	Accepted   int         `json:"accepted"`
	Duplicates int         `json:"duplicates"`
	Rejected   []Rejection `json:"rejected"`
}

// Rejection names an observation the core refused.
type Rejection struct {
	Index   int    `json:"index"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Problem is the error body (RFC 9457 subset).
type Problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// OwnedDomainList is the answer of GET /collector/v1/owned-domains.
type OwnedDomainList struct {
	Domains []string `json:"domains"`
}
