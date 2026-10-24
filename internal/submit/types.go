package submit

import "time"

// Wire types of POST /collector/v1/observations, hand-written from
// api/collector.yaml (core contract 0.2.0 plus the additive CT extensions
// marked "WP0.4" there). Field names and JSON tags follow the schema; the
// fake core in client_test.go validates every request against the YAML.

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
	// KindCTEntry is a certificate found in Certificate Transparency
	// (WP0.4 extension).
	KindCTEntry = "ct_entry"
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
	// ServedChain is leaf first, each certificate DER (base64 in JSON).
	ServedChain [][]byte    `json:"served_chain,omitempty"`
	TLS         *TLSParams  `json:"tls,omitempty"`
	CT          *CTEvidence `json:"ct,omitempty"`
}

// Target is the locator of an observation.
type Target struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
	// Port is required for host_port_sni and absent for ct_entry.
	Port int    `json:"port,omitempty"`
	SNI  string `json:"sni,omitempty"`
	// Fingerprint is the lowercase hex SHA-256 of the leaf DER; ct_entry only
	// (WP0.4 extension). It makes the core's idempotency key (target, method,
	// observed_at) distinct per certificate.
	Fingerprint string `json:"fingerprint,omitempty"`
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

// CT sources (schema CTEvidence.source).
const (
	SourceCertSpotter = "certspotter"
	SourceRFC6962     = "rfc6962"
	SourceStaticCT    = "static_ct"
	SourceCrtSh       = "crtsh"
)

// CT entry types (schema CTEvidence.entry_type).
const (
	EntryX509    = "x509_entry"
	EntryPrecert = "precert_entry"
)

// CTEvidence is the CT log entry (or search-service record) that produced an
// observation with method ct (WP0.4 extension).
type CTEvidence struct {
	Source        string   `json:"source"`
	MatchedDomain string   `json:"matched_domain"`
	DNSNames      []string `json:"dns_names,omitempty"`
	EntryType     string   `json:"entry_type,omitempty"`
	// LogURL, EntryIndex, EntryTimestamp and LeafInput are set for entries
	// read from a log (rfc6962, static_ct); ExtraData for rfc6962 only.
	LogURL         string     `json:"log_url,omitempty"`
	LogID          []byte     `json:"log_id,omitempty"`
	EntryIndex     *int64     `json:"entry_index,omitempty"`
	EntryTimestamp *time.Time `json:"entry_timestamp,omitempty"`
	LeafInput      []byte     `json:"leaf_input,omitempty"`
	ExtraData      []byte     `json:"extra_data,omitempty"`
	// SourceID is the record id at a search service (Cert Spotter issuance
	// id, crt.sh certificate id).
	SourceID string `json:"source_id,omitempty"`
	// SCTs are the SCTs embedded in the certificate: which logs hold it.
	SCTs []SCT `json:"scts,omitempty"`
}

// SCT is an embedded signed certificate timestamp.
type SCT struct {
	LogID     []byte    `json:"log_id"`
	Timestamp time.Time `json:"timestamp"`
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
