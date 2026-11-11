package submit

import (
	"slices"
	"time"
)

// Wire types of the collector API (/collector/v1), hand-written from
// api/collector.yaml, which is vendored byte for byte from the core (core
// contract 0.9.0, which adopted the 0.5.0 adapter additions marked
// PROPOSED below). Field names and JSON tags follow the schema; the fake
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

	// KindStore is a certificate store on a host, read by an adapter
	// (PROPOSED in contract 0.5.0, not yet adopted by the core).
	KindStore = "store"
	// KindFile is a keystore or certificate file on a host, read by an
	// adapter (PROPOSED in contract 0.5.0).
	KindFile = "file"
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
	// Adapter is adapter evidence (PROPOSED in contract 0.5.0); method
	// adapter only.
	Adapter *AdapterEvidence `json:"adapter,omitempty"`
}

// Target is the locator of an observation.
type Target struct {
	Kind string `json:"kind"`
	// Host is the endpoint connected to; for ct_log the API host of the log
	// or service.
	Host string `json:"host"`
	// Port is required for host_port_sni and ct_log and absent for store
	// and file (0 is never a valid port, so omitempty loses nothing).
	Port int    `json:"port,omitempty"`
	SNI  string `json:"sni,omitempty"`
	// Store is the store locator of a store target (PROPOSED 0.5.0).
	Store string `json:"store,omitempty"`
	// Path is the file path of a file target (PROPOSED 0.5.0).
	Path string `json:"path,omitempty"`
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
	// Reason is what the observation is counted as rejected under: Code when
	// this collector knows it, else "unknown:<code>". Set by the Client.
	Reason string `json:"-"`
}

// RejectionCodes are the rejection codes of the contract this collector was
// built against. The core may add codes (x-extensible-enum, contract 0.4.1).
var RejectionCodes = []string{
	"invalid_target", "invalid_method", "invalid_outcome", "invalid_observed_at",
	"observed_at_in_future", "invalid_served_chain", "chain_outcome_mismatch", "invalid_ct_entry",
}

// Known reports whether the rejection code is one this collector knows.
func (r Rejection) Known() bool { return slices.Contains(RejectionCodes, r.Code) }

// RejectionReason is the reason a rejection with this code is counted under.
func RejectionReason(code string) string {
	if slices.Contains(RejectionCodes, code) {
		return code
	}
	return "unknown:" + code
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

// Custody.key_custody values (PROPOSED 0.5.0).
const (
	KeyPresent = "present"
	KeyAbsent  = "absent"
	KeyUnknown = "unknown"
)

// AdapterEvidence is what an adapter read from a system the customer
// already runs (schema AdapterEvidence, PROPOSED in contract 0.5.0).
type AdapterEvidence struct {
	Source      string               `json:"source"`
	Certificate *CertificateMetadata `json:"certificate,omitempty"`
	File        *FileDigest          `json:"file,omitempty"`
	Custody     *Custody             `json:"custody,omitempty"`
	Findings    []Finding            `json:"findings,omitempty"`
}

// Finding codes (PROPOSED 0.5.0).
const (
	// FindingKeystoreNotParsed marks a keystore container (.p12, .pfx, .jks,
	// .kdb) whose content the collector does not parse. It may or may not be
	// password-protected, and the collector never guesses passwords.
	FindingKeystoreNotParsed = "keystore_not_parsed"
)

// Finding is something an adapter could not do and reports instead of
// skipping it silently (schema Finding, PROPOSED 0.5.0).
type Finding struct {
	Code string `json:"code"`
}

// Store types of FileDigest.store_type (PROPOSED 0.5.0).
const (
	StoreJKS    = "jks"
	StorePKCS12 = "pkcs12"
	StorePEM    = "pem"
	StoreNSS    = "nss"
	StoreOther  = "other"
)

// CertificateMetadata holds certificate fields as the source reports them
// (schema CertificateMetadata, PROPOSED 0.5.0). It never holds key material.
type CertificateMetadata struct {
	SHA1             string     `json:"sha1"`
	Serial           string     `json:"serial,omitempty"`
	Subject          string     `json:"subject,omitempty"`
	Issuer           string     `json:"issuer,omitempty"`
	CommonName       string     `json:"common_name,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	CA               *bool      `json:"ca,omitempty"`
	SelfSigned       *bool      `json:"self_signed,omitempty"`
	KeyAlgorithm     string     `json:"key_algorithm,omitempty"`
	KeyStrength      string     `json:"key_strength,omitempty"`
	SigningAlgorithm string     `json:"signing_algorithm,omitempty"`
	SubjectKeyID     string     `json:"subject_key_id,omitempty"`
	AuthorityKeyID   string     `json:"authority_key_id,omitempty"`
}

// FileDigest is a file's digest and size, never its contents (schema
// FileDigest, PROPOSED 0.5.0).
type FileDigest struct {
	SHA256      string     `json:"sha256"`
	Size        *int64     `json:"size,omitempty"`
	MTime       *time.Time `json:"mtime,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	Permissions string     `json:"permissions,omitempty"`
	StoreType   string     `json:"store_type,omitempty"`
}

// Custody holds custody flags (schema Custody, PROPOSED 0.5.0).
type Custody struct {
	KeyCustody string `json:"key_custody"`
}
