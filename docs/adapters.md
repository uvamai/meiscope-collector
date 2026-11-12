# Adapters

An adapter reads certificate data from a system the customer already runs
(osquery or Fleet, a cloud API, a scanner export) and maps it to observations
with `method: adapter`. Adapters implement ADR-0016: leverage what is
deployed instead of adding an endpoint agent.

Rules for every adapter:

- It only reads. It never scans networks, probes ports or connects to hosts
  other than the one system it is configured for. Network probing belongs to
  the probe plugins under ScanPolicy, not here.
- Credentials are named by reference in the configuration and resolved just
  in time through `credential.Source` (the age-encrypted `FileSource`; see
  docs/install.md; the environment source exists only in `devcredentials`
  builds). A value is a `credential.Secret`,
  which never prints. Settings may not hold credentials: `Config.Check`
  rejects setting names like `token`/`password` and values shaped like keys
  or bearer tokens, and its errors never repeat the value.
- No credential or key material reaches a log, an error, an observation or a
  fixture. `adapter.Redact` and `adapter.FindSecrets` help; a test greps all
  fixtures and packs for secret patterns.
- Every adapter ships redacted fixtures under `testdata/adapters/<name>/`
  (synthetic host names such as `web01.example.test` only) and a README there
  that says which are recorded and which are hand-made.

## The interface

```go
type Adapter interface {
    Describe() Description
    Validate(cfg Config) error                              // no I/O
    Sync(ctx context.Context, cfg Config, since Cursor) (Result, error)
}
```

`Sync` returns observations and the new `Cursor` (an opaque string; use
`adapter.EncodeCursor`/`DecodeCursor` for JSON state). It must be
deterministic for the same inputs and cursor. Register the adapter in
`init()` with `adapter.Register(name, factory)`; a factory gets an
`adapter.Env` (proxy-aware `HTTP` client, `Creds`, `Clock`, `Log`) and the
command imports the package for its side effect (`cmd/meiscope-collector/adapter.go`).

### Configuration

```json
[{"name": "fleet-prod", "adapter": "osquery",
  "settings": {"mode": "fleet", "url": "https://fleet.example.test"},
  "credentials": {"api_token": "fleet_api_token"}}]
```

`credentials` maps a purpose to a `credential.Source` reference
(`^[a-z][a-z0-9_]{0,63}$`). Read it with `cfg.Credential(ctx, env.Creds, "api_token")`.

### Helpers

| Need | Helper |
|---|---|
| Paged APIs | `adapter.Paginate` (page cap, repeated-token guard, context aware) |
| Rate limits | `adapter.NewLimiter(clock, perSecond)` |
| Delta since last run | the cursor; `adapter.CursorStore` persists it |
| Retries | `internal/retry` (`Retry-After`, backoff) as in the Fleet client |
| Tests without the network | `adapter/fixture.Load(dir)` is an `http.RoundTripper` replaying recorded exchanges |
| Secrets in text | `adapter.Redact`, `adapter.LooksSecret`, `adapter.FindSecrets` |

### Cursor discipline

`adapter.RunOnce` hands the observations to the sink (the durable buffer, or
the submit client) and only then stores the cursor. If either step fails the
same delta is read again next run; the core de-duplicates.

### Mapping observations

`api/collector.yaml` is the core's contract, vendored byte for byte
(currently 0.8.1); the core owns it. Certificate stores and files are not
network endpoints, so the osquery adapter needs the target kinds `store` and
`file` and the `adapter` evidence object. These are a PROPOSAL in
`api/proposed/collector-0.5.0-proposed.yaml` (additive; `task
contract:proposal` runs oasdiff and reports no breaking change; the new
objects are open, with no `additionalProperties: false`).

**The core must adopt the proposal before a collector sends any of it.** The
core's ingest rejects unknown fields today (`additionalProperties: false` on
Observation, Target and CTEntry in `api/openapi/collector.yaml`, and
`DisallowUnknownFields` in `internal/api/observations.go` of the core). So
the requirement "the core accepts and ignores unknown fields" is a
requirement on the core's next contract version, and the collector keeps
everything behind `MEISCOPE_FEATURE_LOCAL_STORE_V1` (off by default): with it
off an adapter emits nothing the current core would reject, and logs and
counts what it skipped (`skipped_feature_disabled`); with it on it emits the
proposed shape.

Only public certificate data and file metadata may be carried. A guard test
(`internal/submit/contract_test.go`) rejects key-shaped property names,
patterns and examples in both contract files and pins the exact set of new
fields. Test every mapping against `submittest.NewProposedCore()` (the
proposal) and, for what is emitted by default, `submittest.NewCore()` (the
vendored contract).

### Contract drift

`task contract:diff CORE=<path to the core's api/openapi/collector.yaml>`
compares the vendored file with the core's, lists the changes with oasdiff,
and runs the tests that send the collector's output (CT poller, probe-style
shapes, owned domains, batching) to the fake core validating against the
core's file (`MEISCOPE_CONTRACT`). `STRICT=1` also fails on any difference.
Real-core ingestion is left to the Phase 0 integration step.

## Azure, Entra ID and Defender

`azure_key_vault`, `azure_app_service`, `azure_app_gateway`, `entra_id` and
`defender_tvm` are described in [azure.md](azure.md). The first four emit
`cloud_resource` targets, a PROPOSAL in
`api/proposed/collector-0.10.0-proposed.yaml` (additive over 0.9.0), kept
behind `MEISCOPE_FEATURE_CLOUD_RESOURCE_V1` (off by default); test them
against `submittest.NewCloudProposedCore()`.

### Proposed contract 0.10.0 (WP1.3)

The Kubernetes, x509-certificate-exporter, Qualys and Tenable adapters
(docs/adapters-kubernetes.md, docs/adapters-scanners.md) need three
additive changes, proposed in the same shared `api/proposed/collector-0.10.0-proposed.yaml`
as the cloud additions:
adapter evidence on `host_port_sni` targets (a scanner export), certificate
identity by issuer and serial where the source has no SHA-1 (the exporter,
Qualys), and the evidence objects `kubernetes` and `scanner` plus `certificate.sha256` and `certificate.dns_names`. The
evidence objects are unknown properties that 0.9.0 accepts and ignores, so
Kubernetes Secrets (with `renewal_mode` from the shared proposal) are sent under `MEISCOPE_FEATURE_LOCAL_STORE_V1` alone;
everything 0.9.0 would refuse stays behind
`MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2`. No new target kind is proposed: a
Kubernetes Secret is a `store` (`kubernetes/<cluster>/<namespace>/<secret>`).

## Adapters

| Adapter | Reads | Document |
|---|---|---|
| `osquery` | Fleet, an osquery log sink or osqueryi output | docs/osquery.md |
| `azure_key_vault`, `azure_app_service`, `azure_app_gateway`, `entra_id`, `defender_tvm` | Azure, Entra ID and Defender APIs | docs/azure.md |
| `kubernetes` | TLS Secrets, cert-manager Certificates, Ingress and Gateway TLS | docs/adapters-kubernetes.md |
| `x509-certificate-exporter` | the exporter's Prometheus metrics endpoint | docs/adapters-scanners.md |
| `qualys`, `tenable` | CSV exports given by path | docs/adapters-scanners.md |

## Running adapters

```
meiscope-collector adapter list
meiscope-collector adapter run --config adapters.json [--every 24h] [NAME...]
meiscope-collector adapter pack [--format osquery|fleet] [--query NAME] [--max-file-bytes N] [--max-files N]
```

Without `MEISCOPE_CORE_URL` the run is a dry run: the observation batch goes to
stdout and cursors are not saved. With it, observations go through the local
buffer when `MEISCOPE_BUFFER_DIR` is set (recommended), else straight to the core.

| Variable | Meaning |
|---|---|
| `MEISCOPE_CORE_URL` | https URL of the core |
| `MEISCOPE_FEATURE_LOCAL_STORE_V1` | `true` enables store and file observations (proposed contract); default off |
| `MEISCOPE_FEATURE_CLOUD_RESOURCE_V1` | `true` enables cloud_resource observations (proposed contract 0.10.0); default off |
| `MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2` | `true` enables the observations of proposed contract 0.10.0 (scanner exports on `host_port_sni`, certificates identified by issuer and serial); default off |
| `MEISCOPE_CREDENTIAL_FILE`, `MEISCOPE_CREDENTIAL_KEY_FILE` | the age-encrypted credential file and the collector's identity file |
| `MEISCOPE_BUFFER_DIR` | directory of the local buffer |
| `MEISCOPE_BUFFER_KEY_REF` | credential reference of the buffer key (default `buffer_key`; 32 bytes, base64) |
| `MEISCOPE_ADAPTER_STATE_FILE` | where adapter cursors are kept |
| `MEISCOPE_PROXY_URL`, `MEISCOPE_NO_PROXY`, `MEISCOPE_PROXY_CREDENTIAL`, `MEISCOPE_CA_BUNDLE` | egress (below) |

The command is a minimal local runner. Scheduling from signed jobs arrives
with the job loop (WP0.3).

## Local buffer

When the core is unreachable, observations stay in `MEISCOPE_BUFFER_DIR` for
up to 72 hours, encrypted with AES-256-GCM (sequence number as additional
data, so records cannot be reordered or swapped). The log is bounded
(512 MiB by default); at the bound `Enqueue` fails with `ErrFull`, the adapter
does not advance its cursor, and the same data is read again once space is
free. After a restart the buffer replays only what the core has not accepted,
in the order it was written, at most 1000 observations per request, using the
submit client's retries and backoff. A batch is acknowledged on disk right after
the core accepts it; a crash in the instant between the core's answer and that
write resends one batch, which the core counts as duplicates. Observations the
core rejects individually are acknowledged, since resending cannot succeed.
Each cycle logs `collector heartbeat` with `buffer_depth` and `buffer_expired`;
the version is in every log line (the core heartbeat endpoint arrives with WP0.3).

## Egress and proxies

The collector's HTTP client (`internal/egress`) honours `HTTPS_PROXY`/`NO_PROXY`
or an explicit `MEISCOPE_PROXY_URL` (`http://` or `https://` proxy, CONNECT
tunnel, `MEISCOPE_NO_PROXY` for bypass). A proxy URL with user information is
refused, since it would leak into logs. Proxy authentication comes only from the
credential source: set `MEISCOPE_PROXY_CREDENTIAL` to a reference whose value is
`user:password`; it is read for each CONNECT and sent only in
`Proxy-Authorization`. `MEISCOPE_CA_BUNDLE` adds trusted roots (a TLS-inspecting
proxy, a private core CA).
