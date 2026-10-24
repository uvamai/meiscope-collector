# meiscope-collector

The open-source collector for Meiscope, a certificate lifecycle management
product. The collector runs inside your network, finds TLS certificates and
reports them to the Meiscope core. It connects **outbound only**: nothing
needs to reach into your network.

Licence: Apache-2.0. The collector is public so that you can read and verify
exactly what runs in your network; release binaries are built by the public
pipeline in `.github/workflows` and signed (cosign keyless, SBOM, provenance).

> **Status: skeleton (WP0.1) plus the CT poller (WP0.4).** This release has
> `version`, a placeholder `run` loop with a local `/healthz`, a placeholder
> `enrol`, and `ct-poll` / `ct-baseline`, which read public Certificate
> Transparency data for your owned domains (see [docs/ct.md](docs/ct.md)).
> It does not probe anything yet. Probing and enrolment arrive in WP0.3.

## What the collector sends, and what it never sends

| | |
|---|---|
| **Sends** (to the core, over mutually authenticated TLS, outbound on 443) | The **public** certificate (DER), its fingerprint and chain; the binding where it was seen (host, port, SNI, path or certificate store); the owner reference; expiry and policy findings; the daily count of managed certificates. In metadata-only mode, hostnames are replaced by keyed hashes. |
| **For enrolment and renewal** | A certificate signing request (CSR). The core returns a public certificate. |
| **Never sends** | **Private keys** - they are generated on the host or platform that uses them and never leave it. **Credentials** - platform credentials are leased just-in-time from *your* vault (CyberArk, HashiCorp Vault, Azure Key Vault) by the collector, used for the call, and never written to disk, logs or observations, and never sent to the core. **Raw device configurations.** |
| **Never does** | Authenticate to a scanned target: the TLS handshake stops after the server's Certificate message. Probe outside the signed scan scope it was given. Accept a write job by default: the default enrolment is read-only; write capability is a separate, two-person-approved enrolment per host. |

Scanning obeys a signed `ScanPolicy`: allow and deny lists, a rate limit per
/24, at most one connection per target:port at a time, back-off, maintenance
windows, a canary on new scopes, and a global pause.

## Quick start (development)

Requirements: Go 1.27.3 (`GOTOOLCHAIN=local`), [Task](https://taskfile.dev),
golangci-lint v2, gofumpt, nFPM. Run `task doctor` to check.

```sh
task build      # bin/linux_amd64, bin/linux_arm64, bin/windows_amd64, plus bin/meiscope-collector for this machine
task test       # unit tests (-race where cgo is available)
task lint       # go vet, golangci-lint, gofumpt
task package    # deb and rpm into dist/
bin/meiscope-collector version
```

Run the placeholder loop:

```sh
MEISCOPE_HEALTH_ADDR=127.0.0.1:8090 bin/meiscope-collector run
curl http://127.0.0.1:8090/healthz
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MEISCOPE_CORE_URL` | (unset) | https base URL of the Meiscope core |
| `MEISCOPE_HEALTH_ADDR` | `127.0.0.1:8090` | listen address of `/healthz` (`0.0.0.0:8090` in the container image) |
| `MEISCOPE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `MEISCOPE_LOG_FORMAT` | `json` | `json` or `text` |
| `MEISCOPE_CT_*` | | Certificate Transparency poller: owned domains, logs, state; see [docs/ct.md](docs/ct.md) |

## API contract

`api/collector.yaml` is a vendored copy of the collector surface
(`/collector/v1`, OpenAPI 3.1) of the Meiscope core (contract 0.2.0), plus
the additive CT extensions marked "WP0.4 (proposed)". Changes inside `/v1`
are additive only.

## Install

See [docs/install.md](docs/install.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: [SECURITY.md](SECURITY.md).
