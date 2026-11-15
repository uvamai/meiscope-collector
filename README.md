# meiscope-collector

The open-source collector for Meiscope, a certificate lifecycle management
product. The collector runs inside your network, finds TLS certificates and
reports them to the Meiscope core. It connects **outbound only**: nothing
needs to reach into your network.

Licence: Apache-2.0. The collector is public so that you can read and verify
exactly what runs in your network; release binaries are built by the public
pipeline in `.github/workflows` and signed (cosign keyless, SBOM, provenance).

> **Status: pre-release.** `enrol` enrols with the core (key generated on
> this host, client certificate for mTLS, pinned CA and scope-signing keys;
> see [docs/install.md](docs/install.md#enrolment)); `ct-poll` /
> `ct-baseline` read public Certificate Transparency data for your owned
> domains ([docs/ct.md](docs/ct.md)). Once enrolled, `run` is one process
> that talks to the core over mTLS only: it renews its certificate, fetches
> and verifies the signed scopes, polls CT for the owned domains and
> reports its state on `GET /status`
> ([docs/install.md](docs/install.md#running-an-enrolled-collector)).
> Probing the scopes fetched from the core is not wired in yet; a collector
> that is not enrolled can still probe a signed scope from a file
> ([docs/probe.md](docs/probe.md)).

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

Requirements: Go 1.27.4 (`GOTOOLCHAIN=local`), [Task](https://taskfile.dev),
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
| `MEISCOPE_BUFFER_DIR`, `MEISCOPE_ADAPTER_STATE_FILE`, `MEISCOPE_PROXY_*`, `MEISCOPE_CA_BUNDLE` | | Adapters, local buffer and proxy egress; see [docs/adapters.md](docs/adapters.md) and [docs/osquery.md](docs/osquery.md) |

## API contract

`api/collector.yaml` is a byte-for-byte vendored copy of the collector
surface (`/collector/v1`, OpenAPI 3.1) of the Meiscope core, which owns it
(contract 0.8.1). The collector does not extend it; the tests submit to a
fake core that validates every request against this file. Changes inside
`/v1` are additive only. The CT poller's use of it (target kind `ct_log`,
`ct_entry`, `GET /owned-domains`) is described in [docs/ct.md](docs/ct.md).

## Install on Linux

These are the steps the Meiscope portal shows under **Collectors ▸ Add
collector**. The portal fills in the core URL and the CA fingerprint, and
gives you the CA certificate (`collector-ca.crt`) and a one-time enrolment
code. The steps are for a Debian or Ubuntu server on amd64 and the
`v0.3.0-rc1` pre-release. Run them on the server, as a user with `sudo`.
You also need `curl` and [cosign](https://docs.sigstore.dev/cosign/system_config/installation/).

1. **Download** the package, the checksums and the package's signature:

   ```sh
   curl -fLO https://github.com/uvamai/meiscope-collector/releases/download/v0.3.0-rc1/meiscope-collector_0.3.0~rc1_amd64.deb
   curl -fLO https://github.com/uvamai/meiscope-collector/releases/download/v0.3.0-rc1/SHA256SUMS
   curl -fLO https://github.com/uvamai/meiscope-collector/releases/download/v0.3.0-rc1/meiscope-collector_0.3.0~rc1_amd64.deb.sigstore.json
   ```

2. **Check that the package is ours.** Both checks must pass: the first
   prints `OK`, the second `Verified OK`. If either fails, stop.

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   cosign verify-blob --bundle meiscope-collector_0.3.0~rc1_amd64.deb.sigstore.json \
     --certificate-identity-regexp '^https://github.com/uvamai/meiscope-collector/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     meiscope-collector_0.3.0~rc1_amd64.deb
   ```

3. **Install it.** This installs the collector and its systemd service. The
   service is not started yet.

   ```sh
   sudo apt install ./meiscope-collector_0.3.0~rc1_amd64.deb
   ```

4. **Save the core's CA certificate** (`collector-ca.crt` from the portal)
   and check its fingerprint against the one the portal shows. The check
   must print `OK`.

   ```sh
   sudo install -m 644 -o root -g root collector-ca.crt /etc/meiscope-collector/collector-ca.crt
   echo '<ca_sha256>  /etc/meiscope-collector/collector-ca.crt' | sha256sum -c
   ```

5. **Save the enrolment code** in a file that only root can read. Run the
   command, paste the code, press Enter, then Ctrl+D. The code never goes
   on a command line, so it stays out of your shell history and the process
   list.

   ```sh
   sudo install -m 600 -o root -g root /dev/stdin /etc/meiscope-collector/enrol-code
   ```

6. **Enrol.** The collector creates its private key on this server and
   sends only a certificate request. The code works once, and the file is
   deleted when enrolment succeeds.

   ```sh
   sudo MEISCOPE_CORE_URL='<core_url>' \
     MEISCOPE_CA_BUNDLE=/etc/meiscope-collector/collector-ca.crt \
     meiscope-collector enrol --token-file /etc/meiscope-collector/enrol-code \
     && sudo rm -f /etc/meiscope-collector/enrol-code
   ```

7. **Start the collector.** It then shows on the portal's Collectors page.
   It probes only the explicit targets in the scopes you create there.

   ```sh
   sudo systemctl enable --now meiscope-collector
   ```

For other systems, the container image, upgrades and troubleshooting, see
[docs/install.md](docs/install.md).

## Contributing and security

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: [SECURITY.md](SECURITY.md).

## Working in this repository

Run `task hooks` once in every clone to install the `pre-push` guard, which refuses any push to `main` and any force-push. Every change goes through a pull request and is merged with `gh pr merge <n> --merge` only after `gh pr checks <n>` shows every check passed. The `main-guard` workflow opens an issue if a commit reaches `main` without a merged pull request. The full rule is in `CLAUDE.md`.
