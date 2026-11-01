# Installing the collector

> Stub (WP0.1). Full instructions, the hardening guide and the egress
> allow-list arrive with the first usable release (WP0.3 onward).

## Linux (deb / rpm)

Signed apt and yum repositories are not published yet. Until then, install a
package from a GitHub release after verifying its signature (see
[SECURITY.md](../SECURITY.md)):

```sh
sudo apt install ./meiscope-collector_<version>_amd64.deb      # Debian, Ubuntu
sudo dnf install ./meiscope-collector-<version>-1.x86_64.rpm   # RHEL, Fedora
```

The package installs:

| Path | Purpose |
|---|---|
| `/usr/bin/meiscope-collector` | the binary |
| `/usr/lib/systemd/system/meiscope-collector.service` | hardened systemd unit (dynamic unprivileged user) |
| `/etc/meiscope-collector/collector.env` | configuration (no secrets) |

```sh
sudoedit /etc/meiscope-collector/collector.env   # set MEISCOPE_CORE_URL
sudo meiscope-collector enrol --token <one-time token>   # placeholder until WP0.3
sudo systemctl enable --now meiscope-collector
```

## Container

```sh
docker run -d --name meiscope-collector \
  -e MEISCOPE_CORE_URL=https://<core> \
  ghcr.io/uvamai/meiscope-collector@sha256:<digest>
```

## Windows

A signed MSI is planned; until the code-signing certificate exists, Windows
builds are for pilots only.

## Network

Outbound HTTPS (443) to the core only. No inbound ports are required; the
health endpoint listens on loopback by default. Behind a proxy, see
"Proxy" below. The only optional listener is the log-push receiver, which is
off by default (see "Log-push receiver").

## Credentials

Credentials (the Fleet API token, the Cert Spotter key, the proxy login, the
buffer key) are read from an age-encrypted file; the process environment is
not a credential source in release builds.

```
export MEISCOPE_CREDENTIAL_FILE=/var/lib/meiscope/credentials.age
export MEISCOPE_CREDENTIAL_KEY_FILE=/etc/meiscope/identity.txt   # the collector's keystore, mode 0600
meiscope-collector credential init                              # creates the age identity
printf '%s\n' "$TOKEN" | meiscope-collector credential set fleet_api_token
head -c 32 /dev/urandom | base64 | meiscope-collector credential set buffer_key
meiscope-collector credential list                              # names only, never values
```

Keep the identity file and the credential file apart in backups. The values
never appear in arguments, logs or errors. A release build refuses to start
when `MEISCOPE_DEV_CREDENTIAL_*` variables are set; development builds
(`task build:dev`, tag `devcredentials`) accept them. Vault-backed sources
(HashiCorp Vault, Azure Key Vault, CyberArk) arrive with WP3.4.

## Local buffer

Set `MEISCOPE_BUFFER_DIR` (and the `buffer_key` credential) so adapter
observations survive a core outage: they are kept encrypted for 72 hours and
replayed in order (docs/adapters.md).

## Proxy

`HTTPS_PROXY`/`NO_PROXY` are honoured; `MEISCOPE_PROXY_URL` (an http or https
proxy URL without user information) overrides them, and
`MEISCOPE_PROXY_CREDENTIAL` names the credential holding `user:password` for
proxy authentication. `MEISCOPE_CA_BUNDLE` adds trusted roots.

## Log-push receiver (optional, off by default)

For pipelines that push osquery results (Fluent Bit, Logstash, osquery's TLS
logger) instead of writing files, `meiscope-collector receiver run` accepts
POSTs and spools them for the osquery adapter's log-sink mode. It is the only
listener that accepts data (the separate `/healthz` endpoint only reports
liveness), so it is locked down:

| Setting | Meaning |
|---|---|
| `MEISCOPE_RECEIVER_ENABLED=true` | required; the default is off and the command refuses to run |
| `MEISCOPE_RECEIVER_ADDR=127.0.0.1:9100` | an IP literal that is loopback or private (10/8, 172.16/12, 192.168/16, fc00::/7). `0.0.0.0`, `::`, public, link-local (including 169.254.169.254) and 100.64.0.0/10 addresses are rejected when the configuration loads |
| `MEISCOPE_RECEIVER_DIR` | spool directory (mode 0600 files) |
| `MEISCOPE_RECEIVER_TOKEN_REF` | credential reference of the bearer token; every request needs `Authorization: Bearer ...` |
| `MEISCOPE_RECEIVER_RATE` | requests per second (default 5, burst 10) |

The receiver speaks plain HTTP. Put a customer-controlled TLS terminator
(nginx, HAProxy, a service mesh sidecar) in front of it whenever the pipeline
is not on the same host, and restrict who can reach it with the network
firewall. Mutual TLS, if wanted, is enforced by that terminator; the
receiver itself always requires the bearer token. Requests above 1 MiB are
refused (413), more than 1000 events per request or events above 512 KiB are
refused, and pushed content is parsed only as data: events must be osquery
result events of the Meiscope pack's queries and are stored as JSON lines.
Binding to a non-private address is not supported; ask before changing that.
