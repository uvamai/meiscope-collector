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
sudoedit /etc/meiscope-collector/collector.env   # set MEISCOPE_CORE_URL and MEISCOPE_CA_BUNDLE
sudo sh -c 'set -a; . /etc/meiscope-collector/collector.env; meiscope-collector enrol --token-file -'
                                                  # paste the one-time token, then Enter
sudo systemctl enable --now meiscope-collector
```

### Enrolment

Enrolment runs once per collector and needs a **one-time token** from the
core (valid 24 hours, single use). The collector:

1. generates its private key **on this host**; the key never leaves it,
2. sends the token and a certificate signing request (CSR) that asks for
   nothing; the core decides the certificate (client authentication only,
   valid 30 days),
3. keeps the key and certificate together in
   `/var/lib/meiscope-collector/identity.pem` (mode 0600, directory 0700),
   and **pins** the core's CA bundle and scope-signing keys from the answer.

From then on the collector trusts only the pinned CA for the core, presents
its certificate on every call (mTLS), and renews it at two thirds of its
lifetime with a new key.

| Variable | Meaning |
|---|---|
| `MEISCOPE_CORE_URL` | the core's collector endpoint, `https://…` |
| `MEISCOPE_CA_BUNDLE` | PEM file with the core's CA certificate, for the **first contact** only (the system roots are also trusted then). Without it, enrolment fails unless the core's certificate is publicly trusted; the token is never sent to a server the collector cannot verify. |
| `MEISCOPE_STATE_DIR` | identity directory (default `/var/lib/meiscope-collector`) |

Give the token through `--token-file PATH` or `--token-file -` (standard
input) rather than `--token`: command-line arguments are visible to other
users of the host. The token is never printed or logged.

If enrolment fails with "invalid, expired or already used", ask for a new
token. To enrol again, stop the collector and move the state directory away
first; `enrol` refuses to overwrite an existing identity.

### Running an enrolled collector

Once `enrol` has written an identity, `meiscope-collector run` (the systemd
unit's command) is **one long-lived process** that talks to the core only
over mTLS with that identity, at the core URL stored at enrolment:

| Task | What it does | How often |
|---|---|---|
| Certificate renewal | At two thirds of the certificate's lifetime: a new key **on this host**, a CSR, `POST /collector/v1/certificate` authenticated by the current certificate, then the new key and certificate replace the old ones together (one rename). The next request presents the new certificate. | once per lifetime (about every 20 days); after a failure, again after 30 s, 1 min, 2 min, ... at most 1 h (jittered) |
| Scan scopes | `GET /collector/v1/scopes`. Each scope is verified with the scope-signing keys pinned at enrolment, validated, and refused if its version is lower than the last accepted for its id (or the same version with other bytes). When a fetch fails, the last good set is kept; scopes the core no longer lists, or that have expired, are dropped. | `MEISCOPE_SCOPE_REFRESH` (5 min); after a failure, from 30 s doubling up to that interval |
| Certificate Transparency | Reads the owned domains from the core (`GET /collector/v1/owned-domains`), polls public CT sources for them and submits what it finds (`POST /collector/v1/observations`), as `ct-poll` does ([ct.md](ct.md)). | `MEISCOPE_CT_INTERVAL` (1 h) |
| Probing | Runs exactly the scopes the set holds now, each verified again against the pinned keys, with the same runner and ScanPolicy as a scope file ([probe.md](probe.md)): plan and deny list, rate per /24, one connection per target:port, windows, dry run, canary, pause (`POST /pause`). One scope runs at a time, so the per-/24 rate and one connection per target:port hold for the whole collector even when scopes overlap. The pinned keys are re-read every tick (a renewal may rotate them); if the scopes or keys cannot be read, nothing runs (fail closed). A scope the core stops listing, or that is replaced by a new version, has its run in progress cancelled at the next tick; a run also ends by itself at the scope's `not_after` or the end of the collector certificate, whichever is first, and nothing starts after the certificate has ended. Results go to `POST /collector/v1/observations` over the same mTLS client. | every 5 s the schedule checks what is due; each scope at its own rescan interval |

If the certificate expires without being renewed (the core was unreachable
for the last third of its lifetime, or refused every renewal), the collector
logs an error saying so, stops calling the core (every request would be
refused) and drops its scopes; `/healthz` keeps answering and `GET /status`
shows `"state": "expired"`. Enrol again: stop the service, move the state
directory away, and run `enrol` with a new token.

Environment variables of an enrolled `run` (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `MEISCOPE_STATE_DIR` | `/var/lib/meiscope-collector` | the identity written by `enrol`; its presence is what makes `run` an enrolled collector |
| `MEISCOPE_CORE_URL` | the URL stored at enrolment | may be left set; if it differs from the stored URL, `run` refuses to start (enrol again to move to another core) |
| `MEISCOPE_SCOPE_REFRESH` | `5m` | how often the scopes are fetched; `1m` to `1h` |
| `MEISCOPE_SCOPE_STATE_FILE` | `<state dir>/scope-versions.json` | the highest scope version accepted per id, so an older signed scope is refused after a restart too |
| `MEISCOPE_CT_INTERVAL` | `1h` | how often CT is polled; `15m` to `24h`, or `off` |
| `MEISCOPE_CT_STATE_FILE` | `<state dir>/ct-state.json` | CT progress (public data only); the other `MEISCOPE_CT_*` settings are in [ct.md](ct.md). `MEISCOPE_CT_DOMAINS` is ignored: the owned domains come from the core |
| `MEISCOPE_PROXY_URL`, `MEISCOPE_NO_PROXY`, `MEISCOPE_PROXY_CREDENTIAL`, `HTTPS_PROXY`, `NO_PROXY` | none | the proxy for calls to the core ("Proxy" below); mTLS runs through the proxy's CONNECT tunnel |
| `MEISCOPE_HEALTH_ADDR` | `127.0.0.1:8090` | the local listener of `/healthz` and `/status` |
| `MEISCOPE_LOG_LEVEL`, `MEISCOPE_LOG_FORMAT` | `info`, `json` | logging |
| `MEISCOPE_SCOPE_FILE`, `MEISCOPE_SCOPE_KEYS` | none | **must not be set** on an enrolled collector (configuration error) |

`MEISCOPE_CA_BUNDLE` is used only for the first contact by `enrol`; every
later call to the core trusts only the CA bundle pinned in the state
directory.

What an operator sees:

```text
$ journalctl -u meiscope-collector
{"level":"INFO","msg":"enrolled collector running","collector_id":"0b7f…","core_url":"https://core.example","certificate_not_after":"…","renew_at":"…","scope_refresh":"5m0s","ct_interval":"1h0m0s"}
{"level":"INFO","msg":"scope accepted","scope":"7d0f…","version":3,"targets":12,"not_after":"…"}
{"level":"INFO","msg":"collector certificate renewed","collector_id":"0b7f…","not_after":"…","renew_at":"…"}
{"level":"WARN","msg":"collector certificate renewal failed; retrying","attempt":1,"retry_in":"24s","error":"…"}

$ curl -s http://127.0.0.1:8090/status
{
  "enrolled": true,
  "collector_id": "0b7f3c52-…",
  "core_url": "https://core.example",
  "certificate": {
    "state": "valid",
    "not_before": "…", "not_after": "…", "renew_at": "…",
    "renewal": { "last_renewed": "…", "consecutive_failures": 0, "expired": false }
  },
  "scopes": { "count": 1, "ids": ["7d0f…"], "last_fetch": "…", "last_attempt": "…", "refused_in_last_fetch": 0 },
  "probing": { "state": "active", "scopes": 1, "running": 0, "last_tick": "…" },
  "ct": { "enabled": true, "interval": "1h0m0s", "last_poll": "…" }
}
```

`probing.state` is `active`, `paused` (after `POST /pause`) or `stopped`
(the certificate expired). `certificate.state` is `valid`, `renewal_failing` (renewal is being retried;
the current certificate still works) or `expired`. `/status` never shows
keys, tokens or credentials; `/healthz` is unchanged (liveness only).
`/status` is served only by an enrolled collector.

The systemd unit runs as a dynamic unprivileged user whose state directory
is `/var/lib/meiscope-collector`; systemd hands the identity written by
`sudo … enrol` to that user when the service starts. Do not run a second
`run` or a `ct-poll` against the same state directory: the one process
renews the certificate, so there is never a second renewer.

## Container

The image runs `meiscope-collector run` as the distroless `nonroot` user;
keep the state directory on a volume so the identity survives restarts.

```sh
# once: enrol into the volume (the token is read from standard input)
docker run --rm -i \
  -v meiscope-collector-state:/var/lib/meiscope-collector \
  -v "$PWD/core-ca.pem:/etc/meiscope/core-ca.pem:ro" \
  -e MEISCOPE_CORE_URL=https://<core> \
  -e MEISCOPE_CA_BUNDLE=/etc/meiscope/core-ca.pem \
  ghcr.io/uvamai/meiscope-collector@sha256:<digest> enrol --token-file -

# then run it
docker run -d --name meiscope-collector --restart unless-stopped \
  -v meiscope-collector-state:/var/lib/meiscope-collector \
  ghcr.io/uvamai/meiscope-collector@sha256:<digest>
```

Inside the container `/healthz` and `/status` listen on `0.0.0.0:8090`;
publish that port only on a private network, if at all.

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
