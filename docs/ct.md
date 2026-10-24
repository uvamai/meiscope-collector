# Certificate Transparency poller

The CT poller finds every publicly trusted certificate issued for your owned
domains (FR-DISC-020) and reports each one to the core as an observation with
method `ct`. It only **reads public CT data over HTTPS**. It never connects to
any host on your network, and it sends nothing about your network to CT
services: the only thing a CT service sees is the owned domain it is asked
about (Cert Spotter, crt.sh) or nothing at all (log tailing).

## What it queries

| Source | When | Requests | What is sent |
|---|---|---|---|
| [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1) `GET https://api.certspotter.com/v1/issuances` | Primary source, every poll, per owned domain | One per page; resumes from the last issuance id seen (`after`), so a steady-state poll is one request per domain | The domain, `include_subdomains=true`, `match_wildcards=true`; the API key as a bearer token when one is configured |
| CT logs you select, read directly | Every poll, per configured log | RFC 6962 logs: `get-sth`, then `get-entries` in batches of 256 (certificate-transparency-go v1.4.0). Static CT API (tiled) logs: `checkpoint`, `tile/data/…`, and `issuer/<sha256>` for the issuers of matching entries only (cached) | Nothing about you: the collector downloads the log and matches entries locally |
| [crt.sh](https://crt.sh) `GET https://crt.sh/?q=<domain>&output=json&exclude=expired` and `GET https://crt.sh/?d=<id>` | **Fallback only**: for a domain whose Cert Spotter query failed in this poll (for example the free-tier quota is used up) | One search per domain, then one download per certificate not already known by serial, at most 30 downloads per poll | The domain |

Cert Spotter returns unexpired certificates only; the crt.sh fallback asks for
unexpired certificates too.

A new log starts at its current tree size (only certificates logged from now
on). Each poll reads at most `MEISCOPE_CT_MAX_ENTRIES_PER_LOG` entries
(50,000 by default) from each log, so a large shared log (hundreds of entries
per second) is **not** fully tailed at the default budget and falls behind:
log tailing is meant for selected logs, with Cert Spotter as the primary
source.

### Rate limits and back-off

All requests go through one rate limiter and back-off per service:

| Service | Minimum spacing | Back-off on 429 / 5xx / network error | Longest Retry-After waited for |
|---|---|---|---|
| Cert Spotter | 1 s | 5 s, doubling, capped at 1 min, 3 retries | 2 min (a longer one ends the attempt and the domain goes to the crt.sh fallback) |
| crt.sh | **10 s** | 30 s, doubling, capped at 5 min, 4 retries | 10 min |
| each CT log | 250 ms | 1 s, doubling, capped at 2 min, 5 retries | 5 min |
| the core | – | 1 s, doubling, capped at 1 min, 5 retries | 5 min |

`Retry-After` is always honoured (seconds or an HTTP date); the collector
never retries sooner than its own back-off schedule. Tests prove the crt.sh
back-off with a fake clock (`internal/ct/transport_test.go`) and use only
recorded fixtures and local fake servers; no test contacts a public service.

Requests carry `User-Agent: meiscope-collector/<version>
(+https://github.com/uvamai/meiscope-collector)`. Some log operators ask for
contact details in the User-Agent; set `MEISCOPE_CT_CONTACT` (for example an
operations mailbox) to add them.

## What it sends to the core

New certificates only: the poller dedupes by the SHA-256 fingerprint of the
(pre)certificate across sources and across polls. Each becomes one
observation (`POST /collector/v1/observations`, gzip JSON, at most 1,000 per
batch):

- `method: ct`, `outcome: cert_seen`;
- `target`: kind `ct_entry`, `host` = the owned domain that matched,
  `fingerprint` = the SHA-256 of the leaf;
- `served_chain`: the certificate or precertificate as logged, then its
  issuers when the source provides them;
- `ct`: the evidence: the source, the DNS names, the entry type and, for log
  entries, the log URL, entry index, entry timestamp, the RFC 6962
  `leaf_input` (and `extra_data` for RFC 6962 logs); the Cert Spotter or
  crt.sh record id otherwise; and the SCTs embedded in the certificate.

A precertificate and its final certificate have different fingerprints and
are reported separately; the core links them by issuer and serial.

The `ct_entry` kind, `Target.fingerprint` and `Observation.ct` are additive
extensions of the collector API proposed by this work package (see
`api/collector.yaml`); a core that does not support them yet refuses the
batch, and the poller then keeps its progress and retries next poll.

## Configuration

Until the core delivers the tenant's owned-domain list to the collector, the
poller is configured with environment variables (in
`/etc/meiscope-collector/collector.env` for the packaged service):

| Variable | Default | Meaning |
|---|---|---|
| `MEISCOPE_CT_DOMAINS` | (required) | Owned domains, comma-separated, e.g. `example.com,example.net`. Each includes its subdomains. |
| `MEISCOPE_CT_LOGS` | (none) | Logs to tail, comma-separated: `rfc6962=<log URL>` or `static=<monitoring prefix>`, e.g. `static=https://mon.willow.ct.letsencrypt.org/2026h2/`. URLs are in the [Google log list](https://www.gstatic.com/ct/log_list/v3/log_list.json) (`url`, or `monitoring_url` for `tiled_logs`). |
| `MEISCOPE_CT_CERTSPOTTER` | `true` | Query the Cert Spotter API. |
| `MEISCOPE_CT_CRTSH_FALLBACK` | `true` | Use crt.sh when Cert Spotter fails for a domain. |
| `MEISCOPE_CT_MAX_ENTRIES_PER_LOG` | `50000` | Entries read from each log per poll. |
| `MEISCOPE_CT_STATE_FILE` | (none) | Where progress is kept (Cert Spotter cursors, log positions, fingerprints already sent), e.g. `/var/lib/meiscope-collector/ct-state.json`. Without it, every start begins afresh. Holds public CT data only. |
| `MEISCOPE_CT_CONTACT` | (none) | Contact details added to the User-Agent. |
| `MEISCOPE_CT_CERTSPOTTER_URL`, `MEISCOPE_CT_CRTSH_URL` | the public services | For tests and mirrors only. |
| `MEISCOPE_CORE_URL` | (none) | Without it, `ct-poll` prints the observation batch instead of submitting it and saves no progress (a dry run). |

### The Cert Spotter API key

The poller works **without a key** at the Cert Spotter free-tier limits
(a few queries per hour). A key raises the limits. The key is a credential:
it is read only through the collector's credential source (reference
`certspotter_api_key`), used as a bearer token for the request, and never
written to disk, logs, state or observations. Do not put it in
`collector.env`.

Vault-backed credential sources arrive with the adapter framework (WP1.1).
Until then, **for development only**, the environment variable
`MEISCOPE_DEV_CREDENTIAL_CERTSPOTTER_API_KEY` is read as a fallback.
Environment variables are visible to other processes of the same user, so do
not use this in production.

## Commands

```sh
# One poll (submit when MEISCOPE_CORE_URL is set, else print the batch)
MEISCOPE_CT_DOMAINS=example.com meiscope-collector ct-poll

# Poll every hour until stopped (the cadence in integration-architecture.md)
meiscope-collector ct-poll --every 1h

# Coverage against the crt.sh baseline for one domain (WP0.4 acceptance:
# at least 95 % of names and certificates)
meiscope-collector ct-baseline --domain example.com [--json]
```

`ct-baseline` queries Cert Spotter from scratch (no saved cursor) and crt.sh
once, and compares certificates by serial number (crt.sh shows a
precertificate and its certificate as one row) and DNS names, for unexpired
certificates. It does not submit anything.
