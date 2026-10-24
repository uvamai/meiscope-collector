# osquery pack

Meiscope reads the certificates your osquery estate already reports. It does
not install an agent and does not run queries on hosts.

## Privacy

Only certificate metadata and file digests are collected:

- `certificates` table columns: names, issuer, validity, key algorithm and
  size, key identifiers, SHA-1 fingerprint, serial, and the store or path.
  No certificate bodies and no private keys (the table has none).
- Keystore files (`*.jks`, `*.p12`, `*.pfx`, `*.pem`, `*.kdb`): path, size and
  SHA-256 only. File contents are never read into results.

Caps, so the pack stays cheap: files up to 10 MiB, at most 1000 per host and
query, once a day. System trust-store directories (read by the certificates
query already) and container data directories (`/var/lib/docker`,
`/var/lib/containerd`, `/var/lib/containers`, kubelet pods, Docker and
containerd under `C:\ProgramData`) are excluded: there is no container
root-filesystem scanning. Changing the caps needs a decision from the
product owner.

Custody: osquery 5.x exposes no private-key presence column, so observations
carry `custody.private_key: unknown`.

## Files

| File | Use |
|---|---|
| `packs/osquery/meiscope.conf` | osquery pack (standalone `osqueryd`, Kolide, any TLS/remote config). Platform-scoped: `posix` and `windows` queries |
| `packs/osquery/fleet-queries.yml` | the same four queries as Fleet saved queries (`fleetctl apply -f`) |

Queries: `meiscope_certificates_posix`, `meiscope_certificates_windows`
(including per-user stores, with `sid`, `username`, `store_location`),
`meiscope_keystores_posix`, `meiscope_keystores_windows`. All are snapshot
queries with a 24 h interval.

## Deployment

### Fleet

1. `fleetctl apply -f packs/osquery/fleet-queries.yml` (or per team).
2. Create an API-only user with the observer role and a token; store the token
   in the collector's credential source under a reference such as `fleet_api_token`.
3. Collector config:
   ```json
   [{"name": "fleet", "adapter": "osquery",
     "settings": {"mode": "fleet", "url": "https://fleet.example.test", "team_id": "2"},
     "credentials": {"api_token": "fleet_api_token"}}]
   ```
   The adapter lists saved queries, then reads each pack query's report
   (`GET /api/v1/fleet/queries/{id}/report`) at most 5 requests per second,
   and ingests rows newer than the stored `last_fetched` per host.
   It needs a Fleet that offers the saved-query report API (4.4x and later);
   an older Fleet gets a clear error, and we should talk before building a workaround.

### Kolide and other pipelines (log sink)

Add `packs/osquery/meiscope.conf` to the pack configuration. Send results to
the collector host, either:

- **JSONL directory**: point osquery's filesystem logger (or your Fluent Bit /
  Logstash output) at a directory the collector can read; config
  `{"mode": "logsink", "dir": "/var/log/osquery"}`. Complete new lines of
  `*.log`, `*.json`, `*.jsonl` are read in name order; log rotation is followed.
  Of several snapshots in one run only the latest per host and query is mapped.
- **HTTP push**: `osquery.PushHandler` accepts the pipeline's POSTs
  (NDJSON, a JSON array, or the osquery TLS logger envelope) with a bearer
  token from the credential source and appends them to the directory. The
  collector command does not open a listener itself; wire the handler behind
  a listener you control (TLS, internal network only).

### Standalone (direct)

```
osqueryi --json "$(query from meiscope.conf)" > web01-meiscope_certificates_posix.json
```
Name each output file so that it ends with the query name, then:
`{"mode": "direct", "host": "web01.example.test", "files": "a.json,b.json"}`.
`observed_at` is the collector's clock because `osqueryi` records no time.
Unchanged files are not read again.

## Result mapping

| Row | Observation |
|---|---|
| certificate | target `store` (`posix/system` or `windows/<location>[/<sid>]/<store>`) with the file path when osquery reports one, outcome `cert_seen`, `adapter.certificate` (SHA-1 and metadata) |
| keystore file | target `file`, outcome `reached`, `adapter.file` (SHA-256, size) |

All with `method: adapter`, `adapter.source: osquery`. These target kinds and
the `adapter` object are proposed contract additions (0.5.0).

## Verification status

The pack was recorded on osquery 5.12.1 on Ubuntu 24.04 (`testdata/adapters/osquery/record-linux.sh`).
It has not been run on Windows Server 2022: the Windows queries and fixtures are
derived from the osquery schema and must be checked on a real host before rollout.
