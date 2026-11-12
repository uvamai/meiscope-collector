# x509-certificate-exporter, Qualys and Tenable adapters

These adapters bring in what tools the customer already runs have seen
(FR-DISC-028, FR-DISC-029, WP1.3). None of them scans anything.

## x509-certificate-exporter

Adapter `x509-certificate-exporter`, source `x509_certificate_exporter`. It
GETs the exporter's metrics URL once per run and reads `x509_cert_not_after`,
`x509_cert_not_before` and `x509_read_errors` (Prometheus text format). Every
certificate series becomes a `store` observation:

- series with `secret_namespace` and `secret_name` labels:
  store `kubernetes/<cluster>/<namespace>/<secret>` (the same locator as the
  kubernetes adapter; set `host` to the API server host name so they line up);
- series with an absolute `filepath`: store
  `x509-certificate-exporter/host/files` with `target.path` the file.

The exporter publishes no fingerprint, so the certificate is identified by
issuer (rebuilt from the `issuer_*` labels) and serial (the decimal
`serial_number` label, reported as hex). That identity needs proposed
contract 0.10.0: observations are sent only with both
`MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2` and `MEISCOPE_FEATURE_LOCAL_STORE_V1`
on. Custody is `unknown`.

| Setting | Meaning |
|---|---|
| `url` | the metrics URL; https, or http only with `allow_http=true` and no credential |
| `host` | host name the observations are filed under |
| `cluster` | cluster name for Secret locators |

Credential `bearer_token` (optional, for an exporter behind an
authenticating proxy). The adapter never follows a redirect (a 3xx answer
is an error), so the token is sent to the configured URL only. Permission needed: network reach to the metrics
endpoint only. Statistics: `series`, `unchanged`, `skipped_malformed_line`,
`skipped_no_identity`, `skipped_no_not_after`, `skipped_no_locator`,
`exporter_read_errors`, `skipped_feature_disabled`. Delta: a fingerprint per
certificate in the cursor.

## Qualys and Tenable exports

Adapters `qualys` and `tenable` read CSV files given by absolute path
(`files`, comma-separated; `max_file_bytes`, default 256 MiB). They never
call the scanner's API. A file whose SHA-256 is unchanged since the cursor
is skipped (`files_unchanged`); a changed file is read in full.
`observed_at` is the file's modification time (never later than now).

| Adapter | Export | Certificate rows | Columns read |
|---|---|---|---|
| `tenable` | Nessus / Tenable VM / Tenable.sc CSV | plugin 10863 SSL Certificate Information | `Plugin ID` or `Plugin`; `Host` or `IP Address`; `Port`; `DNS Name`; `Plugin Output` or `Plugin Text` |
| `qualys` | Qualys VMDR scan report CSV (a title block before the header is skipped) | QID 86002 SSL Certificate - Information | `IP`, `DNS`, `Port`, `QID`, `Results` |

From the plugin output or the Results cell the leaf certificate's subject,
issuer, serial, validity, key algorithm and size, signature algorithm,
subjectAltName DNS names and, where printed, SHA-1 and SHA-256 fingerprints
are read. Each certificate becomes a `host_port_sni` observation (host the
scanned address, the port, no SNI) with method `adapter`, outcome
`cert_seen`, `adapter.certificate` and `adapter.scanner` (check id, DNS
name, file name). Contract 0.9.0 allows adapter evidence only on store and
file targets, so these observations need proposed contract 0.10.0 and are
sent only with `MEISCOPE_FEATURE_ADAPTER_EVIDENCE_V2=true`.

Rows are skipped and counted, never fatal: `skipped_malformed_row` (CSV
error or wrong column count), `skipped_no_host`, `skipped_bad_port`,
`skipped_unparsed_output`, `skipped_no_identity` (neither SHA-1 nor issuer
and serial), `skipped_duplicate`; rows of other checks count
`ignored_other_checks`. A file with no recognisable header fails the run.

The column names and output layouts were built from the vendors' published
descriptions; the fixtures are SYNTHETIC (testdata/adapters/*/README.md)
and must be re-recorded from real exports before these adapters are called
supported.
