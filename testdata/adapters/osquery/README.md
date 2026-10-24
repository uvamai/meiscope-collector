# osquery adapter fixtures

All host names are synthetic (`*.example.test`); no customer data, no secrets.

| Directory | Origin |
|---|---|
| `logsink/osqueryd.snapshots.log` | Recorded: osquery 5.12.1 on Ubuntu 24.04 (container `--hostname app01.example.test`) running the generated pack (`meiscope-collector adapter pack`) with the filesystem logger, by `record-linux.sh` and `record-inner.sh`. The certificates are the distribution trust store plus a synthetic test CA; the keystores (a PKCS#12 with a throw-away key, a random-bytes `.jks`, a 20 MB `.pfx` over the size limit, a file in an excluded directory) are made by the script. Only paths, sizes, times, modes and SHA-256 digests are recorded. |
| `direct/` | Recorded: `osqueryi --json` of the three posix pack queries in the same container. |
| `fleet/` | Hand-made from the Fleet REST API shapes of the older endpoints (`GET /api/v1/fleet/queries`, `.../queries/{id}/report`), plus a recorded-style 404 for the reports probe; synthetic values. Shapes confirmed against a real Fleet 4.93.2 in `task test:integration`. |
| `fleet-reports/` | The same data under the newer `/api/v1/fleet/reports` endpoints (Fleet 4.93 and later). |
| `windows/`, `logsink-windows/` | Hand-made from the osquery Windows `certificates` and `file` schema (sid, store_location, store, username, store_id); synthetic values. **Not recorded on Windows**: the Windows CI job (`.github/workflows/windows-osquery.yml`) is written but has not run, and no local Windows run was possible (osquery publishes no SHA-256 for 5.12.1). |

`record-inner.sh` creates throw-away keys inside the container and deletes
them there; they never leave the container. `Dockerfile.osquery` builds the
test image (osquery 5.12.1 on Ubuntu 24.04).
