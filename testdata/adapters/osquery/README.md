# osquery adapter fixtures

All host names are synthetic (`*.example.test`); no customer data, no secrets.

| Directory | Origin |
|---|---|
| `logsink/osqueryd.snapshots.log` | Recorded: osquery 5.12.1 on Ubuntu 24.04 (container `--hostname app01.example.test`) running `packs/osquery/meiscope.conf` with the filesystem logger, by `record-linux.sh`. The certificates are the distribution trust store plus a synthetic test CA; the keystores are synthetic files made by the script. |
| `direct/` | Recorded: `osqueryi --json` of the two posix pack queries in the same container. |
| `fleet/` | Hand-made from the Fleet REST API shapes (`GET /api/v1/fleet/queries`, `GET /api/v1/fleet/queries/{id}/report`); synthetic values. |
| `windows/`, `logsink-windows/` | Hand-made from the osquery Windows `certificates` schema (sid, store_location, store, username, store_id); synthetic values. No Windows host was available to record. |

`record-linux.sh` creates throw-away keys inside the container to build the
synthetic keystore; they are deleted there and never leave it. Only paths,
sizes and SHA-256 digests are recorded.
