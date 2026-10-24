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
health endpoint listens on loopback by default.
