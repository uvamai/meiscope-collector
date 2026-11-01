# Security policy

The collector runs inside customer networks, so we treat its security as the
product's first requirement.

## Reporting a vulnerability

Please **do not open a public issue.** Report privately through GitHub's
private vulnerability reporting: the **Security** tab of
`github.com/uvamai/meiscope-collector`, then **Report a vulnerability**, or
email security@meiscope.cloud.

Include the affected version (`meiscope-collector version`), the platform,
and steps to reproduce. We acknowledge reports within 3 business days and
agree a disclosure date with you; credit is given unless you ask otherwise.

## Supported versions

Pre-release (0.x): only the latest release receives fixes.

## Verifying releases

Release artefacts are signed with cosign keyless (Sigstore, GitHub OIDC) and
come with a CycloneDX SBOM and a GitHub build provenance attestation:

```sh
cosign verify-blob \
  --bundle meiscope-collector_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/uvamai/meiscope-collector/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  meiscope-collector_linux_amd64

gh attestation verify meiscope-collector_linux_amd64 --repo uvamai/meiscope-collector
```

The Windows binary is not yet Authenticode-signed; that step is enabled once
the code-signing certificate exists.

## Design commitments

- Outbound-only connections; mutually authenticated TLS to the core.
- Private keys never leave the host; credentials come from the customer's
  vault (WP3.4) or the collector's age-encrypted credential file, and are
  never written to disk in clear text, logs or observations.
- Probes never authenticate to a target.
- Adapters read data from systems the customer already runs; they never scan
  networks or connect to arbitrary hosts. Observations carry public
  certificate data and file metadata (path, size, times, owner, mode,
  SHA-256) only, never private keys, keystore passwords or key-alias
  secrets. Keystore containers (.p12, .pfx, .jks, .kdb) are reported as
  `keystore_not_parsed` and never opened; the collector never guesses,
  defaults or brute-forces a password.
- The environment-variable credential source exists only in development
  builds (`-tags devcredentials`); release builds refuse to start when
  `MEISCOPE_DEV_CREDENTIAL_*` is set.
- The optional log-push receiver is off by default, binds only to loopback or
  a configured private address, requires a bearer token, limits requests to
  1 MiB and a rate, and treats pushed content as untrusted data (see
  docs/install.md). It expects a customer-controlled TLS terminator in front.
- The local observation buffer is encrypted (AES-256-GCM) and bounded to 72
  hours and a size limit.
