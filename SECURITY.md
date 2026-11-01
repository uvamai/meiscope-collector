# Security policy

The collector runs inside customer networks, so we treat its security as the
product's first requirement.

## Reporting a vulnerability

Please **do not open a public issue.** Report privately through GitHub's
private vulnerability reporting: the **Security** tab of
`github.com/uvamai/meiscope-collector`, then **Report a vulnerability**.

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
- Private keys never leave the host; credentials are leased from the
  customer's vault and never written to disk, logs or observations.
- Probes never authenticate to a target.
