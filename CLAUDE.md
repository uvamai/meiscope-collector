# Meiscope collector (meiscope-collector, Apache-2.0)

Outbound-only probe and adapter runner deployed in customer networks. Go only. Public repository: nothing proprietary, no references to the private core beyond the vendored collector API contract.

## Stack
- Build: task build (linux/amd64, linux/arm64, windows/amd64)   · Test: task test · task test:zoo (TLS zoo) · task test:policy (ScanPolicy property tests)
- Lint: task lint   · Package: task package (nFPM)   · Doctor: task doctor

## Rules that override defaults
- Never authenticate to a target; stop the handshake after the Certificate message; obey ScanPolicy (one connection per target:port, rate per /24, windows, canary, pause).
- Credentials come only through the CredentialSource interface and are never written to disk, logs or observations.
- Private keys never leave the host; the collector sends CSRs and public certificates only.
- Additive-only changes to the collector API surface; support core versions N-2.
- Every adapter ships with redacted recorded fixtures; every probe plugin ships with a TLS zoo target.
