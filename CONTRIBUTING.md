# Contributing to meiscope-collector

Thank you for helping. This repository is the open-source collector of
Meiscope, licensed under Apache-2.0.

## Before you start

- Open an issue describing the change before large pull requests.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.
- Every contributor signs the [Contributor Licence Agreement](CLA.md) once,
  before the first pull request is merged.

## Development

```sh
task doctor   # check the toolchain (Go 1.27.3, task, golangci-lint, gofumpt, nFPM)
task build
task test
task lint
```

`GOTOOLCHAIN=local` is expected; the Go version is pinned in `go.mod`.

## Rules

- Minimum code that solves the problem; tests come with the code.
- Format with `gofumpt`; `task lint` must be clean.
- Never add a probe that authenticates to a target; the TLS handshake stops
  after the server's Certificate message.
- Credentials and private keys are never written to disk, logs or observations.
- Changes to `api/collector.yaml` are additive only within `/v1`.
- New dependencies: licence must be on the allow-list (MIT, BSD-2/3,
  Apache-2.0, MPL-2.0, ISC, Unlicense); justify the dependency in the pull
  request and add it to `NOTICE` where its licence requires.
- Every adapter ships with redacted recorded fixtures; every probe plugin ships
  with a TLS zoo target.

## Pull requests

- Short-lived branches (`feat/...`, `fix/...`, `docs/...`), squash-merged with a
  [Conventional Commit](https://www.conventionalcommits.org/) title, for
  example `feat(probe): add LDAP StartTLS plugin`.
- CI (`.github/workflows/pr.yml`) must be green.
