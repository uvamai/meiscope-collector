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

## Merge rule (founder decision, 1 Nov 2026)

Private repositories have no branch protection (GitHub Free), so these rules replace it. They apply to every contributor, human or agent, in every repository.

- Never push to `main`. Every change goes through a pull request from a branch.
- Merge only when `gh pr checks <n>` shows every check passed. Paste that output in your report before each merge.
- Merge with `gh pr merge <n> --merge`. Never `--admin`, never squash or rebase, never `--no-verify`.
- Run `task hooks` once in every clone. The `pre-push` hook (`scripts/git-hooks/pre-push`) refuses any push to `main` and any force-push, and it applies to all worktrees of the clone.
- `.github/workflows/main-guard.yml` raises an issue assigned to the owner, and fails, when a commit lands on `main` without a merged pull request.
- GitHub Free for now. Revisit GitHub Pro before the first external engineer joins.
