#!/bin/sh
# Compares the vendored collector contract (api/collector.yaml) with a core's
# collector.yaml and validates everything the collector emits in tests
# against the core's file, so drift is caught when the core changes.
#
# Usage: task contract:diff CORE=<path to the core's api/openapi/collector.yaml>
#        STRICT=1 also fails when the files differ at all (the vendored copy
#        is meant to be byte-identical to the core's file).
#
# Exit status: 0 when the collector's output validates against the core's
# file and the core's changes break nothing the collector relies on; 1
# otherwise. A plain difference is reported as DRIFT and is a failure only
# with STRICT=1. Needs oasdiff and Go on PATH. The core is only read.
set -u
core="${1:-}"
vend="api/collector.yaml"
if [ -z "$core" ] || [ ! -f "$core" ]; then
  echo "usage: contract-diff.sh <core collector.yaml>" >&2
  exit 2
fi
core_abs="$(cd "$(dirname "$core")" && pwd)/$(basename "$core")"
version() { sed -n 's/^  version: *//p' "$1" | head -1; }
status=0

echo "vendored: $vend (version $(version "$vend"))"
echo "core:     $core_abs (version $(version "$core_abs"))"
if cmp -s "$vend" "$core_abs"; then
  echo "IDENTICAL: the vendored copy is byte-identical to the core's file"
else
  echo "DRIFT: the vendored copy differs from the core's file; changes the core made since:"
  oasdiff changelog "$vend" "$core_abs" || true
  echo "--- breaking changes (core versus vendored), oasdiff:"
  if ! oasdiff breaking --flatten-allof "$vend" "$core_abs" --fail-on ERR; then
    echo "BREAKING: the core's contract changed in a way the collector must handle"
    status=1
  fi
  if [ "${STRICT:-0}" = "1" ]; then
    echo "STRICT: refresh api/collector.yaml from the core"
    status=1
  fi
fi

echo "--- collector output validated against the core's file (MEISCOPE_CONTRACT)"
if MEISCOPE_CONTRACT="$core_abs" go test -tags devcredentials -count=1 -v \
  -run 'TestContract|TestObservationsSubmittedToFakeCore|TestCTPollSubmitsAndSavesProgress|TestCTPollOwnedDomainsFromCore' \
  ./internal/submit/ ./internal/ct/ ./cmd/meiscope-collector/ 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL|PASS|panic)|contract /|validating against'; then
  :
fi
# The grep above hides the exit status of go test; run it once more quietly for the status.
if MEISCOPE_CONTRACT="$core_abs" go test -tags devcredentials -count=1 \
  -run 'TestContract|TestObservationsSubmittedToFakeCore|TestCTPollSubmitsAndSavesProgress|TestCTPollOwnedDomainsFromCore' \
  ./internal/submit/ ./internal/ct/ ./cmd/meiscope-collector/ >/dev/null 2>&1; then
  echo "VALIDATION: PASS (the collector's output is valid against the core's file)"
else
  echo "VALIDATION: FAIL (the collector's output is not valid against the core's file)"
  status=1
fi

echo "--- proposal check: the collector's proposed contract against the core's file"
if oasdiff breaking --flatten-allof "$core_abs" api/proposed/collector-0.5.0-proposed.yaml --fail-on ERR >/dev/null 2>&1; then
  echo "PROPOSAL: no breaking change relative to the core's file"
else
  echo "PROPOSAL: breaking relative to the core's file (the proposal needs rebasing on it):"
  oasdiff breaking --flatten-allof "$core_abs" api/proposed/collector-0.5.0-proposed.yaml || true
  status=1
fi
exit "$status"
