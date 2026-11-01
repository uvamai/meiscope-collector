#!/usr/bin/env bash
# Fails when a keystore or key file is tracked by git.
# Usage: check-tracked-keystores.sh [ALLOWED_PATH ...]
# Any .p12, .pfx, .jks, .kdb or .key file not listed as an argument is an error.
set -eu
allowed=("$@")
bad=0
while IFS= read -r f; do
  ok=0
  for a in ${allowed[@]+"${allowed[@]}"}; do
    if [ "$f" = "$a" ]; then ok=1; fi
  done
  if [ "$ok" = 0 ]; then
    echo "tracked keystore or key file is not allowed: $f"
    bad=1
  fi
done < <(git ls-files | grep -iE '\.(p12|pfx|jks|kdb|key)$' || true)
if [ "$bad" != 0 ]; then exit 1; fi
echo "no tracked keystore or key files outside the allowed paths"
