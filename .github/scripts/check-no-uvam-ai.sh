#!/bin/sh
# Fails if the UVAMAI hostname appears in any tracked file or path (WP0.10:
# the product uses meiscope.cloud; tests and examples use reserved names such
# as example.com and *.test). The GitHub organisation "uvamai" in github.com/
# and ghcr.io/ paths does not match: the pattern needs the dot.
# The pattern is written as uvam[.]ai so this script does not match itself.
set -eu
pattern='uvam[.]ai'
status=0
if git grep -n -i -E "$pattern" -- . ; then
  echo "::error::tracked files mention the UVAMAI hostname; use meiscope.cloud or a reserved name (example.com, *.test)"
  status=1
fi
if git ls-files | grep -i -E "$pattern"; then
  echo "::error::tracked file paths mention the UVAMAI hostname"
  status=1
fi
[ "$status" -eq 0 ] && echo "no UVAMAI hostname in tracked files or paths"
exit "$status"
