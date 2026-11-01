#!/bin/sh
# Installs scripts/git-hooks/pre-push into this clone's shared hooks directory,
# which every worktree of the clone uses. Run it with "task hooks".
set -eu
root="$(git rev-parse --show-toplevel)"
hooks="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
mkdir -p "$hooks"
cp "$root/scripts/git-hooks/pre-push" "$hooks/pre-push"
chmod +x "$hooks/pre-push"
echo "installed pre-push guard in $hooks"
