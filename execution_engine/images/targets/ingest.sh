#!/usr/bin/env bash
# BugFund target ingestion entrypoint.
#
# Env:
#   TARGET_REPO          git URL to clone (required)
#   TARGET_COMMIT        commit/pin to checkout (default: HEAD)
#   TARGET_ROOT          destination root (default: /srv/target)
#   BUILD_INSTRUCTIONS   JSON recipe: {"commands": [...], "env": {...}}
set -euo pipefail

: "${TARGET_REPO:?TARGET_REPO is required}"
TARGET_COMMIT="${TARGET_COMMIT:-HEAD}"
WORK="${TARGET_ROOT:-/srv/target}"
mkdir -p "$WORK/src"

echo "ingest: cloning $TARGET_REPO @ $TARGET_COMMIT"
git clone --quiet "$TARGET_REPO" "$WORK/src"
cd "$WORK/src"
git checkout "$TARGET_COMMIT"

# Apply optional env from the build recipe.
if [[ -n "${BUILD_INSTRUCTIONS:-}" ]]; then
  while IFS='=' read -r k v; do
    [[ -n "$k" ]] && export "$k=$v"
  done < <(echo "$BUILD_INSTRUCTIONS" | jq -r '.env // {} | to_entries[] | "\(.key)=\(.value)"')
  # Run each build command in a login shell.
  while IFS= read -r cmd; do
    [[ -z "$cmd" ]] && continue
    echo "ingest: $ $cmd"
    bash -lc "$cmd"
  done < <(echo "$BUILD_INSTRUCTIONS" | jq -r '.commands[]? // empty')
fi

echo "ingest: complete"
echo "INGEST_OK"
