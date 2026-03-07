#!/usr/bin/env bash
set -euo pipefail

CRATE="${1:-}"

if [ -z "$CRATE" ]; then
  echo "❌ Missing crate name argument"
  exit 1
fi

echo "Preparing publish check for $CRATE"

set +e
DRY_RUN_OUTPUT=$(cargo publish --dry-run -p "$CRATE" 2>&1)
DRY_RUN_EXIT=$?
set -e

if [ $DRY_RUN_EXIT -ne 0 ]; then
  if echo "$DRY_RUN_OUTPUT" | grep -q "already exists on crates.io index"; then
    echo "⚠️  Crate version already exists. Skipping publish."
    exit 0
  fi

  echo "❌ Dry-run failed:"
  echo "$DRY_RUN_OUTPUT"
  exit $DRY_RUN_EXIT
fi

echo "Dry-run successful. Publishing $CRATE..."

cargo publish -p "$CRATE"

echo "⏳ Waiting for registry index propagation"
sleep 20