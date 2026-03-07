#!/usr/bin/env bash
set -euo pipefail

CRATE="${1:-}"

if [ -z "$CRATE" ]; then
  echo "❌ Missing crate name argument"
  exit 1
fi

echo "Preparing publish for $CRATE"

# Validate packaging first
cargo publish --dry-run -p "$CRATE"

set +e
PUBLISH_OUTPUT=$(cargo publish -p "$CRATE" 2>&1)
PUBLISH_EXIT=$?
set -e

if [ $PUBLISH_EXIT -ne 0 ]; then
  if echo "$PUBLISH_OUTPUT" | grep -q "already exists on crates.io index"; then
    echo "⚠️  $CRATE already published. Skipping."
    exit 0
  fi

  echo "$PUBLISH_OUTPUT"
  exit $PUBLISH_EXIT
fi

echo "⏳ Waiting for index propagation"
sleep 20