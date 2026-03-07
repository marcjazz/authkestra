#!/usr/bin/env bash
set -euo pipefail

CRATE="${1:-}"

if [ -z "$CRATE" ]; then
  echo "❌ Missing crate name argument"
  exit 1
fi

echo "Publishing $CRATE"

VERSION=$(cargo metadata --no-deps --format-version=1 \
  | jq -r ".packages[] | select(.name==\"$CRATE\") | .version")

if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
  echo "❌ Failed to determine version for $CRATE"
  exit 1
fi

echo "Detected version: $VERSION"

VERSION_EXISTS=$(curl -fsSL -H "User-Agent: authkestra-ci" \
  "https://crates.io/api/v1/crates/$CRATE/versions" \
  | jq -e --arg version "$VERSION" '.versions[] | select(.num == $version)' > /dev/null && echo "true" || echo "false")

if [ "$VERSION_EXISTS" = "true" ]; then
  echo "⚠️  $CRATE $VERSION already exists on crates.io. Skipping."
  exit 0
fi

set +e
PUBLISH_OUTPUT=$(cargo publish -p "$CRATE" 2>&1)
PUBLISH_EXIT=$?
set -e

if [ $PUBLISH_EXIT -ne 0 ]; then
  if echo "$PUBLISH_OUTPUT" | grep -q "already exists on crates.io index"; then
    echo "⚠️  $CRATE $VERSION was published during this run. Skipping."
    exit 0
  fi

  echo "$PUBLISH_OUTPUT"
  exit $PUBLISH_EXIT
fi

echo "⏳ Waiting for index propagation"
sleep 20