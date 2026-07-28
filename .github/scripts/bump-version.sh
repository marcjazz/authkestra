#!/usr/bin/env bash
# bump-version.sh <new-version>
#
# Atomically bumps the version across the entire authkestra workspace:
#   - [package] version in every crates/*/Cargo.toml
#   - [workspace.dependencies] pins in the root Cargo.toml
#   - Version strings in website docs and README.md
#
# Usage:
#   bash .github/scripts/bump-version.sh 0.2.4
set -euo pipefail

NEW_VERSION="${1:?Usage: bump-version.sh <new-version>  (e.g. 0.2.4)}"

ROOT="$(git rev-parse --show-toplevel)"

echo "🔖 Bumping all crates to $NEW_VERSION"
echo ""

# ── 1. Every crate's [package] version ───────────────────────────────────────
# Uses awk to only touch the first `version = "..."` inside a [package] block,
# avoiding false positives on third-party dependency version pins.
for toml in "$ROOT"/crates/*/Cargo.toml; do
  crate="$(basename "$(dirname "$toml")")"
  awk -v ver="$NEW_VERSION" '
    /^\[package\]/ { in_pkg=1 }
    /^\[/ && !/^\[package\]/ { in_pkg=0 }
    in_pkg && /^version = "/ {
      sub(/version = "[^"]*"/, "version = \"" ver "\"")
    }
    { print }
  ' "$toml" > "$toml.tmp" && mv "$toml.tmp" "$toml"
  echo "  ✔ $crate"
done

# ── 2. Root Cargo.toml [workspace.dependencies] pins ─────────────────────────
# Matches lines of the form:
#   authkestra-engine = { version = "0.2.3", path = "..." }
sed -i -E \
  's/(authkestra[a-z-]* = \{ version = ")[^"]*/\1'"$NEW_VERSION"'/' \
  "$ROOT/Cargo.toml"
echo "  ✔ root Cargo.toml (workspace.dependencies)"

# ── 3. Website docs + README version strings in TOML code blocks ──────────────
# Only replaces version = "0.x.y" style strings (not prose mentions of versions).
FILES=$(grep -rl 'version = "0\.' \
  "$ROOT/website/src/content/docs/" \
  "$ROOT/README.md" 2>/dev/null || true)

if [ -n "$FILES" ]; then
  echo "$FILES" | xargs sed -i -E \
    's/version = "0\.[0-9]+\.[0-9]+"/version = "'"$NEW_VERSION"'"/g'
  echo "$FILES" | while read -r f; do
    echo "  ✔ ${f#"$ROOT/"}"
  done
fi

echo ""
echo "✅ All locations bumped to $NEW_VERSION"
echo "   Verify: grep -r 'version = \"$NEW_VERSION\"' crates/*/Cargo.toml"
