#!/usr/bin/env bash
set -euo pipefail

# Usage: ./devtools/scripts-meta/bump_version.sh <major|minor|patch> [--no-tag]
# Bumps versions across shared Python/Rust/React packages, updates CHANGELOG, commits & tags.

PART=${1:-}
TAG=1
if [[ "$PART" == "" || "$PART" == "-h" || "$PART" == "--help" ]]; then
  echo "Usage: $0 <major|minor|patch> [--no-tag]"; exit 1; fi
if [[ "${2:-}" == "--no-tag" ]]; then TAG=0; fi

get_next() {
  local ver=$1 part=$2
  IFS='.' read -r MA MI PA <<<"$ver"
  case $part in
    major) ((MA++)); MI=0; PA=0;;
    minor) ((MI++)); PA=0;;
    patch) ((PA++));;
    *) echo "Invalid part: $part"; exit 1;;
  esac
  echo "$MA.$MI.$PA"
}

PY_FILE=repo/shared/python/pyproject.toml
RUST_FILE=repo/shared/rust/Cargo.toml
TS_FILE=repo/shared/react/package.json
CHANGELOG=repo/shared/CHANGELOG.md

CUR_PY=$(grep '^version' $PY_FILE | head -1 | sed -E 's/version\s*=\s*"([0-9.]+)"/\1/')
CUR_RS=$(grep '^version' $RUST_FILE | head -1 | sed -E 's/version\s*=\s*"([0-9.]+)"/\1/')
CUR_TS=$(grep '"version"' $TS_FILE | head -1 | sed -E 's/.*"version"\s*:\s*"([0-9.]+)".*/\1/')

if [[ ! $CUR_PY == $CUR_RS || ! $CUR_PY == $CUR_TS ]]; then
  echo "Version mismatch: py=$CUR_PY rust=$CUR_RS react=$CUR_TS" >&2
  exit 1
fi

NEXT=$(get_next "$CUR_PY" "$PART")

echo "Bumping version $CUR_PY -> $NEXT"

# Python
sed -i -E "s/^version = \"[0-9.]+\"/version = \"$NEXT\"/" $PY_FILE
# Rust
sed -i -E "s/^version = \"[0-9.]+\"/version = \"$NEXT\"/" $RUST_FILE
# React
sed -i -E "s/\"version\"\s*:\s*\"[0-9.]+\"/\"version\": \"$NEXT\"/" $TS_FILE

# Changelog
if [[ ! -f $CHANGELOG ]]; then
  echo "# Changelog" > $CHANGELOG
fi
DATE=$(date +%Y-%m-%d)
{ echo -e "\n## $NEXT - $DATE\n- TBD"; } >> $CHANGELOG

if [[ -n $(git diff --name-only $PY_FILE $RUST_FILE $TS_FILE $CHANGELOG) ]]; then
  git add $PY_FILE $RUST_FILE $TS_FILE $CHANGELOG
  git commit -m "chore(version): bump shared libs to $NEXT"
  if [[ $TAG -eq 1 ]]; then
    git tag "shared_v$NEXT"
  fi
  echo "Done. Remember: git push && git push --tags"
else
  echo "No changes detected"; fi
