#!/usr/bin/env bash
# Normalize a Rust crate Cargo.toml that used workspace dependencies into pinned standalone versions.
# Usage: ./migration/normalize-rust-standalone.sh <crate-dir>
# Creates a Cargo.toml.orig backup if modifications occur.
set -euo pipefail
DIR=${1:-}
[[ -z $DIR ]] && echo "Usage: $0 <crate-dir>" >&2 && exit 1
[[ ! -f $DIR/Cargo.toml ]] && echo "Cargo.toml not found in $DIR" >&2 && exit 1

pushd "$DIR" >/dev/null
if ! grep -q 'workspace = true' Cargo.toml; then
  echo "[normalize] No workspace deps detected; skipping" >&2
  exit 0
fi
cp Cargo.toml Cargo.toml.orig 2>/dev/null || true

declare -A PIN=( [clap]="4.5" [serde]="1.0" [serde_yaml]="0.9" [serde_json]="1.0" [anyhow]="1.0" [thiserror]="1.0" [tracing]="0.1" [tracing-subscriber]="0.3" [chrono]="0.4" [uuid]="1" [schemars]="0.8" )
# Replace simple forms: dep = { workspace = true }
for dep in "${!PIN[@]}"; do
  ver=${PIN[$dep]}
  # curly form
  sed -i -E "s#^${dep}[[:space:]]*=[[:space:]]*\{[[:space:]]*workspace[[:space:]]*=[[:space:]]*true[[:space:]]*\}#${dep} = { version = \"${ver}\" }#" Cargo.toml || true
  # plain form
  sed -i -E "s#^${dep}[[:space:]]*=[[:space:]]*workspace[[:space:]]*=.*#${dep} = \"${ver}\"#" Cargo.toml || true
  # degenerate pattern: dep = { workspace = true, features = [...] }
  if grep -q "^${dep} = { workspace = true, features" Cargo.toml; then
    feat=$(grep "^${dep} = { workspace = true, features" Cargo.toml | sed -E 's/.*features *= *\[(.*)\].*/\1/' )
    sed -i -E "s#^${dep} = { workspace = true, features = \[(.*)\] }#${dep} = { version = \"${ver}\", features = [\1] }#" Cargo.toml
  fi
  # Ensure derive features for clap & serde
  if grep -q '^clap = ' Cargo.toml && ! grep -q 'clap = { version' Cargo.toml; then
    sed -i -E 's/^clap = "([0-9.]+)"/clap = { version = "\1", features=["derive"] }/' Cargo.toml
  fi
  if grep -q '^serde = ' Cargo.toml && ! grep -q 'features=' Cargo.toml; then
    sed -i -E 's/^serde = "([0-9.]+)"/serde = { version = "\1", features=["derive"] }/' Cargo.toml
  fi
  # Add env-filter feature to tracing-subscriber if present without features
  if grep -q '^tracing-subscriber = "' Cargo.toml; then
    sed -i -E 's/^tracing-subscriber = "([0-9.]+)"/tracing-subscriber = { version = "\1", features=["fmt","env-filter"] }/' Cargo.toml
  fi
  if grep -q '^uuid = "' Cargo.toml; then
    sed -i -E 's/^uuid = "([0-9.]+)"/uuid = { version = "\1", features=["v4"] }/' Cargo.toml
  fi
  if grep -q '^chrono = "' Cargo.toml; then
    sed -i -E 's/^chrono = "([0-9.]+)"/chrono = { version = "\1", features=["clock"] }/' Cargo.toml
  fi

done

# Remove root workspace section if present (since standalone)
sed -i '/^\[workspace\]/,/^$/d' Cargo.toml || true

# Emit pinned dependency map
pins_json=$(awk '/^\[dependencies\]/{f=1;next}/^\[/{if(f){exit}}f' Cargo.toml \
  | grep -E '^[a-zA-Z0-9_-]+ *= *' \
  | sed -E 's/#.*//' \
  | awk -F= '{gsub(/ /,"",$1); dep=$1; rest=$0; if(rest ~ /version/){ if(match(rest,/version *= *\"([^\"]+)\"/,m)){ver=m[1]} } else if(match(rest,/= *\"([^\"]+)\"/,m)){ver=m[1]} else {ver=""}; if(ver!=""){printf "%s %s\n",dep,ver}}' \
  | jq -R 'split(" ") | { (.[0]): .[1] }' | jq -s 'add')
echo "$pins_json" > pinned-deps.json

echo "[normalize] Standalone dependency pinning complete (pinned-deps.json written)" >&2
popd >/dev/null
