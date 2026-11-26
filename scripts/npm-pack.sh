#!/usr/bin/env bash
# Build the WebAssembly module and assemble the npm package in
# crates/solana-thin-wasm, then inspect or publish it.
#
#   scripts/npm-pack.sh pack       # npm pack --dry-run: list what would ship
#   scripts/npm-pack.sh publish    # npm publish to the registry
#
# The package (name "solana-thin") ships the wrapper solana-thin.mjs, its type
# declarations, and the built solana_thin_wasm.wasm. The .wasm and a copy of
# LICENSE are placed in the package directory only for the duration of this
# script; they are not committed.
#
# Needs the wasm32-unknown-unknown target (rustup target add), a clang that can
# compile for wasm32 (blst is C), node and npm.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
action=${1:-pack}
pkg=crates/solana-thin-wasm

# The real target directory, honouring a cargo config that redirects it.
target=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')

echo "== building the module"
cargo build --locked -p solana-thin --target wasm32-unknown-unknown
cargo build --locked -p solana-thin-wasm --target wasm32-unknown-unknown --release
module=$target/wasm32-unknown-unknown/release/solana_thin_wasm.wasm
test -f "$module" || { echo "module not found at $module" >&2; exit 1; }

echo "== assembling the package"
cp "$module" "$pkg/solana_thin_wasm.wasm"
cp LICENSE "$pkg/LICENSE"
trap 'rm -f "$pkg/solana_thin_wasm.wasm" "$pkg/LICENSE"' EXIT

echo "== npm $action (from $pkg)"
cd "$pkg"
case "$action" in
  pack) npm pack --dry-run ;;
  publish) npm publish ;;
  *) echo "usage: $0 [pack|publish]" >&2; exit 2 ;;
esac
