#!/usr/bin/env bash
# The verifier in a JavaScript engine.
#
#   1. Builds solana-thin for wasm32-unknown-unknown, as an app's own crate
#      would take it.
#   2. Builds crates/solana-thin-wasm, the verifier as a module with no
#      imports, in release mode.
#   3. Verifies a mainnet proof in that module under node
#      (crates/solana-thin-wasm/check.mjs).
#
# Needs the wasm32-unknown-unknown target (rustup target add), a clang that
# can compile for wasm32 (blst is C), and node.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
# Honour a cargo config that redirects the target directory, not just the env var.
target=${CARGO_TARGET_DIR:-$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')}

echo "== solana-thin for wasm32-unknown-unknown"
cargo build --locked -p solana-thin --target wasm32-unknown-unknown

echo "== the module"
cargo build --locked -p solana-thin-wasm --target wasm32-unknown-unknown --release
module=$target/wasm32-unknown-unknown/release/solana_thin_wasm.wasm

echo "== a mainnet proof under node"
node crates/solana-thin-wasm/check.mjs "$module" \
  crates/solana-thin/tests/vectors/mainnet-block-473100911.json
