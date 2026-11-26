#!/usr/bin/env bash
# Runs the verifier's test suite as WebAssembly, under node's WASI.
#
# The tests are the ones `cargo test` runs natively, compiled for
# wasm32-wasip1: every check again, on a 32-bit target, with blst's C in
# place of its assembly. Two test files are left out by name because they
# test the repository and not the verifier: they start python3 and bash, and
# a WASI program cannot start a process.
#
# Needs the wasm32-wasip1 target (rustup target add), a clang that can
# compile for wasm32 (blst is C), and node 20 or newer. It takes a few
# minutes: the engine runs the signature checks about seven times slower.
#
# scripts/wasi-test.sh [arguments for cargo test]
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
export CARGO_TARGET_WASM32_WASIP1_RUNNER="node --no-warnings $root/scripts/wasi-runner.mjs"
node --version

# Listed from the directory, so that a test file added later runs here too.
tests=()
for file in crates/solana-thin/tests/*.rs; do
  name=$(basename "$file" .rs)
  case "$name" in
    conformance_ledger | nightly_script) echo "left out: $name (starts a process)" ;;
    *) tests+=(--test "$name") ;;
  esac
done

cargo test --locked -p solana-thin --target wasm32-wasip1 --lib "${tests[@]}" "$@"
