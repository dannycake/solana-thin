#!/usr/bin/env bash
# Holds the Kotlin and Swift bindings to the Rust they are generated from.
#
#   1. Builds solana-thin-ffi for this machine and lists the interface it
#      exports, which must be the one in crates/solana-thin-ffi/interface.txt.
#   2. Generates the Kotlin and Swift sources from the library.
#   3. Compiles crates/solana-thin-ffi/kotlin/Smoke.kt against the generated
#      Kotlin and runs it on the JVM, where it verifies a mainnet proof
#      through the library. Needs a JDK and kotlinc.
#
# scripts/bindings.sh [--update] [--require-jvm]
#   --update        rewrite interface.txt and the committed Swift from the library
#   --require-jvm   fail, do not skip, when step 3 cannot run (CI passes this)
#
# Environment:
#   PROFILE   cargo profile to build with: dev (default) or release
#   KOTLINC   the Kotlin compiler, default `kotlinc`
#   JNA_JAR   a JNA jar to use; by default one is downloaded from Maven
#             Central into the target directory and checked against the
#             hash below
set -euo pipefail

JNA_VERSION=5.19.1
JNA_SHA256=4fb141dd8ef6b0585ffceea4bc49602fbc6312fa977e2c488794ea3e6aafecae

update=0
require_jvm=0
for argument in "$@"; do
  case "$argument" in
    --update) update=1 ;;
    --require-jvm) require_jvm=1 ;;
    *) echo "usage: scripts/bindings.sh [--update] [--require-jvm]" >&2; exit 2 ;;
  esac
done

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
ffi=crates/solana-thin-ffi
profile=${PROFILE:-dev}
# Honour a cargo config that redirects the target directory, not just the env var.
target=${CARGO_TARGET_DIR:-$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')}
# cargo names the dev profile's directory "debug".
built=$target/$([ "$profile" = dev ] && echo debug || echo "$profile")
out=$target/bindings
case "$(uname -s)" in
  Darwin) library=$built/libsolana_thin_ffi.dylib ;;
  *) library=$built/libsolana_thin_ffi.so ;;
esac

echo "== build ($profile)"
cargo build --locked --profile "$profile" -p solana-thin-ffi -p uniffi-bindgen
cargo build --locked --profile "$profile" -p solana-thin-ffi --example smoke_vectors

echo "== the exported interface"
mkdir -p "$out"
"$built/describe-interface" "$library" > "$out/interface.txt"
if [ "$update" = 1 ]; then
  cp "$out/interface.txt" "$ffi/interface.txt"
  echo "wrote $ffi/interface.txt"
elif ! diff -u "$ffi/interface.txt" "$out/interface.txt"; then
  echo "The library's interface is not the one in $ffi/interface.txt." >&2
  echo "If the change is meant, run scripts/bindings.sh --update, and bring" >&2
  echo "$ffi/kotlin/Smoke.kt and docs/BINDINGS.md along." >&2
  exit 1
else
  echo "as in $ffi/interface.txt"
fi

echo "== generate Kotlin and Swift"
rm -rf "$out/kotlin" "$out/swift"
"$built/uniffi-bindgen" generate --no-format --language kotlin --out-dir "$out/kotlin" "$library"
"$built/uniffi-bindgen" generate --no-format --language swift --out-dir "$out/swift" "$library"
kotlin_source=$out/kotlin/uniffi/solana_thin_ffi/solana_thin_ffi.kt
for generated in "$kotlin_source" "$out/swift/solana_thin_ffi.swift" \
  "$out/swift/solana_thin_ffiFFI.h" "$out/swift/solana_thin_ffiFFI.modulemap"; do
  [ -s "$generated" ] || { echo "not generated: $generated" >&2; exit 1; }
  echo "$generated"
done

echo "== the Swift package's committed source"
# The Swift package ships the generated Swift (SwiftPM cannot run the
# generator). UniFFI's Swift output is the same on any target, so the file the
# Linux library generates must equal the committed one.
swift_committed=$root/Sources/SolanaThin/solana_thin_ffi.swift
if [ "$update" = 1 ]; then
  cp "$out/swift/solana_thin_ffi.swift" "$swift_committed"
  echo "wrote $swift_committed"
elif ! diff -u "$swift_committed" "$out/swift/solana_thin_ffi.swift"; then
  echo "$swift_committed is not what the library generates." >&2
  echo "Regenerate it with scripts/bindings.sh --update." >&2
  exit 1
else
  echo "as in $swift_committed"
fi

echo "== Kotlin smoke test"
kotlinc=${KOTLINC:-kotlinc}
missing=
command -v java > /dev/null || missing="java"
command -v "$kotlinc" > /dev/null || missing="${missing:+$missing and }$kotlinc"
if [ -n "$missing" ]; then
  if [ "$require_jvm" = 1 ]; then
    echo "not run: $missing not found, and --require-jvm was given" >&2
    exit 1
  fi
  echo "SKIPPED: $missing not found. Steps 1 and 2 passed; the binding was not run."
  exit 0
fi

jna=${JNA_JAR:-}
if [ -z "$jna" ]; then
  jna=$out/jna-$JNA_VERSION.jar
  if [ ! -f "$jna" ]; then
    curl -fsSL -o "$jna.part" \
      "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar"
    mv "$jna.part" "$jna"
  fi
  echo "$JNA_SHA256  $jna" | sha256sum --check --quiet
fi

"$built/examples/smoke_vectors" "$out/smoke-vectors"
"$kotlinc" -nowarn -classpath "$jna" "$kotlin_source" "$ffi/kotlin/Smoke.kt" \
  -include-runtime -d "$out/smoke.jar"
java -Djna.library.path="$built" -classpath "$out/smoke.jar:$jna" SmokeKt "$out/smoke-vectors"
