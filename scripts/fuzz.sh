#!/usr/bin/env bash
# Fuzz tests: each target in fuzz/ for a while (FUZZ_SECONDS, 30 by default), failing on a
# panic, a broken property, a leak, a timeout, running out of memory, or a target that doesn't
# build or run. The targets and what each one holds the crate to are described at the top of
# fuzz/fuzz_targets/*.rs. None of this needs the Agave checkout: the validator's parsers come
# from crates.io, pinned in fuzz/Cargo.toml and fuzz/Cargo.lock, for two releases: the one
# mainnet runs and, in the targets named *_45, the next.
#
# cargo-fuzz runs on nightly (`rustup toolchain install nightly --profile minimal; cargo
# install cargo-fuzz`). What a run finds stays in fuzz/corpus (not in git) and makes the next
# run start further on; a failing input is left in fuzz/artifacts/<target>/.
#
# The differential targets print a `tally` line: how often the two parsers agreed, and how
# often they differed in a way that is allowed. FUZZ_FAIL_ON=<label> turns one of those into a
# failure, to get an example of it (see fuzz/src/lib.rs).
#
# Usage: scripts/fuzz.sh [target…]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT/fuzz"
SECONDS_EACH=${FUZZ_SECONDS:-30}
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  LIST=$(cargo +nightly fuzz list) || { echo "FAIL: cargo-fuzz on nightly isn't there to list the targets" >&2; exit 1; }
  mapfile -t TARGETS <<<"$LIST"
fi
[ ${#TARGETS[@]} -gt 0 ] && [ -n "${TARGETS[0]}" ] || { echo "FAIL: no fuzz targets" >&2; exit 1; }
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# Starting inputs: valid proofs, transactions, bitmaps and components, rewritten from the
# crate as it is now. A seed that no longer verifies stops the run here.
if ! cargo +nightly run --release --bin seed_corpus -- corpus >"$LOG" 2>&1; then
  tail -n 30 "$LOG" >&2
  echo "FAIL: seed_corpus (the starting inputs could not be written)" >&2
  exit 1
fi

SUMMARY=()
for t in "${TARGETS[@]}"; do
  mkdir -p "corpus/$t"
  echo "fuzzing $t for ${SECONDS_EACH}s…"
  status=0
  # -O -a: optimized, with overflow checks and debug assertions, so arithmetic that would wrap
  # silently in a release build fails here. One input may take 20 s and one allocation 128 MB:
  # far beyond anything these parsers should need for inputs of a few kilobytes.
  cargo +nightly fuzz run -O -a "$t" "corpus/$t" -- -max_total_time="$SECONDS_EACH" \
    -timeout=20 -rss_limit_mb=4096 -malloc_limit_mb=128 >"$LOG" 2>&1 || status=$?
  # No artifacts folder yet (a target that stopped before libFuzzer made it): nothing found, and
  # the failure below still says why (under pipefail, find's error ended the script silently).
  found=$(find "artifacts/$t" -type f \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'leak-*' \) 2>/dev/null | head -1 || true)
  if [ "$status" -ne 0 ] || [ -n "$found" ]; then
    # The panic with its message (the lines after it), then what libFuzzer said about it.
    why=$({ grep -E -A2 "panicked at" "$LOG" | head -9; grep -E "ERROR|SUMMARY|Test unit written|^error" "$LOG" | head -12; } || true)
    if [ "$status" -eq 0 ]; then
      # This run was clean: the input is from an earlier one. It fails every run until it is
      # dealt with and removed.
      why="an input that failed an earlier run is still in fuzz/artifacts/$t/"
    fi
    # Nothing it knows to pick out (a build that stopped, a toolchain missing): the log's end.
    echo "${why:-$(tail -n 30 "$LOG")}" >&2
    echo "FAIL: $t (exit $status) ${found:+found fuzz/$found}" >&2
    exit 1
  fi
  done_line=$(grep -E "^Done [0-9]+ runs" "$LOG" | tail -1 || true)
  runs=$(sed -E 's/^Done ([0-9]+) runs in ([0-9]+) .*/\1/' <<<"$done_line")
  secs=$(sed -E 's/^Done ([0-9]+) runs in ([0-9]+) .*/\2/' <<<"$done_line")
  if ! [[ "$runs" =~ ^[0-9]+$ && "$secs" =~ ^[0-9]+$ ]] || [ "$runs" -eq 0 ]; then
    tail -n 30 "$LOG" >&2
    echo "FAIL: $t ran nothing" >&2
    exit 1
  fi
  line=$(printf '%-22s %10d runs in %3ds  %7d/s' "$t" "$runs" "$secs" $((runs / (secs > 0 ? secs : 1))))
  tally=$(grep -E "^tally " "$LOG" | tail -1 | sed -E 's/^tally [^:]+: //' || true)
  echo "  $line"
  [ -z "$tally" ] || echo "    $tally"
  SUMMARY+=("$line${tally:+
    $tally}")
done
echo
echo "fuzz: every target ran clean"
printf '  %s\n' "${SUMMARY[@]}"
