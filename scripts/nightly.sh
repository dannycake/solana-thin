#!/usr/bin/env bash
# The checks too heavy for CI: everything that links Agave or runs for a long
# time. Meant for a timer on a development machine (ops/install-nightly.sh).
# Every step runs even when an earlier one fails; the exit status is non-zero
# if any did.
#
#   scripts/nightly.sh            # all steps
#   scripts/nightly.sh fuzz tripwire   # only these
#
# Steps: tests, oracle, fuzz, fixtures, tripwire.
#
# Environment:
#   SOLANA_THIN_BUILD   where build output goes (default: <repo>/target/nightly)
#   SOLANA_THIN_STATE   where logs go (default: $XDG_STATE_HOME/solana-thin)
#   FUZZ_SECONDS        per fuzz target (default 600)
#   ORACLE_CASES        random oracle cases (default 20000)
#   FIXTURES_TAG        firedancer-io/test-vectors release (default 54829b38)
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${SOLANA_THIN_BUILD:-$ROOT/target/nightly}
STATE=${SOLANA_THIN_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/solana-thin}
RUN=$STATE/nightly/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$RUN" "$BUILD"
WANT=("$@")
FAILED=()
SUMMARY=$RUN/summary.txt

wanted() {
  [ ${#WANT[@]} -eq 0 ] && return 0
  local s
  for s in "${WANT[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}

# step <name> <command...>: run it, keep its output, record how it went.
step() {
  local name=$1
  shift
  local group=${name%%-*}
  wanted "$group" || return 0
  local started=$SECONDS status=0
  "$@" >"$RUN/$name.log" 2>&1 || status=$?
  local took=$((SECONDS - started))
  if [ "$status" -eq 0 ]; then
    printf 'ok    %-18s %5ss  %s\n' "$name" "$took" "$(tail -n 1 "$RUN/$name.log" | cut -c1-90)" | tee -a "$SUMMARY"
  else
    printf 'FAIL  %-18s %5ss  exit %s, see %s\n' "$name" "$took" "$status" "$RUN/$name.log" | tee -a "$SUMMARY"
    FAILED+=("$name")
  fi
}

cd "$ROOT"
step tests cargo test --workspace --all-features

ORACLE=$BUILD/fixtures-target/release/diff-fuzz
if [ -e "$ROOT/tools/agave/Cargo.toml" ]; then
  step oracle-build env -C "$ROOT/tools/agave-fixtures" CARGO_TARGET_DIR="$BUILD/fixtures-target" cargo build --release --bin diff-fuzz
  step oracle-smoke "$ORACLE" --smoke
  step oracle-corpus "$ORACLE" --corpus
  step oracle-random "$ORACLE" --random "${ORACLE_CASES:-20000}" --seed "$(date -u +%s)"
elif wanted oracle; then
  echo "skip  oracle: no Agave checkout at tools/agave (see tools/agave-fixtures/README.md)" | tee -a "$SUMMARY"
fi

step fuzz env FUZZ_SECONDS="${FUZZ_SECONDS:-600}" CARGO_TARGET_DIR="$BUILD/fuzz-target" "$ROOT/scripts/fuzz.sh"
step fixtures env -C "$ROOT/tools/shred-fixtures" CARGO_TARGET_DIR="$BUILD/shred-fixtures-target" cargo run --release -- --tag "${FIXTURES_TAG:-54829b38}"
step tripwire python3 "$ROOT/scripts/tripwire.py"

MARK=$STATE/nightly/FAILED
if [ ${#FAILED[@]} -gt 0 ]; then
  { echo "$(date -u +%FT%TZ) failed: ${FAILED[*]}"; echo "logs: $RUN"; } >"$MARK"
  echo "nightly: FAILED (${FAILED[*]}); logs in $RUN" | tee -a "$SUMMARY"
  command -v notify-send >/dev/null && notify-send -u critical "solana-thin nightly failed" "${FAILED[*]} (logs: $RUN)" || true
  exit 1
fi
rm -f "$MARK"
date -u +%FT%TZ >"$STATE/nightly/last-ok"
echo "nightly: all steps passed; logs in $RUN" | tee -a "$SUMMARY"
