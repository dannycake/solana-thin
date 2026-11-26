#!/usr/bin/env bash
# The checks too heavy for CI: everything that links Agave or runs for a long
# time. Meant for a timer on a development machine (ops/install-nightly.sh).
# Every step runs even when an earlier one fails. The exit status is 0 only if
# every step asked for ran and passed, 1 if any failed, and 2 if none failed
# but one could not run: a step left out is not a step that passed.
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
SKIPPED=()
SUMMARY=$RUN/summary.txt

# A misspelled step would select nothing, and nothing would then "pass".
for s in ${WANT[@]+"${WANT[@]}"}; do
  case $s in
    tests | oracle | fuzz | fixtures | tripwire) ;;
    *)
      echo "nightly: unknown step '$s' (steps: tests, oracle, fuzz, fixtures, tripwire)" >&2
      exit 64
      ;;
  esac
done

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

# skip <name> <why>: a step that was asked for and cannot run here.
skip() {
  printf 'SKIP  %-18s        %s\n' "$1" "$2" | tee -a "$SUMMARY"
  SKIPPED+=("$1")
}

cd "$ROOT"
step tests cargo test --workspace --all-features

ORACLE=$BUILD/fixtures-target/release/diff-fuzz
if [ -e "$ROOT/tools/agave/Cargo.toml" ]; then
  step oracle-build env -C "$ROOT/tools/agave-fixtures" CARGO_TARGET_DIR="$BUILD/fixtures-target" cargo build --release --bin diff-fuzz
  step oracle-smoke "$ORACLE" --smoke
  step oracle-corpus "$ORACLE" --corpus
  step oracle-recovery "$ORACLE" --corpus --recovery
  step oracle-random "$ORACLE" --random "${ORACLE_CASES:-20000}" --seed "$(date -u +%s)"
  # The other tool that links Agave. Its tests use no network.
  step oracle-snapshots env -C "$ROOT/tools/agave-fixtures" CARGO_TARGET_DIR="$BUILD/fixtures-target" cargo test --release --bin snapshot-stakes
elif wanted oracle; then
  skip oracle "no Agave checkout at tools/agave (see tools/agave-fixtures/README.md)"
fi

step fuzz env FUZZ_SECONDS="${FUZZ_SECONDS:-600}" CARGO_TARGET_DIR="$BUILD/fuzz-target" "$ROOT/scripts/fuzz.sh"
step fixtures env -C "$ROOT/tools/shred-fixtures" CARGO_TARGET_DIR="$BUILD/shred-fixtures-target" cargo run --release -- --tag "${FIXTURES_TAG:-54829b38}"
step tripwire python3 "$ROOT/scripts/tripwire.py"

MARK=$STATE/nightly/FAILED
PARTIAL=$STATE/nightly/INCOMPLETE
ALSO=""
[ ${#SKIPPED[@]} -gt 0 ] && ALSO=", skipped: ${SKIPPED[*]}"
if [ ${#FAILED[@]} -gt 0 ]; then
  { echo "$(date -u +%FT%TZ) failed: ${FAILED[*]}"; echo "logs: $RUN"; } >"$MARK"
  echo "nightly: FAILED (${FAILED[*]})$ALSO; logs in $RUN" | tee -a "$SUMMARY"
  command -v notify-send >/dev/null && notify-send -u critical "solana-thin nightly failed" "${FAILED[*]} (logs: $RUN)" || true
  exit 1
fi
rm -f "$MARK"
if [ ${#SKIPPED[@]} -gt 0 ]; then
  # Nothing that ran failed, and the run is still not a pass: last-ok stays
  # where the last complete run left it.
  { echo "$(date -u +%FT%TZ) skipped: ${SKIPPED[*]}"; echo "logs: $RUN"; } >"$PARTIAL"
  echo "nightly: INCOMPLETE, skipped: ${SKIPPED[*]}; the steps that ran passed; logs in $RUN" | tee -a "$SUMMARY"
  command -v notify-send >/dev/null && notify-send "solana-thin nightly incomplete" "skipped: ${SKIPPED[*]} (logs: $RUN)" || true
  exit 2
fi
rm -f "$PARTIAL"
date -u +%FT%TZ >"$STATE/nightly/last-ok"
echo "nightly: all steps passed; logs in $RUN" | tee -a "$SUMMARY"
