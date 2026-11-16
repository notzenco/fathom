#!/usr/bin/env bash
#
# bench.sh — Measure how fast fathom finds each benchmark target's crash
#
# Usage: bash tests/bench.sh [seconds per run] [runs per target]
#
# Every target is fuzzed from the seed "AAAA" with seeds -s 1..runs, each
# run stopping at its first crash or after the time budget.  The table
# shows, per target, how many runs found the crash, the median time and
# executions to find it among those that did, the median execution rate
# and the median number of blocks covered.  Compare two builds by running
# this on each.

set -euo pipefail

SECS=${1:-30}
RUNS=${2:-5}
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=.exe ;; *) EXE= ;; esac
FATHOM="$ROOT_DIR/fathom$EXE"
TARGETS="$ROOT_DIR/tests/targets"
TARGET_LIST=${BENCH_TARGETS:-"maze magic_memcmp be_length o2_compare heap_overflow stack_smash"}

make -C "$ROOT_DIR" -s all targets >/dev/null

WORK=$(mktemp -d "${TMPDIR:-/tmp}/fathom-bench-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/seeds"
printf 'AAAA' > "$WORK/seeds/a"

stat_of() { awk -v k="$2" '$1 == k { print $2 }' "$1/fuzzer_stats" 2>/dev/null; }

# Median of the numbers on stdin, or "-" if there are none.
median() {
    sort -n | awk '{ v[NR] = $1 } END {
        if (NR == 0) { print "-"; exit }
        print (NR % 2) ? v[(NR + 1) / 2] : int((v[NR / 2] + v[NR / 2 + 1]) / 2) }'
}

printf '%-14s %7s %12s %12s %10s %8s\n' target found "ms to crash" "execs" "execs/s" blocks
for t in $TARGET_LIST; do
    : > "$WORK/ms"; : > "$WORK/execs"; : > "$WORK/rate"; : > "$WORK/cov"
    found=0
    for seed in $(seq 1 "$RUNS"); do
        out="$WORK/$t-$seed"
        "$FATHOM" -i "$WORK/seeds" -o "$out" -t 1000 -T "$SECS" -s "$seed" --until-crash \
            -- "$TARGETS/$t$EXE" >/dev/null 2>&1 || true
        stat_of "$out" execs_per_sec >> "$WORK/rate"
        stat_of "$out" covered >> "$WORK/cov"
        if [ "$(stat_of "$out" unique_crashes)" -gt 0 ] 2>/dev/null; then
            found=$((found + 1))
            stat_of "$out" first_crash_ms >> "$WORK/ms"
            stat_of "$out" first_crash_execs >> "$WORK/execs"
        fi
    done
    printf '%-14s %3d/%-3d %12s %12s %10s %8s\n' "$t" "$found" "$RUNS" \
        "$(median < "$WORK/ms")" "$(median < "$WORK/execs")" \
        "$(median < "$WORK/rate")" "$(median < "$WORK/cov")"
done
