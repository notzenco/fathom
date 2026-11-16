#!/bin/bash
#
# integration.sh — End-to-end tests for the Fathom fuzzer.
#
# Builds fathom and the test targets, then fuzzes them from a seed that
# contains none of the bytes the bugs need.  The maze target can only
# be solved with working coverage feedback, so it is the required
# check on every platform.  Runs on Linux, macOS and Windows (MSYS2).
#
# Environment:
#   MAZE_SECS   time budget for the maze (default 120)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SEED_DIR="$ROOT_DIR/tests/seeds"
MAZE_SECS="${MAZE_SECS:-120}"
OPTIONAL_SECS=20

case "$(uname -s)" in
    MINGW*|MSYS*) EXE=.exe ;;
    *)            EXE= ;;
esac
FATHOM="$ROOT_DIR/fathom$EXE"
TARGETS="$ROOT_DIR/tests/targets"

pass=0
fail_count=0
skip=0
TMPDIRS=()

cleanup() {
    for d in "${TMPDIRS[@]+"${TMPDIRS[@]}"}"; do
        rm -rf "$d"
    done
}
trap cleanup EXIT

if [ -t 1 ]; then
    GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[0;33m' BOLD='\033[1m' RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

info() { echo -e "${BOLD}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[PASS]${RESET} $*"; pass=$((pass + 1)); }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; fail_count=$((fail_count + 1)); }
warn() { echo -e "${YELLOW}[SKIP]${RESET} $*"; skip=$((skip + 1)); }

new_outdir() {
    local d
    d=$(mktemp -d "${TMPDIR:-/tmp}/fathom-it-$1-XXXXXX")
    TMPDIRS+=("$d")
    echo "$d"
}

# stat <dir> <key>: read a value from a fuzzer_stats file
stat_of() {
    awk -v k="$2" '$1 == k { print $2 }' "$1/fuzzer_stats" 2>/dev/null || true
}

count_crashes() {
    find "$1" -type f -path '*crashes/crash_*' ! -name '*.txt' 2>/dev/null | wc -l | tr -d ' '
}

# ── Build ────────────────────────────────────────────────────────────

info "Building fathom and test targets..."
cd "$ROOT_DIR"
make
make targets
[ -x "$FATHOM" ] || { fail "fathom binary not found after build"; exit 1; }
echo

# ── Coverage feedback: the maze ──────────────────────────────────────

info "maze: needs \"FUZZ\", seeded with \"AAAA\" (budget ${MAZE_SECS}s)"
out=$(new_outdir maze)
mkdir -p "$out/seeds"
printf 'AAAA' > "$out/seeds/a"
set +e
"$FATHOM" -i "$out/seeds" -o "$out/run" -t 1000 -T "$MAZE_SECS" -s 1 --until-crash \
    -- "$TARGETS/maze$EXE" 2>"$out/log"
rc=$?
set -e
crashes=$(count_crashes "$out/run")
covered=$(stat_of "$out/run" covered)
execs=$(stat_of "$out/run" execs)
first_execs=$(stat_of "$out/run" first_crash_execs)
first_ms=$(stat_of "$out/run" first_crash_ms)
if [ "$rc" -ne 0 ]; then
    fail "maze: fathom exited with status $rc"
    tail -5 "$out/log"
elif [ "$crashes" -gt 0 ]; then
    ok "maze: solved after $first_execs execs / ${first_ms} ms (covered $covered blocks)"
else
    fail "maze: not solved in ${MAZE_SECS}s ($execs execs, covered ${covered:-0} blocks)"
    cat "$out/run/fuzzer_stats" 2>/dev/null || true
    for f in "$out"/run/queue/*; do
        printf '  %s  %s\n' "$(basename "$f")" "$(od -An -tx1 -N8 "$f" | tr -d '\n')"
    done | head -20
fi

# ── Replay and minimise the maze crash ───────────────────────────────

crash=$(find "$out/run/crashes" -type f -name 'crash_*' ! -name '*.txt' 2>/dev/null | head -1)
if [ -n "$crash" ]; then
    info "replay: the saved maze crash must replay as a crash and minimise to FUZZ"
    set +e
    "$FATHOM" --replay "$crash" -- "$TARGETS/maze$EXE" 2>"$out/replay.log"
    replay_rc=$?
    "$FATHOM" --minimize "$crash" -- "$TARGETS/maze$EXE" 2>"$out/min.log"
    min_rc=$?
    set -e
    if [ "$replay_rc" -ne 2 ]; then
        fail "replay: exit status $replay_rc, expected 2 (crash)"
        cat "$out/replay.log"
    elif [ "$min_rc" -ne 0 ] || [ "$(cat "$crash.min" 2>/dev/null)" != "FUZZ" ]; then
        fail "minimize: status $min_rc, result '$(cat "$crash.min" 2>/dev/null)'"
        cat "$out/min.log"
    elif [ ! -f "$crash.txt" ]; then
        fail "crash report $crash.txt missing"
    else
        ok "replay: crash replays, minimises to FUZZ and has a report"
    fi

    set +e
    "$FATHOM" -i "$out/run/queue" -o "$out/again" -T 30 --until-crash --fail-on-crash \
        -- "$TARGETS/maze$EXE" 2>/dev/null
    again_rc=$?
    set -e
    if [ "$again_rc" -ne 2 ]; then
        fail "--fail-on-crash: exit status $again_rc, expected 2"
    elif [ -z "$(stat_of "$out/again" execs_per_sec)" ]; then
        fail "fuzzer_stats has no execs_per_sec"
    else
        ok "--fail-on-crash exits 2, fuzzer_stats is complete"
    fi
fi

# ── Classic memory-safety targets (crash behaviour varies by libc) ───

run_optional() {
    local name="$1" out rc crashes
    info "$name (optional, ${OPTIONAL_SECS}s)"
    out=$(new_outdir "$name")
    set +e
    "$FATHOM" -i "$SEED_DIR" -o "$out" -t 500 -T "$OPTIONAL_SECS" \
        -- "$TARGETS/$name$EXE" 2>"$out/log"
    rc=$?
    set -e
    crashes=$(count_crashes "$out")
    if [ "$rc" -ne 0 ]; then
        fail "$name: fathom exited with status $rc"
    elif [ "$crashes" -gt 0 ]; then
        ok "$name: found $crashes unique crash(es)"
    else
        warn "$name: no crash in ${OPTIONAL_SECS}s"
    fi
}

run_optional heap_overflow
run_optional stack_smash
run_optional format_string

# ── Hangs are not crashes ────────────────────────────────────────────

info "hang: timeouts must be reported as hangs, never crashes"
out=$(new_outdir hang)
mkdir -p "$out/seeds"
printf 'G' > "$out/seeds/g"
set +e
"$FATHOM" -i "$out/seeds" -o "$out/run" -t 200 -T 10 -s 3 \
    -- "$TARGETS/hang$EXE" 2>"$out/log"
rc=$?
set -e
hangs=$(stat_of "$out/run" hangs)
crashes=$(stat_of "$out/run" crashes)
if [ "$rc" -ne 0 ]; then
    fail "hang: fathom exited with status $rc"
elif [ "${crashes:-1}" -ne 0 ]; then
    fail "hang: $crashes run(s) misreported as crashes"
elif [ "${hangs:-0}" -gt 0 ]; then
    ok "hang: $hangs hang(s), 0 crashes"
else
    warn "hang: no hanging input found in 10s"
fi

# ── Parallel workers ─────────────────────────────────────────────────

info "parallel: 2 workers on the maze"
out=$(new_outdir parallel)
set +e
"$FATHOM" -i "$SEED_DIR" -o "$out" -t 1000 -T 15 -j 2 -s 7 \
    -- "$TARGETS/maze$EXE" 2>"$out/log"
rc=$?
set -e
missing=0
for w in worker-000 worker-001; do
    if [ ! -d "$out/$w/queue" ] || [ ! -d "$out/$w/crashes" ] || [ ! -f "$out/$w/fuzzer_stats" ]; then
        missing=1
    fi
done
orphans=0
if command -v pgrep >/dev/null 2>&1 && pgrep -f "$out" >/dev/null 2>&1; then
    orphans=1
fi
if [ "$rc" -ne 0 ]; then
    fail "parallel: fathom exited with status $rc"
    tail -5 "$out/log"
elif [ "$missing" -ne 0 ]; then
    fail "parallel: missing worker queue/crashes/stats"
elif [ "$orphans" -ne 0 ]; then
    fail "parallel: worker processes still running"
else
    w0=$(stat_of "$out/worker-000" execs)
    w1=$(stat_of "$out/worker-001" execs)
    ok "parallel: both workers ran ($w0 + $w1 execs)"
fi

info "parallel: the first crash stops every worker and is saved once"
out=$(new_outdir parallel-crash)
mkdir -p "$out/seeds"
printf 'AAAA' > "$out/seeds/a"
start=$SECONDS
set +e
"$FATHOM" -i "$out/seeds" -o "$out/run" -t 1000 -T 120 -j 2 -s 1 --until-crash \
    -- "$TARGETS/maze$EXE" 2>"$out/log"
rc=$?
set -e
took=$((SECONDS - start))
crashes=$(count_crashes "$out/run")
if [ "$rc" -ne 0 ]; then
    fail "parallel-crash: fathom exited with status $rc"
    tail -5 "$out/log"
elif [ "$crashes" -ne 1 ]; then
    fail "parallel-crash: $crashes crash files across workers, expected 1"
elif [ "$took" -ge 110 ]; then
    fail "parallel-crash: workers ran on to the time limit (${took}s)"
else
    ok "parallel-crash: stopped after ${took}s with one saved crash"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo
echo "========================================"
info "Results: $pass passed, $fail_count failed, $skip skipped"
echo "========================================"

[ "$fail_count" -eq 0 ]
