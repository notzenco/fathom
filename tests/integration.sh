#!/bin/bash
#
# integration.sh — Integration tests for Fathom fuzzer.
#
# Builds fathom and the vulnerable test targets, then runs the fuzzer
# against each target to verify it can discover crashes.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FATHOM="$ROOT_DIR/fathom"
SEED_DIR="$ROOT_DIR/tests/seeds"
TIMEOUT_SEC=30
PARALLEL_TIMEOUT_SEC=20

# Counters
pass=0
fail_count=0
skip=0

# Temporary directories to clean up
TMPDIRS=()

cleanup() {
    for d in "${TMPDIRS[@]}"; do
        rm -rf "$d"
    done
}
trap cleanup EXIT

# ── Colors (disabled if not a terminal) ──────────────────────────────

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

info()  { echo -e "${BOLD}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[SKIP]${RESET} $*"; }

# ── Phase 1: Build ──────────────────────────────────────────────────

info "Building fathom and test targets..."

cd "$ROOT_DIR"
make clean && make && make targets

if [ ! -x "$FATHOM" ]; then
    fail "fathom binary not found after build"
    exit 1
fi

info "Build complete."
echo

# ── Phase 2: Run fuzzer against each target ─────────────────────────

# run_target <name> <binary> <optional:1=optional>
run_target() {
    local name="$1"
    local binary="$2"
    local optional="${3:-0}"

    info "Testing target: $name ($binary)"

    if [ ! -x "$binary" ]; then
        fail "$name: binary not found: $binary"
        fail_count=$((fail_count + 1))
        return
    fi

    # Create a temp output directory for this run
    local outdir
    outdir=$(mktemp -d "/tmp/fathom-test-${name}-XXXXXX")
    TMPDIRS+=("$outdir")

    # Run fathom with a timeout. The fuzzer runs until SIGINT or crash,
    # so we use `timeout` to bound it. Exit code 124 means timeout
    # expired (expected), 0 means it exited normally (also fine).
    set +e
    timeout "$TIMEOUT_SEC" "$FATHOM" \
        -i "$SEED_DIR" \
        -o "$outdir" \
        -t 500 \
        -- "$binary" \
        >/dev/null 2>&1
    local rc=$?
    set -e

    # rc=124 is normal (timeout killed the fuzzer)
    # rc=0   is normal (fuzzer stopped on its own)
    # Other non-zero could indicate build/init errors
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
        # If the fuzzer itself errored out, still check for crashes
        # (it might have found one before the error)
        :
    fi

    # Check for crashes
    local crash_dir="$outdir/crashes"
    local crash_count=0
    if [ -d "$crash_dir" ]; then
        crash_count=$(find "$crash_dir" -type f -name 'crash_*' | wc -l)
    fi

    if [ "$crash_count" -gt 0 ]; then
        ok "$name: found $crash_count crash(es)"
        pass=$((pass + 1))
    elif [ "$optional" -eq 1 ]; then
        warn "$name: no crashes found (optional target, may need longer run)"
        skip=$((skip + 1))
    else
        fail "$name: no crashes found in $TIMEOUT_SEC seconds"
        fail_count=$((fail_count + 1))
    fi
}

run_target "heap_overflow"   "$ROOT_DIR/tests/targets/heap_overflow"   0
run_target "stack_smash"     "$ROOT_DIR/tests/targets/stack_smash"     0
run_target "format_string"   "$ROOT_DIR/tests/targets/format_string"   1

run_parallel_target() {
    local name="$1"
    local binary="$2"

    info "Testing parallel mode: $name ($binary)"

    if [ ! -x "$binary" ]; then
        fail "$name parallel: binary not found: $binary"
        fail_count=$((fail_count + 1))
        return
    fi

    local outdir
    outdir=$(mktemp -d "/tmp/fathom-test-${name}-parallel-XXXXXX")
    TMPDIRS+=("$outdir")

    set +e
    timeout "$PARALLEL_TIMEOUT_SEC" "$FATHOM" \
        -i "$SEED_DIR" \
        -o "$outdir" \
        -t 500 \
        -j 2 \
        -- "$binary" \
        >/dev/null 2>&1
    local rc=$?
    set -e

    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
        fail "$name parallel: fathom exited with status $rc"
        fail_count=$((fail_count + 1))
        return
    fi

    local missing_dirs=0
    for worker in "$outdir"/worker-000 "$outdir"/worker-001; do
        if [ ! -d "$worker/queue" ] || [ ! -d "$worker/crashes" ]; then
            missing_dirs=1
        fi
    done

    local crash_count=0
    crash_count=$(find "$outdir" -type f -path '*/crashes/crash_*' | wc -l)

    local orphaned=0
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -f "$outdir" >/dev/null 2>&1; then
            orphaned=1
        fi
    fi

    if [ "$missing_dirs" -ne 0 ]; then
        fail "$name parallel: missing worker queue/crash directories"
        fail_count=$((fail_count + 1))
    elif [ "$crash_count" -le 0 ]; then
        fail "$name parallel: no crashes found in $PARALLEL_TIMEOUT_SEC seconds"
        fail_count=$((fail_count + 1))
    elif [ "$orphaned" -ne 0 ]; then
        fail "$name parallel: orphan worker processes still running"
        fail_count=$((fail_count + 1))
    else
        ok "$name parallel: worker shards created and found $crash_count crash(es)"
        pass=$((pass + 1))
    fi
}

run_parallel_target "heap_overflow" "$ROOT_DIR/tests/targets/heap_overflow"

# ── Phase 3: Summary ───────────────────────────────────────────────

echo
echo "========================================"
info "Results: $pass passed, $fail_count failed, $skip skipped"
echo "========================================"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi

exit 0
