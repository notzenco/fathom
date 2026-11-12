/*
 * exec.h — Executor internals shared by the debugger backends
 *
 * exec.c owns the breakpoint table, coverage bookkeeping and crash
 * hashing.  Each backend (exec_posix.c for Linux and macOS,
 * exec_windows.c for Windows) launches the target under its OS debug
 * API and reports breakpoint hits and faults back through these hooks.
 *
 * Coverage model: before the target runs, every instrumented block
 * start is overwritten with a breakpoint instruction.  The first time a
 * block executes, the breakpoint fires, the backend marks the block's
 * coverage slot, restores the original bytes and resumes.  Each
 * breakpoint costs one trap per run, so the run then proceeds at native
 * speed.
 */

#ifndef FATHOM_EXEC_INTERNAL_H
#define FATHOM_EXEC_INTERNAL_H

#include "fathom.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#endif

#define FATHOM_DEFAULT_TIMEOUT_MS  1000
#define FATHOM_BP_INIT_CAP         64
#define FATHOM_STACK_HASH_DEPTH    8

#define FATHOM_FNV_OFFSET  0xcbf29ce484222325ULL
#define FATHOM_FNV_PRIME   0x100000001b3ULL

static inline uint64_t fathom_fnv_mix(uint64_t hash, uint64_t val)
{
    for (size_t i = 0; i < sizeof(val); i++) {
        hash ^= (uint8_t)(val >> (8 * i));
        hash *= FATHOM_FNV_PRIME;
    }
    return hash;
}

struct fathom_exec_os {
    /* Breakpoint address -> slot, open addressing (key 0 = empty). */
    uint64_t *hash_keys;
    uint32_t *hash_vals;
    size_t    hash_cap;

    /* Link-time span covering every breakpoint: [lo, hi). */
    uint64_t  lo, hi;
    uint8_t  *orig;          /* target bytes of [lo, hi) at launch */
    uint8_t  *patched;       /* the same with breakpoints written in */

    uint8_t   bp_insn[4];
    size_t    bp_len;
    /* How far past the breakpoint the PC is reported when it fires. */
    size_t    pc_adjust;

    uint64_t  slide;         /* runtime address - link-time address */

#ifdef _WIN32
    HANDLE    input;
    HANDLE    devnull;
    char     *cmdline;
#else
    int       input_fd;
#endif
};

/* Slot for link-time address addr, or -1. */
int exec_bp_lookup(const fathom_exec_t *ex, uint64_t addr);

/*
 * Handle a breakpoint trap at runtime address pc_bp (already adjusted
 * to the breakpoint's own address).  Marks coverage and tells the
 * caller which original bytes to write back.  Returns false if pc_bp is
 * not one of ours.
 */
bool exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                 const uint8_t **orig, size_t *len);

/*
 * Hash a crash from its PC and frame-pointer chain, using only addresses
 * inside the main image (at their link-time value), so the same bug
 * hashes the same way across runs.
 */
typedef bool (*exec_read_word_fn)(void *ctx, uint64_t addr, uint64_t *out);
uint64_t exec_crash_hash(const fathom_exec_t *ex, uint64_t pc, uint64_t fp,
                         exec_read_word_fn read_word, void *ctx);
uint64_t exec_link_addr(const fathom_exec_t *ex, uint64_t runtime);

/*
 * Fill os->patched from os->orig (just read from the target) with a
 * breakpoint at every instrumented address.
 */
void exec_build_patch(fathom_exec_t *ex);

/* Backend hooks. */
int  exec_os_init(fathom_exec_t *ex);
void exec_os_destroy(fathom_exec_t *ex);
int  exec_os_write_input(fathom_exec_t *ex, const uint8_t *data, size_t len);
int  exec_os_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                 fathom_exec_result_t *res);

#endif /* FATHOM_EXEC_INTERNAL_H */
