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
 *
 * Breakpoints are written in clusters: runs of breakpoints no more than
 * a page apart.  Two addresses within a page of each other lie on pages
 * that both hold a breakpoint, so a cluster never spans an unmapped
 * hole between sections, and the bytes between distant sections are
 * never copied.
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

    /* Breakpoint clusters, link-time [lo, hi), at off in orig/patched. */
    struct exec_cluster { uint64_t lo, hi; size_t off; } *clusters;
    size_t    n_clusters;
    uint8_t  *orig;          /* launch-time bytes of every cluster */
    uint8_t  *patched;       /* the same with breakpoints written in */
    size_t   *bp_off;        /* slot -> offset of its bytes in orig */

    /*
     * Hit counting (fathom_exec_count_hits): a counted block's breakpoint
     * is restored as usual, and a temporary one on the block's second
     * instruction ("follow") re-arms it once the first has run.
     */
    uint64_t *follow_addrs;
    uint32_t *follow_slot;   /* follow -> slot it re-arms */
    size_t   *follow_off;    /* follow -> offset of its bytes in orig */
    size_t    n_follow;
    uint32_t *bp_follow;     /* slot -> follow, or UINT32_MAX */
    size_t    bp_follow_len;
    /*
     * orig and patched were read at patch_slide.  Code bytes only change
     * with the load address, so they are reused while it stays the same.
     */
    bool      patch_ready;
    uint64_t  patch_slide;

    uint8_t   bp_insn[4];
    size_t    bp_len;
    /* How far past the breakpoint the PC is reported when it fires. */
    size_t    pc_adjust;

    uint64_t  slide;         /* runtime address - link-time address */
    /*
     * The target has exec'd a different program, so no address is in our
     * image any more: breakpoints and link-time crash PCs no longer apply.
     */
    bool      foreign_image;

#ifdef _WIN32
    HANDLE    input;
    HANDLE    devnull;
    HANDLE    job;           /* holds the target and everything it starts */
    char     *cmdline;
#else
    int       input_fd;
#endif
};

/* Slot for link-time address addr, or -1 (also for follow breakpoints). */
int exec_bp_lookup(const fathom_exec_t *ex, uint64_t addr);
/* Whether link-time address addr holds any of our breakpoints. */
bool exec_is_ours(const fathom_exec_t *ex, uint64_t addr);

/* A write into the target at a runtime address. */
typedef struct {
    uint64_t       addr;
    const uint8_t *bytes;
    size_t         len;
} exec_write_t;

/*
 * Handle a breakpoint trap at runtime address pc_bp (already adjusted
 * to the breakpoint's own address).  Marks coverage and fills w with
 * the writes to make before resuming at pc_bp: the original bytes back,
 * and for counted blocks the breakpoint that comes next.  Returns the
 * number of writes, or 0 if pc_bp is not one of ours, including a block
 * whose own first instruction is a trap: that one was never patched and
 * belongs to the target.
 */
size_t exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                   exec_write_t w[2]);

/*
 * Hash a crash from its PC and frame-pointer chain, so the same bug
 * hashes the same way across runs.  Main-image addresses count at their
 * link-time value; addresses in other modules count as the module's
 * stable key from module_key (path and offset), which the backend may
 * leave NULL.  Addresses in no module (input bytes after a stack smash)
 * are ignored.
 */
typedef bool (*exec_read_word_fn)(void *ctx, uint64_t addr, uint64_t *out);
typedef bool (*exec_module_key_fn)(void *ctx, uint64_t addr, uint64_t *key);
uint64_t exec_crash_hash(const fathom_exec_t *ex, uint64_t pc, uint64_t fp,
                         exec_read_word_fn read_word,
                         exec_module_key_fn module_key, void *ctx);
uint64_t exec_link_addr(const fathom_exec_t *ex, uint64_t runtime);

/* Key for a module-relative address: path hash mixed with the offset. */
uint64_t exec_module_key(const char *path, uint64_t offset);

/*
 * Write every breakpoint into the stopped target, reading the original
 * bytes first unless they are cached for the current slide.  Prints the
 * failing address and returns -1 on error.
 */
typedef bool (*exec_read_fn)(void *ctx, uint64_t addr, void *buf, size_t len);
typedef bool (*exec_write_fn)(void *ctx, uint64_t addr, const void *buf, size_t len);
int exec_insert_breakpoints(fathom_exec_t *ex, exec_read_fn rd, exec_write_fn wr,
                            void *ctx);

/* Backend hooks. */
int  exec_os_init(fathom_exec_t *ex);
void exec_os_destroy(fathom_exec_t *ex);
int  exec_os_write_input(fathom_exec_t *ex, const uint8_t *data, size_t len);
int  exec_os_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                 fathom_exec_result_t *res);

#endif /* FATHOM_EXEC_INTERNAL_H */
