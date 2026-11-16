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
    bool      patch_stale;   /* patched needs rebuilding from orig (arming changed) */
    uint64_t  patch_gen;     /* bumped whenever patched changes */
    bool     *disarmed;      /* slot -> left out of the patch */
    size_t    disarmed_len;

    /*
     * Comparison probes: one-shot breakpoints on compare sites, armed
     * only for a comparison-logging run.  A site on a block start shares
     * that slot's breakpoint (slot_probe); others have their own.
     */
    fathom_cmp_site_t  *probes;
    size_t             *probe_off;      /* own breakpoints: offset in orig */
    bool               *probe_own;
    size_t              n_probes;
    uint32_t           *slot_probe;     /* slot -> probe, or UINT32_MAX */
    size_t              slot_probe_len;
    bool                probes_armed;
    fathom_cmp_entry_t *cmp_log;
    size_t              cmp_count;

    uint8_t   bp_insn[4];
    size_t    bp_len;
    /* How far past the breakpoint the PC is reported when it fires. */
    size_t    pc_adjust;

    uint64_t  slide;         /* runtime address - link-time address */

    /*
     * Input by path: target_argv contains "@@", so the backend keeps the
     * input file at input_path (stdin is then empty) and argv is a copy
     * with "@@" replaced by that path.
     */
    bool      input_by_path;
    char      input_path[1100];
    char    **argv;
    /*
     * The target has exec'd a different program, so no address is in our
     * image any more: breakpoints and link-time crash PCs no longer apply.
     */
    bool      foreign_image;

#if defined(__linux__)
    /* Fork server: the stopped template every run is forked from. */
    bool      fs_wanted;
    bool      fs_failed;
    pid_t     fs_pid;
    int       fs_mem;
    uint64_t  fs_entry;          /* runtime entry point, where code is injected */
    uint64_t  fs_patch_gen;      /* patch generation last written to the template */
    unsigned char fs_regs[1024]; /* registers at the entry point (user_regs_struct) */
#endif

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

typedef bool (*exec_read_fn)(void *ctx, uint64_t addr, void *buf, size_t len);

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
 * belongs to the target.  *probe is a comparison probe to log with
 * exec_probe_log (the stopped thread's registers are needed), or
 * UINT32_MAX.
 */
size_t exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                   exec_write_t w[2], uint32_t *probe);

/* Registers of a stopped thread, numbered as FATHOM_REG_* describes. */
typedef struct {
    uint64_t r[FATHOM_REG_COUNT];
} exec_regs_t;

/* Record what probe's comparison sees, reading memory through rd. */
void exec_probe_log(fathom_exec_t *ex, uint32_t probe, const exec_regs_t *regs,
                    exec_read_fn rd, void *ctx);

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
