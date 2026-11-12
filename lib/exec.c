/*
 * exec.c — Target executor: platform-neutral half
 *
 * Breakpoint table, coverage marking and crash hashing.  Launching the
 * target and talking to the OS debugger lives in exec_posix.c and
 * exec_windows.c; see exec.h for the coverage model.
 */

#include "exec.h"
#include "osdep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_CAP  (2 * FATHOM_MAP_SIZE)   /* load factor <= 0.5 */

static size_t hash_slot(uint64_t addr)
{
    return (size_t)((addr * 0x9E3779B97F4A7C15ULL) >> 47) & (HASH_CAP - 1);
}

/* ── Init / Destroy ─────────────────────────────────────────────────── */

int fathom_exec_init(fathom_exec_t *ex, const fathom_config_t *cfg,
                     const fathom_binary_t *bin)
{
    memset(ex, 0, sizeof(*ex));

    if (bin->arch != fathom_host_arch()) {
        fprintf(stderr, "fathom: cannot run a %s target on a %s host "
                        "(emulated targets are not supported)\n",
                fathom_arch_name(bin->arch), fathom_arch_name(fathom_host_arch()));
        return -1;
    }
#if defined(_WIN32)
    bool native = bin->format == FATHOM_FMT_PE;
#elif defined(__APPLE__)
    bool native = bin->format == FATHOM_FMT_MACHO;
#else
    bool native = bin->format == FATHOM_FMT_ELF;
#endif
    if (!native) {
        fprintf(stderr, "fathom: %s executables cannot run on this OS "
                        "(analysis mode -a still works)\n",
                fathom_format_name(bin->format));
        return -1;
    }

    ex->target_path = cfg->target_path;
    ex->target_argv = cfg->target_argv;
    ex->timeout_ms  = cfg->timeout_ms ? cfg->timeout_ms : FATHOM_DEFAULT_TIMEOUT_MS;
    ex->arch        = bin->arch;
    ex->entry       = bin->entry;
    ex->image_base  = bin->image_base;
    ex->image_size  = bin->image_size;

    ex->os = calloc(1, sizeof(*ex->os));
    ex->bp_capacity = FATHOM_BP_INIT_CAP;
    ex->bp_addrs = calloc(ex->bp_capacity, sizeof(*ex->bp_addrs));
    if (!ex->os || !ex->bp_addrs)
        goto fail;

    struct fathom_exec_os *os = ex->os;
    os->hash_cap  = HASH_CAP;
    os->hash_keys = calloc(HASH_CAP, sizeof(*os->hash_keys));
    os->hash_vals = calloc(HASH_CAP, sizeof(*os->hash_vals));
    if (!os->hash_keys || !os->hash_vals)
        goto fail;

    if (ex->arch == FATHOM_ARCH_ARM64) {
#ifdef _WIN32
        uint32_t brk = 0xd43e0000;   /* brk #0xf000: the Windows debugger break */
#else
        uint32_t brk = 0xd4200000;   /* brk #0 */
#endif
        memcpy(os->bp_insn, &brk, 4);
        os->bp_len = 4;
        os->pc_adjust = 0;           /* PC stays on the brk */
    } else {
        os->bp_insn[0] = 0xcc;       /* int3 */
        os->bp_len = 1;
        os->pc_adjust = 1;           /* PC is reported after the int3 */
    }

    if (exec_os_init(ex) < 0)
        goto fail;
    return 0;

fail:
    fathom_exec_destroy(ex);
    return -1;
}

void fathom_exec_destroy(fathom_exec_t *ex)
{
    if (ex->os) {
        exec_os_destroy(ex);
        free(ex->os->hash_keys);
        free(ex->os->hash_vals);
        free(ex->os->orig);
        free(ex->os->patched);
        free(ex->os);
    }
    free(ex->bp_addrs);
    memset(ex, 0, sizeof(*ex));
}

/* ── Breakpoints ────────────────────────────────────────────────────── */

int exec_bp_lookup(const fathom_exec_t *ex, uint64_t addr)
{
    const struct fathom_exec_os *os = ex->os;
    if (addr == 0)
        return -1;
    for (size_t i = hash_slot(addr);; i = (i + 1) & (HASH_CAP - 1)) {
        if (os->hash_keys[i] == addr)
            return (int)os->hash_vals[i];
        if (os->hash_keys[i] == 0)
            return -1;
    }
}

int fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr)
{
    struct fathom_exec_os *os = ex->os;
    if (addr == 0)
        return -1;

    size_t i = hash_slot(addr);
    for (; os->hash_keys[i] != 0; i = (i + 1) & (HASH_CAP - 1)) {
        if (os->hash_keys[i] == addr)
            return (int)os->hash_vals[i];
    }
    if (ex->bp_count >= FATHOM_MAP_SIZE)
        return -1;

    if (ex->bp_count >= ex->bp_capacity) {
        size_t cap = ex->bp_capacity * 2;
        uint64_t *p = realloc(ex->bp_addrs, cap * sizeof(*p));
        if (!p)
            return -1;
        ex->bp_addrs = p;
        ex->bp_capacity = cap;
    }

    int slot = (int)ex->bp_count++;
    ex->bp_addrs[slot] = addr;
    os->hash_keys[i] = addr;
    os->hash_vals[i] = (uint32_t)slot;

    if (slot == 0 || addr < os->lo)
        os->lo = addr;
    if (slot == 0 || addr + os->bp_len > os->hi)
        os->hi = addr + os->bp_len;

    /* The patch buffers are rebuilt for the new span on the next run. */
    free(os->orig);
    free(os->patched);
    os->orig = os->patched = NULL;
    return slot;
}

bool exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                 const uint8_t **orig, size_t *len)
{
    struct fathom_exec_os *os = ex->os;
    uint64_t addr = pc_bp - os->slide;
    int slot = exec_bp_lookup(ex, addr);
    if (slot < 0 || !os->orig)
        return false;

    if (cov)
        cov->local[slot] = 1;   /* one-shot: a block counts once per run */
    *orig = os->orig + (addr - os->lo);
    *len  = os->bp_len;
    return true;
}

/* ── Crash hashing ──────────────────────────────────────────────────── */

uint64_t exec_link_addr(const fathom_exec_t *ex, uint64_t runtime)
{
    uint64_t base = ex->image_base + ex->os->slide;
    if (runtime >= base && runtime - base < ex->image_size)
        return runtime - ex->os->slide;
    return 0;
}

uint64_t exec_crash_hash(const fathom_exec_t *ex, uint64_t pc, uint64_t fp,
                         exec_read_word_fn read_word, void *ctx)
{
    /*
     * Only addresses inside the main image are hashed, at their link-time
     * value.  Library addresses move with ASLR, and after a stack smash
     * the PC and return addresses are input bytes, so hashing either
     * would split one bug into many "unique" crashes.
     */
    uint64_t hash = fathom_fnv_mix(FATHOM_FNV_OFFSET, exec_link_addr(ex, pc));

    /* Walk saved frame pointers: [fp] = caller's fp, [fp+8] = return address. */
    for (int depth = 0; depth < FATHOM_STACK_HASH_DEPTH; depth++) {
        uint64_t ret, next;
        if (fp == 0 || (fp & 7) != 0)
            break;
        if (!read_word(ctx, fp + 8, &ret) || !read_word(ctx, fp, &next))
            break;
        uint64_t link = exec_link_addr(ex, ret);
        if (link)
            hash = fathom_fnv_mix(hash, link);
        if (next <= fp)
            break;
        fp = next;
    }
    return hash;
}

/* ── Execution ──────────────────────────────────────────────────────── */

int fathom_exec_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                    const uint8_t *input, size_t input_len,
                    fathom_exec_result_t *result)
{
    struct fathom_exec_os *os = ex->os;
    memset(result, 0, sizeof(*result));
    if (cov)
        fathom_coverage_reset_local(cov);

    if (ex->bp_count > 0 && !os->orig) {
        size_t span = (size_t)(os->hi - os->lo);
        os->orig = malloc(span);
        os->patched = malloc(span);
        if (!os->orig || !os->patched) {
            result->status = FATHOM_EXIT_ERROR;
            return -1;
        }
    }

    if (exec_os_write_input(ex, input, input_len) < 0) {
        result->status = FATHOM_EXIT_ERROR;
        return -1;
    }

    uint64_t start = fathom_now_us();
    int rc = exec_os_run(ex, cov, result);
    result->exec_us = fathom_now_us() - start;

    if (rc < 0)
        result->status = FATHOM_EXIT_ERROR;
    return rc;
}

void exec_build_patch(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    memcpy(os->patched, os->orig, (size_t)(os->hi - os->lo));
    for (size_t i = 0; i < ex->bp_count; i++)
        memcpy(os->patched + (ex->bp_addrs[i] - os->lo), os->bp_insn, os->bp_len);
}
