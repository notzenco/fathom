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

#define HASH_INIT_CAP  4096   /* power of two; doubles to keep load <= 0.5 */

static size_t hash_slot(uint64_t addr, size_t cap)
{
    return (size_t)((addr * 0x9E3779B97F4A7C15ULL) >> 32) & (cap - 1);
}

static int hash_grow(struct fathom_exec_os *os)
{
    size_t cap = os->hash_cap * 2;
    uint64_t *keys = calloc(cap, sizeof(*keys));
    uint32_t *vals = calloc(cap, sizeof(*vals));
    if (!keys || !vals) {
        free(keys);
        free(vals);
        return -1;
    }
    for (size_t i = 0; i < os->hash_cap; i++) {
        if (!os->hash_keys[i])
            continue;
        size_t j = hash_slot(os->hash_keys[i], cap);
        while (keys[j])
            j = (j + 1) & (cap - 1);
        keys[j] = os->hash_keys[i];
        vals[j] = os->hash_vals[i];
    }
    free(os->hash_keys);
    free(os->hash_vals);
    os->hash_keys = keys;
    os->hash_vals = vals;
    os->hash_cap  = cap;
    return 0;
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
    os->hash_cap  = HASH_INIT_CAP;
    os->hash_keys = calloc(HASH_INIT_CAP, sizeof(*os->hash_keys));
    os->hash_vals = calloc(HASH_INIT_CAP, sizeof(*os->hash_vals));
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
        free(ex->os->clusters);
        free(ex->os->orig);
        free(ex->os->patched);
        free(ex->os->bp_off);
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
    for (size_t i = hash_slot(addr, os->hash_cap);; i = (i + 1) & (os->hash_cap - 1)) {
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

    int existing = exec_bp_lookup(ex, addr);
    if (existing >= 0)
        return existing;
    if ((ex->bp_count + 1) * 2 > os->hash_cap && hash_grow(os) < 0)
        return -1;

    size_t i = hash_slot(addr, os->hash_cap);
    while (os->hash_keys[i] != 0)
        i = (i + 1) & (os->hash_cap - 1);

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

    /* Clusters and patch buffers are rebuilt on the next run. */
    free(os->clusters);
    free(os->orig);
    free(os->patched);
    free(os->bp_off);
    os->clusters = NULL;
    os->orig = os->patched = NULL;
    os->bp_off = NULL;
    os->n_clusters = 0;
    os->patch_ready = false;
    return slot;
}

/* ── Patching ───────────────────────────────────────────────────────── */

#define CLUSTER_GAP  4096   /* see the cluster note in exec.h */

static const uint64_t *g_sort_addrs;   /* qsort has no context argument */

static int cmp_slot_addr(const void *a, const void *b)
{
    uint64_t x = g_sort_addrs[*(const uint32_t *)a];
    uint64_t y = g_sort_addrs[*(const uint32_t *)b];
    return (x > y) - (x < y);
}

static int build_clusters(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    size_t n = ex->bp_count;
    uint32_t *order = malloc(n * sizeof(*order));
    os->clusters = malloc(n * sizeof(*os->clusters));
    os->bp_off = malloc(n * sizeof(*os->bp_off));
    if (!order || !os->clusters || !os->bp_off) {
        free(order);
        return -1;
    }
    for (size_t i = 0; i < n; i++)
        order[i] = (uint32_t)i;
    g_sort_addrs = ex->bp_addrs;
    qsort(order, n, sizeof(*order), cmp_slot_addr);
    g_sort_addrs = NULL;

    size_t total = 0;
    struct exec_cluster *c = NULL;
    uint64_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t addr = ex->bp_addrs[order[i]];
        if (!c || addr - prev > CLUSTER_GAP) {
            if (c)
                total += (size_t)(c->hi - c->lo);
            c = &os->clusters[os->n_clusters++];
            c->lo = addr;
            c->off = total;
        }
        c->hi = addr + os->bp_len;
        os->bp_off[order[i]] = c->off + (size_t)(addr - c->lo);
        prev = addr;
    }
    total += (size_t)(c->hi - c->lo);
    free(order);

    os->orig = malloc(total);
    os->patched = malloc(total);
    return os->orig && os->patched ? 0 : -1;
}

static bool is_trap(const struct fathom_exec_os *os, size_t off)
{
    return memcmp(os->orig + off, os->bp_insn, os->bp_len) == 0;
}

int exec_insert_breakpoints(fathom_exec_t *ex, exec_read_fn rd, exec_write_fn wr,
                            void *ctx)
{
    struct fathom_exec_os *os = ex->os;
    if (ex->bp_count == 0)
        return 0;
    if (!os->clusters && build_clusters(ex) < 0) {
        fprintf(stderr, "fathom: out of memory for breakpoints\n");
        return -1;
    }

    if (!os->patch_ready || os->patch_slide != os->slide) {
        os->patch_ready = false;
        for (size_t i = 0; i < os->n_clusters; i++) {
            const struct exec_cluster *c = &os->clusters[i];
            if (!rd(ctx, c->lo + os->slide, os->orig + c->off, (size_t)(c->hi - c->lo))) {
                fprintf(stderr, "fathom: cannot read target code at 0x%llx\n",
                        (unsigned long long)(c->lo + os->slide));
                return -1;
            }
        }
        const struct exec_cluster *last = &os->clusters[os->n_clusters - 1];
        memcpy(os->patched, os->orig, last->off + (size_t)(last->hi - last->lo));
        for (size_t i = 0; i < ex->bp_count; i++) {
            if (!is_trap(os, os->bp_off[i]))
                memcpy(os->patched + os->bp_off[i], os->bp_insn, os->bp_len);
        }
        os->patch_ready = true;
        os->patch_slide = os->slide;
    }

    for (size_t i = 0; i < os->n_clusters; i++) {
        const struct exec_cluster *c = &os->clusters[i];
        if (!wr(ctx, c->lo + os->slide, os->patched + c->off, (size_t)(c->hi - c->lo))) {
            fprintf(stderr, "fathom: cannot write breakpoints at 0x%llx\n",
                    (unsigned long long)(c->lo + os->slide));
            return -1;
        }
    }
    return 0;
}

bool exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                 const uint8_t **orig, size_t *len)
{
    struct fathom_exec_os *os = ex->os;
    uint64_t addr = pc_bp - os->slide;
    int slot = os->foreign_image ? -1 : exec_bp_lookup(ex, addr);
    if (slot < 0 || !os->patch_ready || is_trap(os, os->bp_off[slot]))
        return false;

    if (cov && (size_t)slot < cov->size)
        cov->local[slot] = 1;   /* one-shot: a block counts once per run */
    *orig = os->orig + os->bp_off[slot];
    *len  = os->bp_len;
    return true;
}

/* ── Crash hashing ──────────────────────────────────────────────────── */

uint64_t exec_link_addr(const fathom_exec_t *ex, uint64_t runtime)
{
    uint64_t base = ex->image_base + ex->os->slide;
    if (!ex->os->foreign_image && runtime >= base && runtime - base < ex->image_size)
        return runtime - ex->os->slide;
    return 0;
}

uint64_t exec_module_key(const char *path, uint64_t offset)
{
    uint64_t h = FATHOM_FNV_OFFSET;
    for (const char *p = path; *p; p++) {
        h ^= (uint8_t)*p;
        h *= FATHOM_FNV_PRIME;
    }
    return fathom_fnv_mix(h, offset) | 1;   /* never 0, which means "no module" */
}

/*
 * Main-image addresses count at their link-time value and library ones
 * by module and offset, since both move with ASLR.  After a stack smash
 * the PC and return addresses are input bytes that lie in no module;
 * hashing those would split one bug into many "unique" crashes.
 */
static uint64_t stable_addr(const fathom_exec_t *ex, uint64_t addr,
                            exec_module_key_fn module_key, void *ctx)
{
    uint64_t key = exec_link_addr(ex, addr);
    if (!key && module_key && !module_key(ctx, addr, &key))
        key = 0;
    return key;
}

uint64_t exec_crash_hash(const fathom_exec_t *ex, uint64_t pc, uint64_t fp,
                         exec_read_word_fn read_word,
                         exec_module_key_fn module_key, void *ctx)
{
    uint64_t hash = fathom_fnv_mix(FATHOM_FNV_OFFSET,
                                   stable_addr(ex, pc, module_key, ctx));

    /* Walk saved frame pointers: [fp] = caller's fp, [fp+8] = return address. */
    for (int depth = 0; depth < FATHOM_STACK_HASH_DEPTH; depth++) {
        uint64_t ret, next;
        if (fp == 0 || (fp & 7) != 0)
            break;
        if (!read_word(ctx, fp + 8, &ret) || !read_word(ctx, fp, &next))
            break;
        uint64_t key = stable_addr(ex, ret, module_key, ctx);
        if (key)
            hash = fathom_fnv_mix(hash, key);
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
    memset(result, 0, sizeof(*result));
    if (cov)
        fathom_coverage_reset_local(cov);

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
