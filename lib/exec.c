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

/* Copy of argv with every "@@" replaced by path, NULL-terminated. */
static char **substitute_input(char *const *argv, const char *path)
{
    size_t argc = 0;
    while (argv[argc])
        argc++;
    char **out = calloc(argc + 1, sizeof(*out));
    if (!out)
        return NULL;
    for (size_t i = 0; i < argc; i++) {
        size_t n = 0;
        for (const char *p = argv[i]; (p = strstr(p, "@@")); p += 2)
            n++;
        size_t len = strlen(argv[i]) + n * strlen(path) + 1;
        if (!(out[i] = malloc(len))) {
            for (size_t k = 0; k < i; k++)
                free(out[k]);
            free(out);
            return NULL;
        }
        char *d = out[i];
        for (const char *p = argv[i]; *p;) {
            if (p[0] == '@' && p[1] == '@') {
                memcpy(d, path, strlen(path));
                d += strlen(path);
                p += 2;
            } else {
                *d++ = *p++;
            }
        }
        *d = '\0';
    }
    return out;
}

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

    for (size_t i = 0; cfg->target_argv[i]; i++)
        os->input_by_path |= strstr(cfg->target_argv[i], "@@") != NULL;
    if (exec_os_init(ex) < 0)
        goto fail;
    if (os->input_by_path) {
        if (!(os->argv = substitute_input(cfg->target_argv, os->input_path)))
            goto fail;
        ex->target_argv = os->argv;
    }
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
        free(ex->os->follow_addrs);
        free(ex->os->follow_slot);
        free(ex->os->follow_off);
        free(ex->os->bp_follow);
        free(ex->os->disarmed);
        for (size_t i = 0; ex->os->argv && ex->os->argv[i]; i++)
            free(ex->os->argv[i]);
        free(ex->os->argv);
        free(ex->os);
    }
    free(ex->bp_addrs);
    memset(ex, 0, sizeof(*ex));
}

/* ── Breakpoints ────────────────────────────────────────────────────── */

#define FOLLOW_BIT  0x80000000u   /* hash value is a follow index, not a slot */

/* Hash value for addr, or false if there is none. */
static bool hash_get(const struct fathom_exec_os *os, uint64_t addr, uint32_t *val)
{
    if (addr == 0)
        return false;
    for (size_t i = hash_slot(addr, os->hash_cap);; i = (i + 1) & (os->hash_cap - 1)) {
        if (os->hash_keys[i] == addr) {
            *val = os->hash_vals[i];
            return true;
        }
        if (os->hash_keys[i] == 0)
            return false;
    }
}

static int hash_put(struct fathom_exec_os *os, size_t entries, uint64_t addr, uint32_t val)
{
    if ((entries + 1) * 2 > os->hash_cap && hash_grow(os) < 0)
        return -1;
    size_t i = hash_slot(addr, os->hash_cap);
    while (os->hash_keys[i] != 0)
        i = (i + 1) & (os->hash_cap - 1);
    os->hash_keys[i] = addr;
    os->hash_vals[i] = val;
    return 0;
}

int exec_bp_lookup(const fathom_exec_t *ex, uint64_t addr)
{
    uint32_t v;
    if (!hash_get(ex->os, addr, &v) || (v & FOLLOW_BIT))
        return -1;
    return (int)v;
}

bool exec_is_ours(const fathom_exec_t *ex, uint64_t addr)
{
    uint32_t v;
    return hash_get(ex->os, addr, &v);
}

/* Clusters and patch buffers are rebuilt on the next run. */
static void invalidate_patch(struct fathom_exec_os *os)
{
    free(os->clusters);
    free(os->orig);
    free(os->patched);
    free(os->bp_off);
    free(os->follow_off);
    os->clusters = NULL;
    os->orig = os->patched = NULL;
    os->bp_off = os->follow_off = NULL;
    os->n_clusters = 0;
    os->patch_ready = false;
    os->patch_stale = true;
}

int fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr)
{
    struct fathom_exec_os *os = ex->os;
    if (addr == 0)
        return -1;

    uint32_t v;
    if (hash_get(os, addr, &v))
        return v & FOLLOW_BIT ? -1 : (int)v;

    if (ex->bp_count >= ex->bp_capacity) {
        size_t cap = ex->bp_capacity * 2;
        uint64_t *p = realloc(ex->bp_addrs, cap * sizeof(*p));
        if (!p)
            return -1;
        ex->bp_addrs = p;
        ex->bp_capacity = cap;
    }

    if (hash_put(os, ex->bp_count + os->n_follow, addr, (uint32_t)ex->bp_count) < 0)
        return -1;
    int slot = (int)ex->bp_count++;
    ex->bp_addrs[slot] = addr;
    invalidate_patch(os);
    return slot;
}

void fathom_exec_arm(fathom_exec_t *ex, int slot, bool armed)
{
    struct fathom_exec_os *os = ex->os;
    if (slot < 0 || (size_t)slot >= ex->bp_count)
        return;
    if (os->disarmed_len < ex->bp_count) {
        bool *p = realloc(os->disarmed, ex->bp_count * sizeof(*p));
        if (!p)
            return;   /* stays armed: slower, never wrong */
        memset(p + os->disarmed_len, 0, (ex->bp_count - os->disarmed_len) * sizeof(*p));
        os->disarmed = p;
        os->disarmed_len = ex->bp_count;
    }
    if (os->disarmed[slot] != !armed) {
        os->disarmed[slot] = !armed;
        os->patch_stale = true;
    }
}

int fathom_exec_count_hits(fathom_exec_t *ex, int slot, uint64_t next_insn)
{
    struct fathom_exec_os *os = ex->os;
    uint32_t v;
    if (slot < 0 || (size_t)slot >= ex->bp_count || next_insn == 0 ||
        hash_get(os, next_insn, &v))
        return -1;   /* already a breakpoint of its own */

    if (os->bp_follow_len < ex->bp_count) {
        uint32_t *p = realloc(os->bp_follow, ex->bp_count * sizeof(*p));
        if (!p)
            return -1;
        for (size_t i = os->bp_follow_len; i < ex->bp_count; i++)
            p[i] = UINT32_MAX;
        os->bp_follow = p;
        os->bp_follow_len = ex->bp_count;
    }
    if (os->bp_follow[slot] != UINT32_MAX)
        return 0;

    size_t k = os->n_follow;
    uint64_t *a = realloc(os->follow_addrs, (k + 1) * sizeof(*a));
    if (a)
        os->follow_addrs = a;
    uint32_t *f = realloc(os->follow_slot, (k + 1) * sizeof(*f));
    if (f)
        os->follow_slot = f;
    if (!a || !f || hash_put(os, ex->bp_count + k, next_insn, FOLLOW_BIT | (uint32_t)k) < 0)
        return -1;
    os->follow_addrs[k] = next_insn;
    os->follow_slot[k] = (uint32_t)slot;
    os->bp_follow[slot] = (uint32_t)k;
    os->n_follow++;
    invalidate_patch(os);
    return 0;
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

/* Cluster every breakpoint address: slots first, then follows. */
static int build_clusters(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    size_t nb = ex->bp_count, n = nb + os->n_follow;
    uint64_t *addrs = malloc(n * sizeof(*addrs));
    uint32_t *order = malloc(n * sizeof(*order));
    os->clusters = malloc(n * sizeof(*os->clusters));
    os->bp_off = malloc(nb * sizeof(*os->bp_off));
    os->follow_off = malloc((os->n_follow ? os->n_follow : 1) * sizeof(*os->follow_off));
    if (!addrs || !order || !os->clusters || !os->bp_off || !os->follow_off) {
        free(addrs);
        free(order);
        return -1;
    }
    memcpy(addrs, ex->bp_addrs, nb * sizeof(*addrs));
    if (os->n_follow)
        memcpy(addrs + nb, os->follow_addrs, os->n_follow * sizeof(*addrs));
    for (size_t i = 0; i < n; i++)
        order[i] = (uint32_t)i;
    g_sort_addrs = addrs;
    qsort(order, n, sizeof(*order), cmp_slot_addr);
    g_sort_addrs = NULL;

    size_t total = 0;
    struct exec_cluster *c = NULL;
    uint64_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t addr = addrs[order[i]];
        if (!c || addr - prev > CLUSTER_GAP) {
            if (c)
                total += (size_t)(c->hi - c->lo);
            c = &os->clusters[os->n_clusters++];
            c->lo = c->hi = addr;
            c->off = total;
        }
        if (addr + os->bp_len > c->hi)
            c->hi = addr + os->bp_len;
        size_t off = c->off + (size_t)(addr - c->lo);
        if (order[i] < nb)
            os->bp_off[order[i]] = off;
        else
            os->follow_off[order[i] - nb] = off;
        prev = addr;
    }
    total += (size_t)(c->hi - c->lo);
    free(order);
    free(addrs);

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
        os->patch_ready = true;
        os->patch_slide = os->slide;
        os->patch_stale = true;
    }
    if (os->patch_stale) {
        const struct exec_cluster *last = &os->clusters[os->n_clusters - 1];
        memcpy(os->patched, os->orig, last->off + (size_t)(last->hi - last->lo));
        for (size_t i = 0; i < ex->bp_count; i++) {
            bool off = i < os->disarmed_len && os->disarmed[i];
            if (!off && !is_trap(os, os->bp_off[i]))
                memcpy(os->patched + os->bp_off[i], os->bp_insn, os->bp_len);
        }
        os->patch_stale = false;
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

size_t exec_bp_hit(fathom_exec_t *ex, fathom_coverage_t *cov, uint64_t pc_bp,
                   exec_write_t w[2])
{
    struct fathom_exec_os *os = ex->os;
    uint64_t addr = pc_bp - os->slide;
    uint32_t v;
    if (os->foreign_image || !os->patch_ready || !hash_get(os, addr, &v))
        return 0;

    if (v & FOLLOW_BIT) {
        /* The counted block's first instruction has run: re-arm it. */
        uint32_t k = v & ~FOLLOW_BIT, slot = os->follow_slot[k];
        w[0] = (exec_write_t){ pc_bp, os->orig + os->follow_off[k], os->bp_len };
        w[1] = (exec_write_t){ ex->bp_addrs[slot] + os->slide, os->bp_insn, os->bp_len };
        return 2;
    }

    if (is_trap(os, os->bp_off[v]))
        return 0;
    uint8_t hits = 1;
    if (cov && v < cov->size) {
        if (cov->local[v] < 255)
            cov->local[v]++;
        hits = cov->local[v];
    }
    w[0] = (exec_write_t){ pc_bp, os->orig + os->bp_off[v], os->bp_len };

    uint32_t k = v < os->bp_follow_len ? os->bp_follow[v] : UINT32_MAX;
    if (k != UINT32_MAX && hits < FATHOM_HIT_LIMIT && !is_trap(os, os->follow_off[k])) {
        w[1] = (exec_write_t){ os->follow_addrs[k] + os->slide, os->bp_insn, os->bp_len };
        return 2;
    }
    return 1;
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
