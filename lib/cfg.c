/*
 * cfg.c — Control flow graph builder
 *
 * Takes a disassembled instruction stream (fathom_disasm_t) and produces
 * a control flow graph of basic blocks with edges, back-edge detection,
 * and a dominator tree.
 */

#include "cfg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Internal helpers ────────────────────────────────────────────────── */

/*
 * Binary search for a block by start address.
 * Blocks are sorted by start_addr (they inherit instruction order).
 */
static uint32_t find_block_by_addr(const fathom_cfg_t *cfg, uint64_t addr)
{
    size_t lo = 0, hi = cfg->block_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cfg->blocks[mid].start_addr < addr)
            lo = mid + 1;
        else if (cfg->blocks[mid].start_addr > addr)
            hi = mid;
        else
            return (uint32_t)mid;
    }
    return (uint32_t)-1;
}

static bool contiguous(const fathom_disasm_t *dis, size_t a, size_t b)
{
    return dis->insns[a].addr + dis->insns[a].size == dis->insns[b].addr;
}

static bool is_padding(const fathom_insn_t *insn)
{
    return strcmp(insn->mnemonic, "nop") == 0 || strcmp(insn->mnemonic, "int3") == 0;
}

/* ── Step 0: Jump tables ─────────────────────────────────────────────── */

/*
 * A switch compiles to an indirect jump through a table of targets.
 * The shapes recognised, in the few instructions before the jump:
 *
 *   x86-64, PIC     lea T; movsxd r, [T + i*4]; add r, T; jmp r
 *                   (int32 entries relative to T)
 *   x86-64, no-PIE  jmp [T + i*8]                 (absolute entries)
 *   arm64           adrp+add T; ldr{b,h,,sb,sh,sw} e, [T, i];
 *                   adr L; add r, L, e, lsl #2; br r
 *                   (entries are instruction counts from L)
 *
 * The entry count comes from the bounds check (`cmp i, #N`) just before.
 * Every target must be a decoded instruction; entries are read up to the
 * bound, or until the first that is not, and at least two are needed.
 */
#define JT_LOOKBACK   12     /* instructions before the jump holding the table setup */
#define JT_BOUND_BACK 24     /* instructions before the jump to find the bounds check */
#define JT_MAX        1024   /* entries read from one table */

typedef struct {
    size_t    insn;          /* index of the indirect jump */
    uint64_t *targets;
    size_t    n;
} jtab_t;

typedef struct {
    jtab_t *v;
    size_t  n;
    size_t  total;           /* targets over all tables */
} jtabs_t;

static bool read_va(const fathom_binary_t *bin, uint64_t addr, void *out, size_t n)
{
    for (size_t i = 0; i < bin->section_count; i++) {
        const fathom_section_t *s = &bin->sections[i];
        if (addr >= s->addr && addr - s->addr <= s->size && n <= s->size - (addr - s->addr) &&
            s->offset + (addr - s->addr) + n <= bin->image_len) {
            memcpy(out, bin->image + s->offset + (addr - s->addr), n);
            return true;
        }
    }
    return false;
}

static int64_t read_entry(const uint8_t *p, size_t width, bool sign)
{
    uint64_t v = 0;
    for (size_t i = 0; i < width; i++)
        v |= (uint64_t)p[i] << (8 * i);
    if (sign && width < 8 && (v >> (8 * width - 1)) & 1)
        v |= ~0ULL << (8 * width);
    return (int64_t)v;
}

static bool has_prefix(const char *s, const char *p)
{
    return strncmp(s, p, strlen(p)) == 0;
}

/* Read up to max entries; returns how many lead to decoded instructions. */
static size_t read_table(const fathom_disasm_t *dis, const fathom_binary_t *bin,
                         uint64_t table, size_t width, bool sign, uint64_t base,
                         unsigned shift, bool absolute, size_t max, uint64_t *out)
{
    size_t n = 0;
    for (; n < max; n++) {
        uint8_t raw[8];
        if (!read_va(bin, table + n * width, raw, width))
            break;
        int64_t e = read_entry(raw, width, sign);
        uint64_t t = absolute ? (uint64_t)e : base + (uint64_t)(e * ((int64_t)1 << shift));
        if (fathom_disasm_find(dis, t) == (size_t)-1)
            break;
        out[n] = t;
    }
    return n;
}

static size_t decode_table(const fathom_disasm_t *dis, const fathom_binary_t *bin,
                           size_t j, uint64_t *out)
{
    const fathom_insn_t *jmp = &dis->insns[j];
    size_t max = JT_MAX;
    for (size_t k = 1; k <= JT_BOUND_BACK && k <= j; k++) {
        const fathom_insn_t *c = &dis->insns[j - k];
        if (c->has_cmp_imm && strcmp(c->mnemonic, "cmp") == 0) {
            if (c->cmp_imm >= 1 && c->cmp_imm < JT_MAX)
                max = (size_t)c->cmp_imm + 1;
            break;
        }
    }

    if (jmp->jt_table)
        return read_table(dis, bin, jmp->jt_table, 8, false, 0, 0, true, max, out);

    uint64_t table = 0, label = 0;
    const char *load = NULL;
    for (size_t k = 1; k <= JT_LOOKBACK && k <= j; k++) {
        const fathom_insn_t *p = &dis->insns[j - k];
        if (p->kind != FATHOM_INSN_OTHER)
            break;
        if (p->ref_is_addr && strcmp(p->mnemonic, "adr") == 0 && !label)
            label = p->ref_target;
        else if (p->ref_is_addr && !table)
            table = p->ref_target;
        else if (!load && (has_prefix(p->mnemonic, "ldr") || has_prefix(p->mnemonic, "movs")))
            load = p->mnemonic;
    }
    if (!table || !load)
        return 0;

    if (dis->arch == FATHOM_ARCH_X86_64)
        return read_table(dis, bin, table, 4, true, table, 0, false, max, out);
    if (!label)
        return 0;

    size_t width = strstr(load, "b") ? 1 : strstr(load, "h") ? 2 : 4;
    bool sign = has_prefix(load, "ldrs");
    size_t n = read_table(dis, bin, table, width, sign, label, 2, false, max, out);
    if (!sign && width < 4 && n < max) {
        /* gcc sign-extends byte and halfword entries when it adds them. */
        uint64_t *alt = malloc(max * sizeof(*alt));
        size_t m = alt ? read_table(dis, bin, table, width, true, label, 2, false, max, alt) : 0;
        if (m > n) {
            memcpy(out, alt, m * sizeof(*out));
            n = m;
        }
        free(alt);
    }
    return n;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void free_jtabs(jtabs_t *jt)
{
    for (size_t i = 0; i < jt->n; i++)
        free(jt->v[i].targets);
    free(jt->v);
    memset(jt, 0, sizeof(*jt));
}

static int find_jtabs(const fathom_disasm_t *dis, const fathom_binary_t *bin, jtabs_t *jt)
{
    memset(jt, 0, sizeof(*jt));
    if (!bin)
        return 0;
    uint64_t *buf = malloc(JT_MAX * sizeof(*buf));
    if (!buf)
        return -1;
    for (size_t j = 0; j < dis->count; j++) {
        const fathom_insn_t *insn = &dis->insns[j];
        if (insn->kind != FATHOM_INSN_BRANCH || insn->is_conditional || insn->branch_target)
            continue;
        size_t n = decode_table(dis, bin, j, buf);
        if (n < 2)
            continue;

        /* Unused values all lead to the default case: keep each target once. */
        qsort(buf, n, sizeof(*buf), cmp_u64);
        size_t u = 0;
        for (size_t i = 0; i < n; i++) {
            if (u == 0 || buf[i] != buf[u - 1])
                buf[u++] = buf[i];
        }
        jtab_t *v = realloc(jt->v, (jt->n + 1) * sizeof(*v));
        if (v)
            jt->v = v;
        uint64_t *t = malloc(u * sizeof(*t));
        if (!v || !t) {
            free(t);
            free(buf);
            return -1;   /* the caller frees jt */
        }
        memcpy(t, buf, u * sizeof(*t));
        jt->v[jt->n++] = (jtab_t){ j, t, u };
        jt->total += u;
    }
    free(buf);
    return 0;
}

/* ── Step 1: Identify block leaders ──────────────────────────────────── */

/*
 * A "leader" is the first instruction of a basic block.  Leaders are:
 *   - The very first instruction (index 0)
 *   - Any instruction that is the target of a branch
 *   - The instruction immediately following a branch, call, or ret
 *   - The target of a direct call (a function entry)
 *   - Any instruction not contiguous with the previous one (a section
 *     boundary or bytes the disassembler skipped)
 *   - The first instruction after inter-function padding
 *   - The entry point, function symbols and code addresses taken by
 *     lea/adr, which analysis uses as reachability roots
 *   - Jump table targets
 *
 * We collect leader indices in a sorted, deduplicated boolean array.
 */
static void mark_root(const fathom_disasm_t *dis, bool *is_leader, bool *is_target,
                      uint64_t addr)
{
    size_t idx = fathom_disasm_find(dis, addr);
    if (idx != (size_t)-1)
        is_leader[idx] = is_target[idx] = true;
}

static bool *mark_leaders(const fathom_disasm_t *dis, const fathom_binary_t *bin,
                          const jtabs_t *jt, size_t *n_leaders)
{
    bool *is_leader = calloc(dis->count, sizeof(bool));
    bool *is_target = calloc(dis->count, sizeof(bool));
    if (!is_leader || !is_target) {
        free(is_leader);
        free(is_target);
        return NULL;
    }

    /* First instruction is always a leader */
    is_leader[0] = true;

    for (size_t t = 0; t < jt->n; t++) {
        for (size_t k = 0; k < jt->v[t].n; k++)
            mark_root(dis, is_leader, is_target, jt->v[t].targets[k]);
    }

    /* Analysis roots must start blocks, or no block is found to instrument. */
    if (bin) {
        mark_root(dis, is_leader, is_target, bin->entry);
        for (size_t i = 0; i < bin->symbol_count; i++) {
            if (bin->symbols[i].type == FATHOM_SYM_FUNC)
                mark_root(dis, is_leader, is_target, bin->symbols[i].addr);
        }
    }

    for (size_t i = 0; i < dis->count; i++) {
        const fathom_insn_t *insn = &dis->insns[i];

        if (i > 0 && !contiguous(dis, i - 1, i))
            is_leader[i] = true;

        if (insn->ref_is_addr)
            mark_root(dis, is_leader, is_target, insn->ref_target);

        if (insn->kind == FATHOM_INSN_BRANCH ||
            insn->kind == FATHOM_INSN_RET) {
            /* Instruction after a branch/ret starts a new block */
            if (i + 1 < dis->count)
                is_leader[i + 1] = true;

            /* Branch target starts a new block */
            if (insn->kind == FATHOM_INSN_BRANCH &&
                insn->branch_target != 0) {
                size_t idx = fathom_disasm_find(dis, insn->branch_target);
                if (idx != (size_t)-1)
                    is_leader[idx] = is_target[idx] = true;
            }
        } else if (insn->kind == FATHOM_INSN_CALL) {
            /*
             * For calls, the next instruction starts a new block because
             * the call might not return (e.g., exit).  However, we also
             * add a fall-through edge later.
             */
            if (i + 1 < dis->count)
                is_leader[i + 1] = true;
            if (insn->branch_target != 0) {
                size_t idx = fathom_disasm_find(dis, insn->branch_target);
                if (idx != (size_t)-1)
                    is_leader[idx] = is_target[idx] = true;
            }
        }
    }

    /*
     * Alignment padding between functions would otherwise be glued onto
     * the next function's first block, hiding its entry point.  Padding
     * is int3, or a nop that follows a ret/jmp without being a branch
     * target itself; the block ends where the padding does.
     */
    for (size_t i = 1; i < dis->count; i++) {
        const fathom_insn_t *prev = &dis->insns[i - 1];
        bool after_end = prev->kind == FATHOM_INSN_RET ||
                         (prev->kind == FATHOM_INSN_BRANCH && !prev->is_conditional);
        bool pad = strcmp(dis->insns[i].mnemonic, "int3") == 0 ||
                   (after_end && strcmp(dis->insns[i].mnemonic, "nop") == 0 &&
                    !is_target[i]);
        if (!pad)
            continue;
        size_t j = i + 1;
        while (j < dis->count && is_padding(&dis->insns[j]) && contiguous(dis, j - 1, j))
            j++;
        if (j < dis->count)
            is_leader[j] = true;
        i = j - 1;
    }
    free(is_target);

    size_t count = 0;
    for (size_t i = 0; i < dis->count; i++) {
        if (is_leader[i])
            count++;
    }
    *n_leaders = count;
    return is_leader;
}

/* ── Step 2: Build basic blocks ──────────────────────────────────────── */

static int build_blocks(fathom_cfg_t *cfg, const fathom_disasm_t *dis,
                        const bool *is_leader, size_t n_leaders)
{
    cfg->blocks = calloc(n_leaders, sizeof(fathom_block_t));
    if (!cfg->blocks)
        return -1;
    cfg->block_count = n_leaders;

    uint32_t bid = 0;
    for (size_t i = 0; i < dis->count; i++) {
        if (!is_leader[i])
            continue;

        fathom_block_t *b = &cfg->blocks[bid];
        b->id = bid;
        b->start_addr = dis->insns[i].addr;
        b->insn_start = i;
        b->idom = -1;
        b->score = 0.0;

        /* Find the end of this block: next leader or end of stream */
        size_t j = i + 1;
        while (j < dis->count && !is_leader[j])
            j++;

        b->insn_count = j - i;
        /* end_addr is exclusive: address after last instruction */
        const fathom_insn_t *last = &dis->insns[j - 1];
        b->end_addr = last->addr + last->size;

        bid++;
    }

    return 0;
}

static bool falls_into_next(const fathom_cfg_t *cfg, size_t i)
{
    return i + 1 < cfg->block_count &&
           cfg->blocks[i + 1].start_addr == cfg->blocks[i].end_addr;
}

/* ── Step 3: Build edges ─────────────────────────────────────────────── */

static int build_edges(fathom_cfg_t *cfg, const fathom_disasm_t *dis, const jtabs_t *jt)
{
    /*
     * At most 2 successor edges per block (conditional branch:
     * fall-through + taken), plus one per jump table target.
     */
    size_t max_edges = cfg->block_count * 2 + jt->total;
    size_t next_jt = 0;
    cfg->edges = calloc(max_edges, sizeof(fathom_edge_t));
    if (!cfg->edges)
        return -1;

    size_t edge_idx = 0;

    for (size_t i = 0; i < cfg->block_count; i++) {
        fathom_block_t *b = &cfg->blocks[i];
        const fathom_insn_t *last =
            &dis->insns[b->insn_start + b->insn_count - 1];

        switch (last->kind) {
        case FATHOM_INSN_BRANCH:
            if (last->is_conditional) {
                /* Fall-through edge to next block */
                if (falls_into_next(cfg, i)) {
                    cfg->edges[edge_idx].from = b->id;
                    cfg->edges[edge_idx].to   = cfg->blocks[i + 1].id;
                    edge_idx++;
                }
                /* Taken edge */
                if (last->branch_target != 0) {
                    uint32_t target = find_block_by_addr(cfg, last->branch_target);
                    if (target != (uint32_t)-1) {
                        cfg->edges[edge_idx].from = b->id;
                        cfg->edges[edge_idx].to   = target;
                        edge_idx++;
                    }
                }
            } else {
                /* Unconditional jump: taken edge only */
                if (last->branch_target != 0) {
                    uint32_t target = find_block_by_addr(cfg, last->branch_target);
                    if (target != (uint32_t)-1) {
                        cfg->edges[edge_idx].from = b->id;
                        cfg->edges[edge_idx].to   = target;
                        edge_idx++;
                    }
                }
                /* Indirect: edges only through a decoded jump table. */
                size_t at = b->insn_start + b->insn_count - 1;
                while (next_jt < jt->n && jt->v[next_jt].insn < at)
                    next_jt++;
                if (next_jt < jt->n && jt->v[next_jt].insn == at) {
                    for (size_t k = 0; k < jt->v[next_jt].n; k++) {
                        uint32_t target = find_block_by_addr(cfg, jt->v[next_jt].targets[k]);
                        if (target != (uint32_t)-1) {
                            cfg->edges[edge_idx].from = b->id;
                            cfg->edges[edge_idx].to   = target;
                            edge_idx++;
                        }
                    }
                }
            }
            break;

        case FATHOM_INSN_RET:
            /* No successor edges for returns */
            break;

        case FATHOM_INSN_CALL:
            /* Calls fall through to the next block */
            if (falls_into_next(cfg, i)) {
                cfg->edges[edge_idx].from = b->id;
                cfg->edges[edge_idx].to   = cfg->blocks[i + 1].id;
                edge_idx++;
            }
            break;

        default:
            /* Ordinary instruction: fall through */
            if (falls_into_next(cfg, i)) {
                cfg->edges[edge_idx].from = b->id;
                cfg->edges[edge_idx].to   = cfg->blocks[i + 1].id;
                edge_idx++;
            }
            break;
        }
    }

    cfg->edge_count = edge_idx;

    /* Shrink to actual size */
    if (edge_idx > 0 && edge_idx < max_edges) {
        fathom_edge_t *tmp = realloc(cfg->edges, edge_idx * sizeof(fathom_edge_t));
        if (tmp)
            cfg->edges = tmp;
    } else if (edge_idx == 0) {
        free(cfg->edges);
        cfg->edges = NULL;
    }

    return 0;
}

/* ── Step 4: Build successor/predecessor lists ───────────────────────── */

static int build_adjacency(fathom_cfg_t *cfg)
{
    /* Count successors and predecessors per block */
    for (size_t i = 0; i < cfg->edge_count; i++) {
        cfg->blocks[cfg->edges[i].from].succ_count++;
        cfg->blocks[cfg->edges[i].to].pred_count++;
    }

    /* Allocate arrays */
    for (size_t i = 0; i < cfg->block_count; i++) {
        fathom_block_t *b = &cfg->blocks[i];
        if (b->succ_count > 0) {
            b->succs = calloc(b->succ_count, sizeof(uint32_t));
            if (!b->succs)
                return -1;
        }
        if (b->pred_count > 0) {
            b->preds = calloc(b->pred_count, sizeof(uint32_t));
            if (!b->preds)
                return -1;
        }
        /* Reset counts to use as insertion indices */
        b->succ_count = 0;
        b->pred_count = 0;
    }

    /* Fill arrays */
    for (size_t i = 0; i < cfg->edge_count; i++) {
        uint32_t from = cfg->edges[i].from;
        uint32_t to   = cfg->edges[i].to;

        cfg->blocks[from].succs[cfg->blocks[from].succ_count++] = to;
        cfg->blocks[to].preds[cfg->blocks[to].pred_count++] = from;
    }

    return 0;
}

/* ── Step 5: DFS for back-edges (iterative) ──────────────────────────── */

/*
 * Standard DFS coloring: WHITE=unseen, GRAY=on stack, BLACK=finished.
 * An edge to a GRAY node is a back-edge (indicates a loop).
 *
 * Uses an explicit stack to avoid deep recursion on large CFGs.
 */
enum dfs_color { WHITE = 0, GRAY, BLACK };

typedef struct {
    uint32_t node;
    size_t   succ_idx;   /* next successor to visit */
} dfs_frame_t;

static int detect_back_edges(fathom_cfg_t *cfg)
{
    size_t n = cfg->block_count;
    if (n == 0)
        return 0;

    enum dfs_color *color = calloc(n, sizeof(enum dfs_color));
    dfs_frame_t *stack = malloc(n * sizeof(dfs_frame_t));
    if (!color || !stack) {
        free(color);
        free(stack);
        return -1;
    }

    for (uint32_t start = 0; start < (uint32_t)n; start++) {
        if (color[start] != WHITE)
            continue;

        size_t sp = 0;
        stack[sp].node = start;
        stack[sp].succ_idx = 0;
        color[start] = GRAY;

        while (sp < n) {  /* sp < n is always true if stack non-empty */
            uint32_t u = stack[sp].node;
            const fathom_block_t *b = &cfg->blocks[u];

            if (stack[sp].succ_idx < b->succ_count) {
                uint32_t v = b->succs[stack[sp].succ_idx];
                stack[sp].succ_idx++;

                if (color[v] == GRAY) {
                    /* Back-edge: v is on the stack */
                    cfg->blocks[v].is_loop_header = true;
                    for (size_t e = 0; e < cfg->edge_count; e++) {
                        if (cfg->edges[e].from == u && cfg->edges[e].to == v) {
                            cfg->edges[e].is_back_edge = true;
                            break;
                        }
                    }
                } else if (color[v] == WHITE) {
                    color[v] = GRAY;
                    sp++;
                    stack[sp].node = v;
                    stack[sp].succ_idx = 0;
                }
            } else {
                color[u] = BLACK;
                if (sp == 0)
                    break;
                sp--;
            }
        }
    }

    free(color);
    free(stack);
    return 0;
}

/* ── Step 6: Compute dominator tree (iterative algorithm) ────────────── */

/*
 * Cooper, Harvey, and Kennedy's "A Simple, Fast Dominance Algorithm"
 * (2001).  Requires reverse-postorder (RPO) numbering.
 *
 * Uses iterative DFS to compute RPO (safe for large CFGs).
 */

static int32_t dom_intersect(const int32_t *idom, const uint32_t *rpo_num,
                              int32_t b1, int32_t b2)
{
    while (b1 != b2) {
        while (rpo_num[(uint32_t)b1] > rpo_num[(uint32_t)b2])
            b1 = idom[(uint32_t)b1];
        while (rpo_num[(uint32_t)b2] > rpo_num[(uint32_t)b1])
            b2 = idom[(uint32_t)b2];
    }
    return b1;
}

/*
 * Compute dominators per connected component.
 *
 * For a whole-binary CFG, the text section contains many functions,
 * each forming its own subgraph.  We run the dominator algorithm
 * independently on each connected component to avoid infinite loops
 * in dom_intersect when blocks from different components interact.
 */

/*
 * BFS to find the connected component reachable from `root`.
 * Skips blocks already assigned to a previous component.
 */
static int find_component(const fathom_cfg_t *cfg, uint32_t root,
                          const bool *assigned, bool *in_component,
                          uint32_t *members, size_t *member_count)
{
    size_t head = 0, tail = 0;
    in_component[root] = true;
    members[tail++] = root;

    while (head < tail) {
        uint32_t u = members[head++];
        const fathom_block_t *b = &cfg->blocks[u];
        for (size_t s = 0; s < b->succ_count; s++) {
            uint32_t v = b->succs[s];
            if (!in_component[v] && !assigned[v]) {
                in_component[v] = true;
                members[tail++] = v;
            }
        }
    }

    *member_count = tail;
    return 0;
}

/*
 * Compute RPO for a single component.
 * Only visits nodes in `in_component`.
 * Fills rpo_order[0..member_count-1] and rpo_num[block_id] for members.
 */
static int compute_component_rpo(const fathom_cfg_t *cfg, uint32_t root,
                                  const bool *in_component,
                                  uint32_t *rpo_order, uint32_t *rpo_num,
                                  size_t member_count)
{
    bool *visited = calloc(cfg->block_count, sizeof(bool));
    typedef struct { uint32_t node; size_t succ_idx; } frame_t;
    frame_t *stack = malloc(cfg->block_count * sizeof(frame_t));

    if (!visited || !stack) {
        free(visited);
        free(stack);
        return -1;
    }

    uint32_t rpo_pos = (uint32_t)member_count;

    size_t sp = 0;
    stack[sp].node = root;
    stack[sp].succ_idx = 0;
    visited[root] = true;

    while (sp < cfg->block_count) {
        uint32_t u = stack[sp].node;
        const fathom_block_t *b = &cfg->blocks[u];

        /* Find next unvisited in-component successor */
        bool pushed = false;
        while (stack[sp].succ_idx < b->succ_count) {
            uint32_t v = b->succs[stack[sp].succ_idx];
            stack[sp].succ_idx++;

            if (!visited[v] && in_component[v]) {
                visited[v] = true;
                sp++;
                stack[sp].node = v;
                stack[sp].succ_idx = 0;
                pushed = true;
                break;
            }
        }

        if (!pushed) {
            /* Post-order: assign RPO position */
            if (rpo_pos > 0)
                rpo_order[--rpo_pos] = u;
            if (sp == 0)
                break;
            sp--;
        }
    }

    /* Build inverse mapping for this component */
    for (uint32_t i = 0; i < (uint32_t)member_count; i++)
        rpo_num[rpo_order[i]] = i;

    free(visited);
    free(stack);
    return 0;
}

static int compute_dominators(fathom_cfg_t *cfg)
{
    size_t n = cfg->block_count;
    if (n == 0)
        return 0;

    /* Track which blocks have been assigned to a component */
    bool *assigned = calloc(n, sizeof(bool));
    bool *in_component = calloc(n, sizeof(bool));
    uint32_t *members = malloc(n * sizeof(uint32_t));
    uint32_t *rpo_order = malloc(n * sizeof(uint32_t));
    uint32_t *rpo_num = calloc(n, sizeof(uint32_t));
    int32_t *idom = malloc(n * sizeof(int32_t));

    if (!assigned || !in_component || !members ||
        !rpo_order || !rpo_num || !idom) {
        free(assigned);
        free(in_component);
        free(members);
        free(rpo_order);
        free(rpo_num);
        free(idom);
        return -1;
    }

    /* Initialize all idom to -1 */
    for (size_t i = 0; i < n; i++)
        idom[i] = -1;

    /* Process each connected component */
    for (uint32_t root = 0; root < (uint32_t)n; root++) {
        if (assigned[root])
            continue;

        /* Find all blocks reachable from this root */
        memset(in_component, 0, n * sizeof(bool));
        size_t mc = 0;
        find_component(cfg, root, assigned, in_component, members, &mc);

        /* Mark as assigned */
        for (size_t i = 0; i < mc; i++)
            assigned[members[i]] = true;

        if (mc <= 1) {
            /* Single block: idom = -1 (self) */
            cfg->blocks[root].idom = -1;
            continue;
        }

        /* Compute RPO for this component */
        if (compute_component_rpo(cfg, root, in_component,
                                   rpo_order, rpo_num, mc) != 0) {
            free(assigned); free(in_component); free(members);
            free(rpo_order); free(rpo_num); free(idom);
            return -1;
        }

        /* Initialize: root dominates itself */
        idom[root] = (int32_t)root;

        /* Reset non-root members */
        for (size_t i = 0; i < mc; i++) {
            if (members[i] != root)
                idom[members[i]] = -1;
        }

        /* Iterate until convergence */
        bool changed = true;
        while (changed) {
            changed = false;

            for (uint32_t ri = 0; ri < (uint32_t)mc; ri++) {
                uint32_t b = rpo_order[ri];
                if (b == root)
                    continue;

                const fathom_block_t *blk = &cfg->blocks[b];
                int32_t new_idom = -1;

                /* Pick first processed predecessor in this component */
                for (size_t p = 0; p < blk->pred_count; p++) {
                    uint32_t pred = blk->preds[p];
                    if (in_component[pred] && idom[pred] != -1) {
                        new_idom = (int32_t)pred;
                        break;
                    }
                }

                if (new_idom == -1)
                    continue;

                /* Intersect with remaining processed predecessors */
                for (size_t p = 0; p < blk->pred_count; p++) {
                    uint32_t pred = blk->preds[p];
                    if (in_component[pred] && idom[pred] != -1 &&
                        (int32_t)pred != new_idom)
                        new_idom = dom_intersect(idom, rpo_num,
                                                 new_idom, (int32_t)pred);
                }

                if (idom[b] != new_idom) {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        /* Store results for this component */
        for (size_t i = 0; i < mc; i++) {
            uint32_t b = members[i];
            if (b == root)
                cfg->blocks[b].idom = -1;
            else
                cfg->blocks[b].idom = idom[b];
        }
    }

    free(assigned);
    free(in_component);
    free(members);
    free(rpo_order);
    free(rpo_num);
    free(idom);
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────── */

int fathom_cfg_build(fathom_cfg_t *cfg, const fathom_disasm_t *dis,
                     const fathom_binary_t *bin)
{
    memset(cfg, 0, sizeof(*cfg));

    if (!dis || !dis->insns || dis->count == 0) {
        fprintf(stderr, "fathom_cfg: empty instruction stream\n");
        return -1;
    }

    /* Step 0: Jump tables, whose targets are leaders and successors */
    jtabs_t jt;
    if (find_jtabs(dis, bin, &jt) < 0) {
        free_jtabs(&jt);
        return -1;
    }

    /* Step 1: Mark leaders */
    size_t n_leaders = 0;
    bool *is_leader = mark_leaders(dis, bin, &jt, &n_leaders);
    if (!is_leader || n_leaders == 0) {
        free(is_leader);
        free_jtabs(&jt);
        return -1;
    }

    /* Step 2: Build basic blocks */
    if (build_blocks(cfg, dis, is_leader, n_leaders) != 0) {
        free(is_leader);
        free_jtabs(&jt);
        fathom_cfg_free(cfg);
        return -1;
    }

    free(is_leader);

    /* Step 3: Build edges */
    int rc = build_edges(cfg, dis, &jt);
    free_jtabs(&jt);
    if (rc != 0) {
        fathom_cfg_free(cfg);
        return -1;
    }

    /* Step 4: Build successor/predecessor adjacency lists */
    if (build_adjacency(cfg) != 0) {
        fathom_cfg_free(cfg);
        return -1;
    }

    /* Step 5: DFS to detect back-edges and loop headers */
    if (detect_back_edges(cfg) != 0) {
        fathom_cfg_free(cfg);
        return -1;
    }

    /* Step 6: Compute dominator tree */
    if (compute_dominators(cfg) != 0) {
        fathom_cfg_free(cfg);
        return -1;
    }

    return 0;
}

void fathom_cfg_free(fathom_cfg_t *cfg)
{
    if (!cfg)
        return;

    if (cfg->blocks) {
        for (size_t i = 0; i < cfg->block_count; i++) {
            free(cfg->blocks[i].succs);
            free(cfg->blocks[i].preds);
        }
        free(cfg->blocks);
    }
    free(cfg->edges);

    memset(cfg, 0, sizeof(*cfg));
}
