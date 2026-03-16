/*
 * analyze.c — Static analysis pass for libfathom
 *
 * Walks the CFG and scores each basic block by interestingness:
 *   - calls to dangerous libc functions (memcpy, strcpy, sprintf, ...)
 *   - loop headers (back-edges in CFG)
 *   - error handling paths (exit, abort, perror, ...)
 *   - high fan-out (complex branching)
 *
 * Also extracts printable strings from .rodata for the mutation dictionary
 * and produces a ranked target map (block IDs sorted by score descending).
 */

#include "analyze.h"
#include "elf_internal.h"
#include "disasm.h"
#include "cfg.h"
#include "mutate.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Known function tables ──────────────────────────────────────────── */

static const char *dangerous_funcs[] = {
    "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets",
    "scanf", "sscanf", "fscanf",
    "malloc", "calloc", "realloc", "free",
    "read", "write", "recv", "send",
    "system", "popen", "execve", "execvp",
    NULL
};

static const char *error_funcs[] = {
    "exit", "_exit", "_Exit",
    "abort",
    "perror",
    "err", "errx", "verr", "verrx",
    "warn", "warnx",
    "__assert_fail", "__stack_chk_fail",
    NULL
};

/* ── Helpers ─────────────────────────────────────────────────────────── */

static bool name_in_list(const char *name, const char **list)
{
    for (const char **p = list; *p; p++) {
        if (strcmp(name, *p) == 0)
            return true;
    }
    return false;
}

/*
 * Resolve a call target address to a symbol name.
 * PLT stubs typically have names like "memcpy@plt" in the symbol table;
 * we also check bare names.  Returns the symbol name or NULL.
 */
static const char *resolve_call_name(uint64_t target,
                                     const fathom_elf_t *elf)
{
    if (target == 0)
        return NULL;

    for (size_t i = 0; i < elf->symbol_count; i++) {
        if (elf->symbols[i].addr == target && elf->symbols[i].name)
            return elf->symbols[i].name;
    }
    return NULL;
}

/*
 * Strip a trailing "@plt" suffix from a symbol name for matching.
 * Returns a pointer to a static buffer (not reentrant, but fine for
 * single-threaded analysis).
 */
static const char *strip_plt_suffix(const char *name)
{
    static char buf[256];
    if (!name)
        return NULL;

    const char *at = strstr(name, "@plt");
    if (at) {
        size_t len = (size_t)(at - name);
        if (len >= sizeof(buf))
            len = sizeof(buf) - 1;
        memcpy(buf, name, len);
        buf[len] = '\0';
        return buf;
    }
    return name;
}

/* ── Scoring ─────────────────────────────────────────────────────────── */

static void score_blocks(fathom_cfg_t *cfg, const fathom_elf_t *elf,
                         const fathom_disasm_t *dis)
{
    for (size_t bi = 0; bi < cfg->block_count; bi++) {
        fathom_block_t *b = &cfg->blocks[bi];
        double score = 0.0;

        /* (a) Scan instructions for CALL to dangerous / error functions */
        for (size_t ii = 0; ii < b->insn_count; ii++) {
            const fathom_insn_t *insn =
                &dis->insns[b->insn_start + ii];

            if (insn->kind != FATHOM_INSN_CALL)
                continue;

            const char *name = resolve_call_name(insn->branch_target, elf);
            if (!name)
                continue;

            const char *base = strip_plt_suffix(name);

            if (name_in_list(base, dangerous_funcs))
                score += SCORE_DANGEROUS_CALL;
            if (name_in_list(base, error_funcs))
                score += SCORE_ERROR_PATH;
        }

        /* (b) Loop header bonus */
        if (b->is_loop_header)
            score += SCORE_LOOP_HEADER;

        /* (c) High fan-out bonus */
        if (b->succ_count > 2)
            score += SCORE_HIGH_FANOUT * (double)(b->succ_count - 2);

        b->score = score;
    }
}

/* ── Dictionary extraction from .rodata ──────────────────────────────── */

static int extract_rodata_strings(fathom_dict_t *dict,
                                  const fathom_elf_t *elf)
{
    if (!elf->rodata.size || !elf->mapped)
        return 0;

    const uint8_t *data = elf->mapped + elf->rodata.offset;
    size_t size = (size_t)elf->rodata.size;

    /* Bounds check against the mapped file */
    if (elf->rodata.offset + size > elf->mapped_len)
        size = elf->mapped_len - (size_t)elf->rodata.offset;

    size_t run_start = 0;
    bool in_run = false;

    for (size_t i = 0; i < size; i++) {
        uint8_t c = data[i];

        if (isprint(c) || c == '\t' || c == '\n' || c == '\r') {
            if (!in_run) {
                run_start = i;
                in_run = true;
            }
        } else {
            if (in_run) {
                size_t run_len = i - run_start;
                if (run_len >= RODATA_MIN_STR_LEN) {
                    /* Cap entry at FATHOM_DICT_MAX_ENTRY */
                    size_t add_len = run_len;
                    if (add_len > FATHOM_DICT_MAX_ENTRY)
                        add_len = FATHOM_DICT_MAX_ENTRY;
                    fathom_dict_add(dict, data + run_start, add_len);
                }
                in_run = false;
            }
        }
    }

    /* Handle a run that extends to the end of .rodata */
    if (in_run) {
        size_t run_len = size - run_start;
        if (run_len >= RODATA_MIN_STR_LEN) {
            size_t add_len = run_len;
            if (add_len > FATHOM_DICT_MAX_ENTRY)
                add_len = FATHOM_DICT_MAX_ENTRY;
            fathom_dict_add(dict, data + run_start, add_len);
        }
    }

    return 0;
}

/* ── Ranked block comparison (qsort: descending by score) ────────────── */

static fathom_block_t *g_sort_blocks;   /* set before qsort call */

static int cmp_ranked_desc(const void *a, const void *b)
{
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    double sa = g_sort_blocks[ia].score;
    double sb = g_sort_blocks[ib].score;

    if (sa > sb) return -1;
    if (sa < sb) return  1;
    return 0;
}

static int build_ranked_blocks(fathom_analysis_t *ana, fathom_cfg_t *cfg)
{
    /* Count blocks with positive score */
    size_t count = 0;
    for (size_t i = 0; i < cfg->block_count; i++) {
        if (cfg->blocks[i].score > 0.0)
            count++;
    }

    if (count == 0) {
        ana->ranked_blocks = NULL;
        ana->ranked_count  = 0;
        return 0;
    }

    ana->ranked_blocks = malloc(count * sizeof(uint32_t));
    if (!ana->ranked_blocks)
        return -1;

    size_t idx = 0;
    for (size_t i = 0; i < cfg->block_count; i++) {
        if (cfg->blocks[i].score > 0.0)
            ana->ranked_blocks[idx++] = (uint32_t)i;
    }
    ana->ranked_count = count;

    /* Sort descending by score */
    g_sort_blocks = cfg->blocks;
    qsort(ana->ranked_blocks, count, sizeof(uint32_t), cmp_ranked_desc);
    g_sort_blocks = NULL;

    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────── */

int fathom_analyze(fathom_analysis_t *ana, fathom_cfg_t *cfg,
                   const fathom_elf_t *elf, const fathom_disasm_t *dis)
{
    memset(ana, 0, sizeof(*ana));

    if (!cfg || !elf || !dis) {
        fprintf(stderr, "fathom_analyze: NULL argument\n");
        return -1;
    }

    ana->cfg = cfg;

    /* Step 1-2: Score every block */
    score_blocks(cfg, elf, dis);

    /* Step 3: Extract dictionary from .rodata */
    fathom_dict_init(&ana->dict);
    extract_rodata_strings(&ana->dict, elf);

    /* Step 4: Build ranked target map */
    if (build_ranked_blocks(ana, cfg) != 0) {
        fathom_analysis_free(ana);
        return -1;
    }

    return 0;
}

void fathom_analysis_free(fathom_analysis_t *ana)
{
    if (!ana)
        return;

    fathom_dict_destroy(&ana->dict);
    free(ana->ranked_blocks);

    /* cfg is not owned by the analysis; caller frees it separately */
    memset(ana, 0, sizeof(*ana));
}

void fathom_analysis_print(const fathom_analysis_t *ana,
                           const fathom_disasm_t *dis)
{
    if (!ana || !ana->cfg) {
        fprintf(stderr, "fathom_analysis_print: no analysis data\n");
        return;
    }

    const fathom_cfg_t *cfg = ana->cfg;

    printf("=== Fathom Static Analysis ===\n\n");
    printf("  Blocks: %zu\n", cfg->block_count);
    printf("  Edges:  %zu\n", cfg->edge_count);
    printf("  Scored: %zu (score > 0)\n", ana->ranked_count);
    printf("  Dict:   %zu entries from .rodata\n\n", ana->dict.count);

    /* Top N highest-scored blocks */
    size_t show = ana->ranked_count;
    if (show > ANALYSIS_TOP_N)
        show = ANALYSIS_TOP_N;

    if (show > 0)
        printf("  Top %zu blocks by score:\n\n", show);

    /*
     * To describe blocks we need the ELF for symbol resolution.
     * Since fathom_analysis_print only receives ana and dis, we use a
     * simplified description that doesn't resolve call names (we stored
     * scores already).  For full descriptions, the caller can iterate
     * ranked_blocks directly.
     */
    printf("  %-6s  %-18s  %-8s  %s\n", "Rank", "Address", "Score", "Info");
    printf("  %-6s  %-18s  %-8s  %s\n", "----", "------------------",
           "--------", "----");

    for (size_t i = 0; i < show; i++) {
        uint32_t bid = ana->ranked_blocks[i];
        const fathom_block_t *b = &cfg->blocks[bid];

        /* Build a compact info string from what we know */
        char info[256];
        size_t off = 0;
        info[0] = '\0';

        if (b->is_loop_header) {
            int n = snprintf(info + off, sizeof(info) - off,
                             "loop-header");
            if (n > 0) off += (size_t)n;
        }

        if (b->succ_count > 2) {
            int n = snprintf(info + off, sizeof(info) - off,
                             "%sfan-out:%zu", off > 0 ? " " : "",
                             b->succ_count);
            if (n > 0) off += (size_t)n;
        }

        /* Check for call instructions to give hints */
        for (size_t ii = 0; ii < b->insn_count && off < sizeof(info) - 1; ii++) {
            const fathom_insn_t *insn = &dis->insns[b->insn_start + ii];
            if (insn->kind == FATHOM_INSN_CALL && insn->branch_target != 0) {
                int n = snprintf(info + off, sizeof(info) - off,
                                 "%scall@0x%lx", off > 0 ? " " : "",
                                 (unsigned long)insn->branch_target);
                if (n > 0) off += (size_t)n;
            }
        }

        if (info[0] == '\0')
            snprintf(info, sizeof(info), "-");

        printf("  %-6zu  0x%016lx  %-8.1f  %s\n",
               i + 1, (unsigned long)b->start_addr, b->score, info);
    }

    if (ana->ranked_count > show)
        printf("\n  ... and %zu more scored blocks\n",
               ana->ranked_count - show);

    printf("\n");
}
