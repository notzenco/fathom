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
#include "disasm.h"
#include "cfg.h"
#include "mutate.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
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
    /* glibc / Darwin fortified variants */
    "__memcpy_chk", "__memmove_chk", "__strcpy_chk", "__strcat_chk",
    "__sprintf_chk", "__snprintf_chk", "__vsprintf_chk",
    /* Windows CRT */
    "_snprintf", "_vsnprintf", "lstrcpyA", "lstrcpyW", "lstrcatA",
    "wcscpy", "wcscat", "_read", "_write",
    NULL
};

static const char *error_funcs[] = {
    "exit", "_exit", "_Exit",
    "abort",
    "perror",
    "err", "errx", "verr", "verrx",
    "warn", "warnx",
    "__assert_fail", "__assert_rtn", "_assert", "_wassert",
    "__stack_chk_fail", "__chk_fail",
    "ExitProcess", "TerminateProcess",
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

static bool in_code(const fathom_binary_t *bin, uint64_t addr)
{
    for (size_t i = 0; i < bin->section_count; i++) {
        const fathom_section_t *s = &bin->sections[i];
        if ((s->flags & FATHOM_SEC_CODE) && addr >= s->addr &&
            addr < s->addr + s->size)
            return true;
    }
    return false;
}

static const char *symbol_at(const fathom_binary_t *bin, uint64_t addr)
{
    size_t lo = 0, hi = bin->symbol_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (bin->symbols[mid].addr < addr)
            lo = mid + 1;
        else if (bin->symbols[mid].addr > addr)
            hi = mid;
        else
            return bin->symbols[mid].name;
    }
    return NULL;
}

/*
 * Name the function a call instruction reaches.  Handles direct calls
 * to defined symbols, calls through an import slot (`call [rip+slot]`),
 * and calls to an import stub: a PLT entry, Mach-O stub or MinGW thunk
 * whose first few instructions load and jump through an import slot.
 */
const char *fathom_resolve_call(const fathom_binary_t *bin,
                                const fathom_disasm_t *dis,
                                const fathom_insn_t *call)
{
    if (call->ref_target) {
        const char *name = fathom_import_at(bin, call->ref_target);
        if (name)
            return name;
    }

    uint64_t target = call->branch_target;
    if (target == 0)
        return NULL;

    const char *name = fathom_import_at(bin, target);
    if (!name)
        name = symbol_at(bin, target);
    if (name)
        return name;

    size_t idx = fathom_disasm_find(dis, target);
    for (size_t i = 0; idx != (size_t)-1 && i < 4 && idx + i < dis->count; i++) {
        const fathom_insn_t *insn = &dis->insns[idx + i];
        if (insn->ref_target && (name = fathom_import_at(bin, insn->ref_target)))
            return name;
        if (insn->kind != FATHOM_INSN_OTHER)
            break;
    }
    return NULL;
}

/* ── Scoring ─────────────────────────────────────────────────────────── */

static void score_blocks(fathom_cfg_t *cfg, const fathom_binary_t *bin,
                         const fathom_disasm_t *dis)
{
    for (size_t bi = 0; bi < cfg->block_count; bi++) {
        fathom_block_t *b = &cfg->blocks[bi];
        double score = 0.0;

        /* (a) Calls to dangerous / error functions */
        for (size_t ii = 0; ii < b->insn_count; ii++) {
            const fathom_insn_t *insn = &dis->insns[b->insn_start + ii];
            if (insn->kind != FATHOM_INSN_CALL)
                continue;

            const char *name = fathom_resolve_call(bin, dis, insn);
            if (!name)
                continue;
            if (name_in_list(name, dangerous_funcs))
                score += SCORE_DANGEROUS_CALL;
            if (name_in_list(name, error_funcs))
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

/* ── Instrumentable blocks ───────────────────────────────────────────── */

static uint32_t block_at(const fathom_cfg_t *cfg, uint64_t addr)
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
    return UINT32_MAX;
}

static int cmp_score_desc(const void *a, const void *b, const fathom_block_t *blocks)
{
    double sa = blocks[*(const uint32_t *)a].score;
    double sb = blocks[*(const uint32_t *)b].score;
    return (sa < sb) - (sa > sb);
}

static fathom_block_t *g_sort_blocks;   /* qsort has no context argument */

static int cmp_ranked_desc(const void *a, const void *b)
{
    int c = cmp_score_desc(a, b, g_sort_blocks);
    if (c == 0)
        c = (*(const uint32_t *)a > *(const uint32_t *)b) -
            (*(const uint32_t *)a < *(const uint32_t *)b);
    return c;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/*
 * Breakpoints overwrite code bytes, so they must only land on real
 * instruction boundaries.  Linear sweep can misread data embedded in
 * code, so instead of trusting every block, walk the CFG from known
 * code: the entry point, function symbols, direct call targets, and
 * code addresses the program takes (e.g. `lea rdi, [rip+main]`, which is
 * how _start reaches main in a stripped binary).
 */
static int find_cov_blocks(fathom_analysis_t *ana, const fathom_cfg_t *cfg,
                           const fathom_binary_t *bin, const fathom_disasm_t *dis)
{
    size_t n = cfg->block_count;
    bool *seen = calloc(n ? n : 1, sizeof(bool));
    uint32_t *work = malloc((n ? n : 1) * sizeof(uint32_t));
    if (!seen || !work) {
        free(seen);
        free(work);
        return -1;
    }
    size_t top = 0;

#define PUSH_ADDR(a) do { \
        uint32_t id_ = block_at(cfg, (a)); \
        if (id_ != UINT32_MAX && !seen[id_]) { seen[id_] = true; work[top++] = id_; } \
    } while (0)

    PUSH_ADDR(bin->entry);
    for (size_t i = 0; i < bin->symbol_count; i++) {
        if (bin->symbols[i].type == FATHOM_SYM_FUNC)
            PUSH_ADDR(bin->symbols[i].addr);
    }

    size_t count = 0;
    while (top > 0) {
        const fathom_block_t *b = &cfg->blocks[work[--top]];
        count++;

        for (size_t s = 0; s < b->succ_count; s++) {
            if (!seen[b->succs[s]]) {
                seen[b->succs[s]] = true;
                work[top++] = b->succs[s];
            }
        }
        for (size_t ii = 0; ii < b->insn_count; ii++) {
            const fathom_insn_t *insn = &dis->insns[b->insn_start + ii];
            if (insn->kind == FATHOM_INSN_CALL && insn->branch_target)
                PUSH_ADDR(insn->branch_target);
            if (insn->ref_target && in_code(bin, insn->ref_target))
                PUSH_ADDR(insn->ref_target);
        }
    }
#undef PUSH_ADDR

    ana->cov_blocks = malloc((count ? count : 1) * sizeof(uint32_t));
    if (!ana->cov_blocks) {
        free(seen);
        free(work);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (seen[i])
            ana->cov_blocks[ana->cov_count++] = (uint32_t)i;
    }
    free(seen);
    free(work);

    /* Over the map size, keep the most interesting blocks. */
    if (ana->cov_count > FATHOM_MAP_SIZE) {
        g_sort_blocks = cfg->blocks;
        qsort(ana->cov_blocks, ana->cov_count, sizeof(uint32_t), cmp_ranked_desc);
        g_sort_blocks = NULL;
        ana->cov_count = FATHOM_MAP_SIZE;
        qsort(ana->cov_blocks, ana->cov_count, sizeof(uint32_t), cmp_u32);
    }
    return 0;
}

/* ── Dictionary extraction from .rodata ──────────────────────────────── */

static void add_string(fathom_dict_t *dict, const uint8_t *p, size_t len)
{
    if (len < RODATA_MIN_STR_LEN)
        return;
    if (len > FATHOM_DICT_MAX_ENTRY)
        len = FATHOM_DICT_MAX_ENTRY;
    fathom_dict_add(dict, p, len);
}

static void extract_rodata_strings(fathom_dict_t *dict, const fathom_binary_t *bin)
{
    for (size_t si = 0; si < bin->section_count; si++) {
        const fathom_section_t *sec = &bin->sections[si];
        if (!(sec->flags & FATHOM_SEC_RODATA))
            continue;

        const uint8_t *data = bin->image + sec->offset;
        size_t size = (size_t)sec->size;
        size_t run_start = 0;
        bool in_run = false;

        for (size_t i = 0; i < size; i++) {
            uint8_t c = data[i];
            if (isprint(c) || c == '\t' || c == '\n' || c == '\r') {
                if (!in_run) {
                    run_start = i;
                    in_run = true;
                }
            } else if (in_run) {
                add_string(dict, data + run_start, i - run_start);
                in_run = false;
            }
        }
        if (in_run)
            add_string(dict, data + run_start, size - run_start);
    }
}

/*
 * Constants the program compares input against (`cmp al, 0x46`) are the
 * values random mutation is least likely to guess, so they go into the
 * dictionary as 1-, 2-, 4- or 8-byte little-endian tokens.
 */
static void extract_cmp_constants(fathom_dict_t *dict, const fathom_disasm_t *dis)
{
    size_t added = 0;
    for (size_t i = 0; i < dis->count && added < CMP_DICT_MAX; i++) {
        if (dis->insns[i].has_cmp_imm &&
            fathom_dict_add_constant(dict, dis->insns[i].cmp_imm) > 0)
            added++;
    }
}

/* ── Ranked target map ───────────────────────────────────────────────── */

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
                   const fathom_binary_t *bin, const fathom_disasm_t *dis)
{
    memset(ana, 0, sizeof(*ana));

    if (!cfg || !bin || !dis) {
        fprintf(stderr, "fathom_analyze: NULL argument\n");
        return -1;
    }

    ana->cfg = cfg;

    /* Step 1-2: Score every block */
    score_blocks(cfg, bin, dis);

    /* Step 3: Dictionary from read-only strings and comparison constants */
    fathom_dict_init(&ana->dict);
    extract_rodata_strings(&ana->dict, bin);
    extract_cmp_constants(&ana->dict, dis);

    /* Step 4: Build ranked target map and the instrumentable block set */
    if (build_ranked_blocks(ana, cfg) != 0 ||
        find_cov_blocks(ana, cfg, bin, dis) != 0) {
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
    free(ana->cov_blocks);

    /* cfg is not owned by the analysis; caller frees it separately */
    memset(ana, 0, sizeof(*ana));
}

/* Append printf-style text to buf, never past its end. */
static void appendf(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
    if (*off >= cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n > 0)
        *off += (size_t)n;
}

void fathom_analysis_print(const fathom_analysis_t *ana,
                           const fathom_binary_t *bin,
                           const fathom_disasm_t *dis)
{
    if (!ana || !ana->cfg) {
        fprintf(stderr, "fathom_analysis_print: no analysis data\n");
        return;
    }

    const fathom_cfg_t *cfg = ana->cfg;

    printf("=== Fathom Static Analysis ===\n\n");
    printf("  Format: %s %s%s\n", fathom_format_name(bin->format),
           fathom_arch_name(bin->arch), bin->relocatable ? " (relocatable)" : "");
    printf("  Entry:  0x%" PRIx64 "\n", bin->entry);
    printf("  Blocks: %zu (%zu instrumentable)\n", cfg->block_count, ana->cov_count);
    printf("  Edges:  %zu\n", cfg->edge_count);
    printf("  Imports: %zu, symbols: %zu%s\n", bin->import_count,
           bin->symbol_count, bin->stripped ? " (stripped)" : "");
    printf("  Scored: %zu (score > 0)\n", ana->ranked_count);
    printf("  Dict:   %zu entries (strings + comparison constants)\n\n", ana->dict.count);

    size_t show = ana->ranked_count;
    if (show > ANALYSIS_TOP_N)
        show = ANALYSIS_TOP_N;
    if (show == 0)
        return;

    printf("  Top %zu blocks by score:\n\n", show);
    printf("  %-6s  %-18s  %-8s  %s\n", "Rank", "Address", "Score", "Info");
    printf("  %-6s  %-18s  %-8s  %s\n", "----", "------------------",
           "--------", "----");

    for (size_t i = 0; i < show; i++) {
        const fathom_block_t *b = &cfg->blocks[ana->ranked_blocks[i]];
        char info[256];
        size_t off = 0;
        info[0] = '\0';

        if (b->is_loop_header)
            appendf(info, sizeof(info), &off, "loop-header");
        if (b->succ_count > 2)
            appendf(info, sizeof(info), &off, "%sfan-out:%zu",
                    off ? " " : "", b->succ_count);

        for (size_t ii = 0; ii < b->insn_count; ii++) {
            const fathom_insn_t *insn = &dis->insns[b->insn_start + ii];
            if (insn->kind != FATHOM_INSN_CALL)
                continue;
            const char *name = fathom_resolve_call(bin, dis, insn);
            if (name)
                appendf(info, sizeof(info), &off, "%scall %s", off ? " " : "", name);
            else if (insn->branch_target)
                appendf(info, sizeof(info), &off, "%scall 0x%" PRIx64,
                        off ? " " : "", insn->branch_target);
        }

        printf("  %-6zu  0x%016" PRIx64 "  %-8.1f  %s\n",
               i + 1, b->start_addr, b->score, info[0] ? info : "-");
    }

    if (ana->ranked_count > show)
        printf("\n  ... and %zu more scored blocks\n", ana->ranked_count - show);
    printf("\n");
}
