/*
 * test_analyze.c — Static analysis tests on synthetic instruction streams
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                             \
    do {                                                             \
        if (!(cond)) {                                               \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
            failures++;                                              \
        }                                                            \
    } while (0)

#define INSN(a, sz, k, m) { .addr = (a), .size = (sz), .kind = (k), .mnemonic = m }

static fathom_section_t g_text = {
    .addr = 0x1000, .size = 0x2000, .flags = FATHOM_SEC_CODE, .name = ".text",
};

static fathom_binary_t make_bin(uint64_t entry)
{
    fathom_binary_t bin;
    memset(&bin, 0, sizeof(bin));
    bin.arch = FATHOM_ARCH_X86_64;
    bin.entry = entry;
    bin.sections = &g_text;
    bin.section_count = 1;
    return bin;
}

static bool instrumented(const fathom_analysis_t *ana, const fathom_cfg_t *cfg,
                         uint64_t addr)
{
    for (size_t i = 0; i < ana->cov_count; i++) {
        if (cfg->blocks[ana->cov_blocks[i]].start_addr == addr)
            return true;
    }
    return false;
}

static int analyze(fathom_insn_t *insns, size_t n, const fathom_binary_t *bin,
                   fathom_cfg_t *cfg, fathom_analysis_t *ana)
{
    fathom_disasm_t dis = { .arch = FATHOM_ARCH_X86_64, .insns = insns, .count = n };
    if (fathom_cfg_build(cfg, &dis, bin) < 0)
        return -1;
    if (fathom_analyze(ana, cfg, bin, &dis) < 0) {
        fathom_cfg_free(cfg);
        return -1;
    }
    return 0;
}

/*
 * `mov eax, [rip+0x2000]` reads data that happens to sit in a code
 * section.  A breakpoint there would change the value the target reads.
 */
static void test_data_load_not_a_root(void)
{
    printf("=== test_data_load_not_a_root ===\n");
    fathom_insn_t insns[] = {
        INSN(0x1000, 6, FATHOM_INSN_OTHER, "mov"),
        INSN(0x1006, 1, FATHOM_INSN_RET,   "ret"),
        INSN(0x2000, 1, FATHOM_INSN_OTHER, "nop"),
        INSN(0x2001, 1, FATHOM_INSN_RET,   "ret"),
    };
    insns[0].ref_target = 0x2000;

    fathom_binary_t bin = make_bin(0x1000);
    fathom_cfg_t cfg;
    fathom_analysis_t ana;
    CHECK(analyze(insns, 4, &bin, &cfg, &ana) == 0, "analyze");
    CHECK(instrumented(&ana, &cfg, 0x1000), "entry block instrumented");
    CHECK(!instrumented(&ana, &cfg, 0x2000), "data load target not instrumented");
    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
}

/* `lea rdi, [rip+fn]` takes a code address, so fn is reachable code. */
static void test_lea_is_a_root(void)
{
    printf("=== test_lea_is_a_root ===\n");
    fathom_insn_t insns[] = {
        INSN(0x1000, 7, FATHOM_INSN_OTHER, "lea"),
        INSN(0x1007, 1, FATHOM_INSN_RET,   "ret"),
        INSN(0x2000, 1, FATHOM_INSN_OTHER, "nop"),
        INSN(0x2001, 1, FATHOM_INSN_RET,   "ret"),
    };
    insns[0].ref_target = 0x2000;
    insns[0].ref_is_addr = true;

    fathom_binary_t bin = make_bin(0x1000);
    fathom_cfg_t cfg;
    fathom_analysis_t ana;
    CHECK(analyze(insns, 4, &bin, &cfg, &ana) == 0, "analyze");
    CHECK(instrumented(&ana, &cfg, 0x2000), "lea target instrumented");
    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
}

/* An entry point in the middle of a linear run must still be a block start. */
static void test_mid_block_entry(void)
{
    printf("=== test_mid_block_entry ===\n");
    fathom_insn_t insns[] = {
        INSN(0x1000, 1, FATHOM_INSN_OTHER, "nop"),
        INSN(0x1001, 1, FATHOM_INSN_OTHER, "nop"),
        INSN(0x1002, 1, FATHOM_INSN_RET,   "ret"),
    };

    fathom_binary_t bin = make_bin(0x1001);
    fathom_cfg_t cfg;
    fathom_analysis_t ana;
    CHECK(analyze(insns, 3, &bin, &cfg, &ana) == 0, "analyze");
    CHECK(instrumented(&ana, &cfg, 0x1001), "entry block instrumented");
    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
}

/* Real binaries can have more blocks than any fixed map; none may be dropped. */
static void test_no_block_cap(void)
{
    printf("=== test_no_block_cap ===\n");
    const size_t n = 70000;
    fathom_insn_t *insns = calloc(n, sizeof(*insns));
    for (size_t i = 0; i < n; i++) {
        insns[i] = (fathom_insn_t)INSN(0x100000 + 2 * i, 2, FATHOM_INSN_BRANCH, "je");
        insns[i].is_conditional = true;
        insns[i].branch_target = 0x100000 + 2 * (i + 1);
    }
    insns[n - 1] = (fathom_insn_t)INSN(0x100000 + 2 * (n - 1), 1, FATHOM_INSN_RET, "ret");

    fathom_section_t text = { .addr = 0x100000, .size = 2 * n, .flags = FATHOM_SEC_CODE };
    fathom_binary_t bin = make_bin(0x100000);
    bin.sections = &text;
    fathom_cfg_t cfg;
    fathom_analysis_t ana;
    CHECK(analyze(insns, n, &bin, &cfg, &ana) == 0, "analyze");
    CHECK(ana.cov_count == n, "every reachable block instrumentable");
    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
    free(insns);
}

int main(void)
{
    test_data_load_not_a_root();
    test_lea_is_a_root();
    test_mid_block_entry();
    test_no_block_cap();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("All analyze tests passed\n");
    return 0;
}
