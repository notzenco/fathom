/*
 * test_cfg.c — CFG builder unit tests
 *
 * Tests the CFG builder with both a synthetic instruction stream
 * (known control flow) and a real binary (/bin/ls).
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, msg)                                             \
    do {                                                             \
        if (!(cond)) {                                               \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
            failures++;                                              \
        }                                                            \
    } while (0)

/* ── Helper: locate a test binary ────────────────────────────────────── */

static const char *test_binary(void)
{
    static const char *candidates[] = {
        "/usr/bin/ls",
        "/bin/ls",
        NULL,
    };
    for (const char **p = candidates; *p; p++) {
        if (access(*p, R_OK) == 0)
            return *p;
    }
    return NULL;
}

/* ── Test 1: Synthetic instruction stream ────────────────────────────── */

/*
 * We construct a small "function" that looks like:
 *
 *   0x1000: mov   (OTHER)         -- block 0
 *   0x1003: cmp   (OTHER)         |
 *   0x1006: je    0x1020 (BRANCH, conditional)   -- ends block 0
 *
 *   0x1009: mov   (OTHER)         -- block 1 (fall-through from 0)
 *   0x100c: jmp   0x1018 (BRANCH, unconditional) -- ends block 1
 *
 *   0x100f: nop   (OTHER)         -- block 2 (target of back-edge)
 *   0x1010: add   (OTHER)         |
 *   0x1013: cmp   (OTHER)         |
 *   0x1016: jne   0x100f (BRANCH, conditional) -- back-edge to block 2
 *
 *   0x1018: call  0x2000 (CALL)   -- block 3 (target of jmp from block 1)
 *
 *   0x101d: nop   (OTHER)         -- block 4 (after call)
 *   0x101e: jmp   0x100f (BRANCH, unconditional) -- jump to loop header
 *
 *   0x1020: ret   (RET)           -- block 5 (target of je from block 0)
 *
 * Expected CFG:
 *   Block 0 (0x1000): succs = {1, 5}  (fall-through + taken je)
 *   Block 1 (0x1009): succs = {3}     (unconditional jmp)
 *   Block 2 (0x100f): succs = {3, 2}  (fall-through + back-edge to self)
 *                                       Actually: conditional jne -> 0x100f = block 2
 *                                       fall-through -> 0x1018 = block 3
 *   Block 3 (0x1018): succs = {4}     (call fall-through)
 *   Block 4 (0x101d): succs = {2}     (unconditional jmp to loop header)
 *   Block 5 (0x1020): succs = {}      (ret)
 *
 * Back-edges: (2 -> 2) from jne, (4 -> 2) forms another back-edge
 * Loop headers: block 2 (0x100f)
 */
static void test_synthetic_cfg(void)
{
    printf("=== test_synthetic_cfg ===\n");

    fathom_insn_t insns[] = {
        /* Block 0 */
        { .addr = 0x1000, .size = 3, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "mov" },
        { .addr = 0x1003, .size = 3, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "cmp" },
        { .addr = 0x1006, .size = 3, .kind = FATHOM_INSN_BRANCH,
          .branch_target = 0x1020, .is_conditional = true, .mnemonic = "je" },

        /* Block 1 */
        { .addr = 0x1009, .size = 3, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "mov" },
        { .addr = 0x100c, .size = 3, .kind = FATHOM_INSN_BRANCH,
          .branch_target = 0x1018, .is_conditional = false, .mnemonic = "jmp" },

        /* Block 2: loop body */
        { .addr = 0x100f, .size = 1, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "nop" },
        { .addr = 0x1010, .size = 3, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "add" },
        { .addr = 0x1013, .size = 3, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "cmp" },
        { .addr = 0x1016, .size = 2, .kind = FATHOM_INSN_BRANCH,
          .branch_target = 0x100f, .is_conditional = true, .mnemonic = "jne" },

        /* Block 3 */
        { .addr = 0x1018, .size = 5, .kind = FATHOM_INSN_CALL,
          .branch_target = 0x2000, .is_conditional = false, .mnemonic = "call" },

        /* Block 4 */
        { .addr = 0x101d, .size = 1, .kind = FATHOM_INSN_OTHER,
          .branch_target = 0, .is_conditional = false, .mnemonic = "nop" },
        { .addr = 0x101e, .size = 2, .kind = FATHOM_INSN_BRANCH,
          .branch_target = 0x100f, .is_conditional = false, .mnemonic = "jmp" },

        /* Block 5 */
        { .addr = 0x1020, .size = 1, .kind = FATHOM_INSN_RET,
          .branch_target = 0, .is_conditional = false, .mnemonic = "ret" },
    };

    fathom_disasm_t dis = {
        .insns = insns,
        .count = sizeof(insns) / sizeof(insns[0]),
    };

    fathom_cfg_t cfg;
    int rc = fathom_cfg_build(&cfg, &dis);
    CHECK(rc == 0, "fathom_cfg_build should succeed");
    if (rc != 0) {
        fprintf(stderr, "Cannot build CFG — aborting synthetic test\n");
        return;
    }

    printf("  blocks: %zu  edges: %zu\n", cfg.block_count, cfg.edge_count);

    /* Verify block count */
    CHECK(cfg.block_count == 6, "should have 6 basic blocks");

    /* Verify block addresses */
    if (cfg.block_count >= 6) {
        CHECK(cfg.blocks[0].start_addr == 0x1000, "block 0 starts at 0x1000");
        CHECK(cfg.blocks[1].start_addr == 0x1009, "block 1 starts at 0x1009");
        CHECK(cfg.blocks[2].start_addr == 0x100f, "block 2 starts at 0x100f");
        CHECK(cfg.blocks[3].start_addr == 0x1018, "block 3 starts at 0x1018");
        CHECK(cfg.blocks[4].start_addr == 0x101d, "block 4 starts at 0x101d");
        CHECK(cfg.blocks[5].start_addr == 0x1020, "block 5 starts at 0x1020");
    }

    /* Verify instruction counts */
    if (cfg.block_count >= 6) {
        CHECK(cfg.blocks[0].insn_count == 3, "block 0 has 3 instructions");
        CHECK(cfg.blocks[1].insn_count == 2, "block 1 has 2 instructions");
        CHECK(cfg.blocks[2].insn_count == 4, "block 2 has 4 instructions");
        CHECK(cfg.blocks[3].insn_count == 1, "block 3 has 1 instruction");
        CHECK(cfg.blocks[4].insn_count == 2, "block 4 has 2 instructions");
        CHECK(cfg.blocks[5].insn_count == 1, "block 5 has 1 instruction");
    }

    /* Verify edge count */
    /*
     * Expected edges:
     *   0 -> 1 (fall-through from je)
     *   0 -> 5 (taken je)
     *   1 -> 3 (unconditional jmp)
     *   2 -> 3 (fall-through from jne)
     *   2 -> 2 (taken jne, back-edge)
     *   3 -> 4 (call fall-through)
     *   4 -> 2 (unconditional jmp)
     * Total: 7 edges
     */
    CHECK(cfg.edge_count == 7, "should have 7 edges");

    /* Verify successors */
    if (cfg.block_count >= 6) {
        CHECK(cfg.blocks[0].succ_count == 2, "block 0 has 2 successors");
        CHECK(cfg.blocks[1].succ_count == 1, "block 1 has 1 successor");
        CHECK(cfg.blocks[2].succ_count == 2, "block 2 has 2 successors");
        CHECK(cfg.blocks[3].succ_count == 1, "block 3 has 1 successor");
        CHECK(cfg.blocks[4].succ_count == 1, "block 4 has 1 successor");
        CHECK(cfg.blocks[5].succ_count == 0, "block 5 (ret) has 0 successors");
    }

    /* Verify loop header detection */
    if (cfg.block_count >= 6) {
        CHECK(cfg.blocks[2].is_loop_header == true,
              "block 2 should be a loop header (target of back-edges)");
        CHECK(cfg.blocks[0].is_loop_header == false,
              "block 0 should not be a loop header");
    }

    /* Count back-edges */
    size_t back_edge_count = 0;
    for (size_t i = 0; i < cfg.edge_count; i++) {
        if (cfg.edges[i].is_back_edge)
            back_edge_count++;
    }
    printf("  back-edges: %zu\n", back_edge_count);
    CHECK(back_edge_count >= 1, "should detect at least 1 back-edge");

    /* Verify dominator tree */
    if (cfg.block_count >= 6) {
        CHECK(cfg.blocks[0].idom == -1,
              "block 0 (entry) idom should be -1");
        CHECK(cfg.blocks[1].idom == 0,
              "block 1 idom should be block 0");
        CHECK(cfg.blocks[5].idom == 0,
              "block 5 idom should be block 0");
        /* Block 3 is dominated by block 0 (reachable via both 1->3 and 2->3) */
        CHECK(cfg.blocks[3].idom == 0 ||
              cfg.blocks[3].idom == 1 ||
              cfg.blocks[3].idom == 2,
              "block 3 idom should be reachable from block 0");
    }

    /* Print summary */
    printf("  Dominator tree:\n");
    for (size_t i = 0; i < cfg.block_count; i++) {
        printf("    block %u (0x%lx): idom=%d, loop_header=%d, "
               "succs=%zu, preds=%zu\n",
               cfg.blocks[i].id,
               (unsigned long)cfg.blocks[i].start_addr,
               cfg.blocks[i].idom,
               cfg.blocks[i].is_loop_header,
               cfg.blocks[i].succ_count,
               cfg.blocks[i].pred_count);
    }

    printf("  Edges:\n");
    for (size_t i = 0; i < cfg.edge_count; i++) {
        printf("    %u -> %u%s\n",
               cfg.edges[i].from, cfg.edges[i].to,
               cfg.edges[i].is_back_edge ? " (back-edge)" : "");
    }

    fathom_cfg_free(&cfg);
    printf("  synthetic test done.\n\n");
}

/* ── Test 2: Real binary (/bin/ls) ───────────────────────────────────── */

static void test_real_binary_cfg(void)
{
    printf("=== test_real_binary_cfg ===\n");

    const char *path = test_binary();
    if (!path) {
        fprintf(stderr, "SKIP: no test binary found\n");
        return;
    }

    fathom_elf_t elf;
    int rc = fathom_elf_open(&elf, path);
    CHECK(rc == 0, "fathom_elf_open should succeed");
    if (rc != 0) return;

    fathom_disasm_t dis;
    rc = fathom_disasm_open(&dis, &elf);
    CHECK(rc == 0, "fathom_disasm_open should succeed");
    if (rc != 0) {
        fathom_elf_close(&elf);
        return;
    }

    printf("  disassembled %zu instructions from %s\n", dis.count, path);

    fathom_cfg_t cfg;
    rc = fathom_cfg_build(&cfg, &dis);
    CHECK(rc == 0, "fathom_cfg_build should succeed on real binary");
    if (rc != 0) {
        fathom_disasm_close(&dis);
        fathom_elf_close(&elf);
        return;
    }

    printf("  blocks: %zu  edges: %zu\n", cfg.block_count, cfg.edge_count);

    /* Basic sanity: non-trivial binary should have blocks and edges */
    CHECK(cfg.block_count > 0, "block_count should be > 0");
    CHECK(cfg.edge_count > 0, "edge_count should be > 0");

    /* A binary like /bin/ls should have many blocks */
    CHECK(cfg.block_count > 10, "block_count should be > 10 for /bin/ls");
    CHECK(cfg.edge_count > 10, "edge_count should be > 10 for /bin/ls");

    /* Check that at least some loop headers were detected */
    size_t loop_headers = 0;
    for (size_t i = 0; i < cfg.block_count; i++) {
        if (cfg.blocks[i].is_loop_header)
            loop_headers++;
    }
    printf("  loop headers: %zu\n", loop_headers);
    CHECK(loop_headers > 0, "should detect at least one loop header in /bin/ls");

    /* Check dominator tree: entry block should have idom == -1 */
    CHECK(cfg.blocks[0].idom == -1, "entry block idom should be -1");

    /* Check that some blocks have non-trivial dominators */
    size_t dominated = 0;
    for (size_t i = 1; i < cfg.block_count; i++) {
        if (cfg.blocks[i].idom >= 0)
            dominated++;
    }
    printf("  blocks with idom: %zu / %zu\n", dominated, cfg.block_count - 1);
    CHECK(dominated > 0, "some blocks should have a dominator");

    /* Count back-edges */
    size_t back_edges = 0;
    for (size_t i = 0; i < cfg.edge_count; i++) {
        if (cfg.edges[i].is_back_edge)
            back_edges++;
    }
    printf("  back-edges: %zu\n", back_edges);

    /* Verify edge consistency: all edge endpoints are valid block ids */
    bool edges_valid = true;
    for (size_t i = 0; i < cfg.edge_count; i++) {
        if (cfg.edges[i].from >= cfg.block_count ||
            cfg.edges[i].to >= cfg.block_count) {
            edges_valid = false;
            break;
        }
    }
    CHECK(edges_valid, "all edge endpoints should be valid block ids");

    /* Verify block address ordering is monotonically increasing */
    bool ordering_ok = true;
    for (size_t i = 1; i < cfg.block_count; i++) {
        if (cfg.blocks[i].start_addr <= cfg.blocks[i-1].start_addr) {
            ordering_ok = false;
            break;
        }
    }
    CHECK(ordering_ok, "blocks should be in monotonically increasing address order");

    fathom_cfg_free(&cfg);
    fathom_disasm_close(&dis);
    fathom_elf_close(&elf);

    printf("  real binary test done.\n\n");
}

/* ── Test 3: Edge cases ──────────────────────────────────────────────── */

static void test_single_instruction(void)
{
    printf("=== test_single_instruction ===\n");

    fathom_insn_t insn = {
        .addr = 0x1000, .size = 1, .kind = FATHOM_INSN_RET,
        .branch_target = 0, .is_conditional = false, .mnemonic = "ret"
    };

    fathom_disasm_t dis = { .insns = &insn, .count = 1 };
    fathom_cfg_t cfg;

    int rc = fathom_cfg_build(&cfg, &dis);
    CHECK(rc == 0, "cfg_build should succeed with single instruction");
    if (rc == 0) {
        CHECK(cfg.block_count == 1, "single ret -> 1 block");
        CHECK(cfg.edge_count == 0, "single ret -> 0 edges");
        CHECK(cfg.blocks[0].idom == -1, "single block idom is -1");
        fathom_cfg_free(&cfg);
    }

    printf("  single instruction test done.\n\n");
}

static void test_empty_disasm(void)
{
    printf("=== test_empty_disasm ===\n");

    fathom_disasm_t dis = { .insns = NULL, .count = 0 };
    fathom_cfg_t cfg;

    int rc = fathom_cfg_build(&cfg, &dis);
    CHECK(rc == -1, "cfg_build should fail on empty disasm");

    printf("  empty disasm test done.\n\n");
}

static void test_cfg_free_null(void)
{
    printf("=== test_cfg_free_null ===\n");

    fathom_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Should not crash */
    fathom_cfg_free(&cfg);
    CHECK(cfg.blocks == NULL, "blocks should be NULL after free");
    CHECK(cfg.edges == NULL, "edges should be NULL after free");

    printf("  null free test done.\n\n");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("test_cfg\n\n");

    test_synthetic_cfg();
    test_real_binary_cfg();
    test_single_instruction();
    test_empty_disasm();
    test_cfg_free_null();

    if (failures > 0) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }

    printf("All checks passed.\n");
    return 0;
}
