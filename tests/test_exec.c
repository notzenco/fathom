/*
 * test_exec.c — Executor tests against the maze target.
 *
 * These run the real target under the debugger backend, so they need
 * `make targets` first (the `test` rule does this).
 */

#include "fathom.h"

#include <stdio.h>
#include <string.h>

#define MAZE "tests/targets/maze"

static int tests_run;
static int tests_passed;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("FAIL: %s\n", msg); \
            return; \
        } \
    } while (0)

static fathom_elf_t      g_elf;
static fathom_disasm_t   g_dis;
static fathom_cfg_t      g_cfg;
static fathom_coverage_t g_cov;
static fathom_exec_t     g_ex;

static size_t covered(void)
{
    size_t n = 0;
    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++)
        n += g_cov.local[i] != 0;
    return n;
}

static int setup(void)
{
    static char *argv[] = { MAZE, NULL };
    fathom_config_t cfg = {
        .target_path = MAZE,
        .target_argv = argv,
        .timeout_ms  = 2000,
    };

    if (fathom_elf_open(&g_elf, MAZE) < 0 ||
        fathom_disasm_open(&g_dis, &g_elf) < 0 ||
        fathom_cfg_build(&g_cfg, &g_dis) < 0 ||
        fathom_coverage_init(&g_cov) < 0 ||
        fathom_exec_init(&g_ex, &cfg) < 0)
        return -1;

    for (size_t i = 0; i < g_cfg.block_count && i < 4096; i++)
        fathom_exec_add_breakpoint(&g_ex, g_cfg.blocks[i].start_addr);
    return 0;
}

static void test_records_coverage(void)
{
    tests_run++;
    printf("  %-40s ", "records_block_coverage");

    fathom_exec_result_t res;
    const uint8_t in[] = "AAAA";
    CHECK(fathom_exec_run(&g_ex, &g_cov, in, 4, &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "clean input should exit normally");
    size_t base = covered();
    CHECK(base > 0, "no blocks recorded for an uninstrumented target");

    const uint8_t deeper[] = "FUZA";
    CHECK(fathom_exec_run(&g_ex, &g_cov, deeper, 4, &res) == 0, "exec failed");
    CHECK(covered() > base, "a deeper input should cover more blocks");

    tests_passed++;
    printf("PASS\n");
}

static void test_detects_crash(void)
{
    tests_run++;
    printf("  %-40s ", "detects_crash");

    fathom_exec_result_t res;
    const uint8_t in[] = "FUZZ";
    CHECK(fathom_exec_run(&g_ex, &g_cov, in, 4, &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_CRASH, "FUZZ should crash the maze");

    tests_passed++;
    printf("PASS\n");
}

int main(void)
{
    printf("=== test_exec ===\n");
    if (setup() < 0) {
        printf("setup failed (did `make targets` run?)\n");
        return 1;
    }

    test_records_coverage();
    test_detects_crash();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
