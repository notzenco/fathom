/*
 * test_exec.c — Executor tests on the native debugger backend
 *
 * Runs the maze and hang targets for real, so it needs `make targets`
 * first (the `test` rule does this).
 */

#include "fathom.h"
#include "test_util.h"

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("FAIL: %s\n", msg); \
            return; \
        } \
    } while (0)

#define BEGIN(name) \
    do { \
        tests_run++; \
        printf("  %-40s ", name); \
        fflush(stdout); \
    } while (0)

#define END() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

typedef struct {
    fathom_binary_t   bin;
    fathom_disasm_t   dis;
    fathom_cfg_t      cfg;
    fathom_analysis_t ana;
    fathom_exec_t     ex;
    char             *argv[2];
} target_t;

static fathom_coverage_t g_cov;

static int load(target_t *t, const char *path, uint32_t timeout_ms)
{
    memset(t, 0, sizeof(*t));
    t->argv[0] = (char *)path;
    fathom_config_t cfg = {
        .target_path = path,
        .target_argv = t->argv,
        .timeout_ms  = timeout_ms,
    };

    if (fathom_binary_open(&t->bin, path) < 0 ||
        fathom_disasm_open(&t->dis, &t->bin) < 0 ||
        fathom_cfg_build(&t->cfg, &t->dis) < 0 ||
        fathom_analyze(&t->ana, &t->cfg, &t->bin, &t->dis) < 0 ||
        fathom_exec_init(&t->ex, &cfg, &t->bin) < 0)
        return -1;

    for (size_t i = 0; i < t->ana.cov_count; i++) {
        uint64_t addr = t->cfg.blocks[t->ana.cov_blocks[i]].start_addr;
        if (fathom_exec_add_breakpoint(&t->ex, addr) < 0)
            return -1;
    }
    return 0;
}

static size_t covered(void)
{
    size_t n = 0;
    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++)
        n += g_cov.local[i] != 0;
    return n;
}

static int run(target_t *t, const char *input, fathom_exec_result_t *res)
{
    return fathom_exec_run(&t->ex, &g_cov, (const uint8_t *)input, strlen(input), res);
}

static void test_records_coverage(target_t *maze)
{
    BEGIN("records_block_coverage");
    fathom_exec_result_t res;

    CHECK(run(maze, "AAAA", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "clean input should exit normally");
    size_t base = covered();
    CHECK(base > 0, "no blocks recorded for an uninstrumented target");

    CHECK(run(maze, "FUZA", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "FUZA should exit normally");
    CHECK(covered() > base, "a deeper input should cover more blocks");
    END();
}

static void test_coverage_is_deterministic(target_t *maze)
{
    BEGIN("coverage_is_deterministic");
    fathom_exec_result_t res;
    uint8_t first[FATHOM_MAP_SIZE];

    CHECK(run(maze, "FUA", &res) == 0, "exec failed");
    memcpy(first, g_cov.local, sizeof(first));
    for (int i = 0; i < 20; i++) {
        CHECK(run(maze, "FUA", &res) == 0, "exec failed");
        CHECK(memcmp(first, g_cov.local, sizeof(first)) == 0,
              "same input gave different coverage");
    }
    END();
}

static void test_detects_crash(target_t *maze)
{
    BEGIN("detects_crash_with_stable_hash");
    fathom_exec_result_t a, b;

    CHECK(run(maze, "FUZZ", &a) == 0, "exec failed");
    CHECK(a.status == FATHOM_EXIT_CRASH, "FUZZ should crash the maze");
    CHECK(a.crash_pc != 0, "crash pc should map into the image");

    /* ASLR moves the image between runs; the hash must not change. */
    CHECK(run(maze, "FUZZ", &b) == 0, "exec failed");
    CHECK(b.status == FATHOM_EXIT_CRASH, "second run should crash too");
    CHECK(a.crash_hash == b.crash_hash, "crash hash differs between runs");
    CHECK(a.crash_pc == b.crash_pc, "crash pc differs between runs");
    END();
}

static void test_detects_hang(target_t *hang)
{
    BEGIN("detects_hang");
    fathom_exec_result_t res;

    CHECK(run(hang, "A", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "A should exit normally");
    CHECK(run(hang, "H", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_HANG, "H should time out");
    CHECK(run(hang, "A", &res) == 0, "exec after a hang failed");
    CHECK(res.status == FATHOM_EXIT_OK, "executor should recover after a hang");
    END();
}

int main(void)
{
    target_t maze, hang;

    printf("=== test_exec ===\n");
    if (fathom_coverage_init(&g_cov) < 0 ||
        load(&maze, TARGET("maze"), 2000) < 0 ||
        load(&hang, TARGET("hang"), 300) < 0) {
        printf("setup failed (did `make targets` run?)\n");
        return 1;
    }

    test_records_coverage(&maze);
    test_coverage_is_deterministic(&maze);
    test_detects_crash(&maze);
    test_detects_hang(&hang);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
