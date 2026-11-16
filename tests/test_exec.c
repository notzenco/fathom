/*
 * test_exec.c — Executor tests on the native debugger backend
 *
 * Runs the maze and hang targets for real, so it needs `make targets`
 * first (the `test` rule does this).
 */

#include "fathom.h"
#include "test_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

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
        fathom_cfg_build(&t->cfg, &t->dis, &t->bin) < 0 ||
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

static void free_target(target_t *t)
{
    fathom_exec_destroy(&t->ex);
    fathom_analysis_free(&t->ana);
    fathom_cfg_free(&t->cfg);
    fathom_disasm_close(&t->dis);
    fathom_binary_close(&t->bin);
}

static size_t covered(void)
{
    size_t n = 0;
    for (size_t i = 0; i < g_cov.size; i++)
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
    uint8_t *first = malloc(g_cov.size);

    CHECK(run(maze, "FUA", &res) == 0, "exec failed");
    memcpy(first, g_cov.local, g_cov.size);
    for (int i = 0; i < 20; i++) {
        CHECK(run(maze, "FUA", &res) == 0, "exec failed");
        CHECK(memcmp(first, g_cov.local, g_cov.size) == 0,
              "same input gave different coverage");
    }
    free(first);
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

/* The breakpoint table has no fixed size; slots stay stable as it grows. */
static void test_many_breakpoints(void)
{
    BEGIN("breakpoint_table_grows");
    target_t t;
    CHECK(load(&t, TARGET("maze"), 2000) == 0, "load failed");
    size_t base = t.ex.bp_count;
    const size_t extra = 100000;
    for (size_t i = 0; i < extra; i++) {
        int slot = fathom_exec_add_breakpoint(&t.ex, 0x7f0000000000ull + 4 * i);
        CHECK(slot == (int)(base + i), "new address got an unexpected slot");
    }
    CHECK(fathom_exec_add_breakpoint(&t.ex, 0x7f0000000000ull) == (int)base,
          "a known address must keep its slot");
    CHECK(t.ex.bp_count == base + extra, "breakpoint count");
    free_target(&t);
    END();
}

/* Load path with its own coverage map sized to its breakpoints. */
static int load_cov(target_t *t, fathom_coverage_t *cov, const char *path)
{
    if (load(t, path, 2000) < 0)
        return -1;
    return fathom_coverage_init(cov, t->ex.bp_count);
}

static void unload(target_t *t, fathom_coverage_t *cov)
{
    free_target(t);
    fathom_coverage_destroy(cov);
}

static int run_cov(target_t *t, fathom_coverage_t *cov, const char *input,
                   fathom_exec_result_t *res)
{
    return fathom_exec_run(&t->ex, cov, (const uint8_t *)input, strlen(input), res);
}

/*
 * A block that itself starts with the breakpoint instruction is the
 * target's own trap: it must kill the target, not loop until timeout.
 */
static void test_original_trap(void)
{
    BEGIN("target_trap_is_not_a_breakpoint");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("trap_block")) == 0, "load failed");
    CHECK(run_cov(&t, &cov, "A", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "clean input should exit normally");
    CHECK(run_cov(&t, &cov, "T", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_CRASH, "an executed trap should be a crash");
    unload(&t, &cov);
    END();
}

/* A fault the target's own handler recovers from is not a crash. */
static void test_recovered_fault(void)
{
    BEGIN("recovered_fault_is_not_a_crash");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("sig_recover")) == 0, "load failed");
    CHECK(run_cov(&t, &cov, "A", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "a recovered fault should exit normally");
    CHECK(run_cov(&t, &cov, "C", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_CRASH, "an unhandled fault should be a crash");
    CHECK(res.crash_pc != 0, "crash PC should be inside the image");
    unload(&t, &cov);
    END();
}

/* Loop headers count iterations, so a different trip count is new coverage. */
static void test_loop_counts(void)
{
    BEGIN("loop_iterations_are_coverage");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("loop_count")) == 0, "load failed");
    for (size_t i = 0; i < t.ana.cov_count; i++) {
        const fathom_block_t *b = &t.cfg.blocks[t.ana.cov_blocks[i]];
        if (b->is_loop_header && b->insn_count > 1)
            fathom_exec_count_hits(&t.ex, (int)i, t.dis.insns[b->insn_start + 1].addr);
    }
    CHECK(run_cov(&t, &cov, "1", &res) == 0 && res.status == FATHOM_EXIT_OK, "exec failed");
    fathom_coverage_merge(&cov);
    CHECK(run_cov(&t, &cov, "1", &res) == 0, "exec failed");
    CHECK(!fathom_coverage_has_new(&cov), "same trip count is not new");
    CHECK(run_cov(&t, &cov, "5", &res) == 0 && res.status == FATHOM_EXIT_OK, "exec failed");
    CHECK(fathom_coverage_has_new(&cov), "a longer loop should be new coverage");
    fathom_coverage_merge(&cov);
    CHECK(run_cov(&t, &cov, "9", &res) == 0 && res.status == FATHOM_EXIT_OK, "exec failed");
    CHECK(fathom_coverage_has_new(&cov), "past the 4-7 bucket should be new coverage");
    unload(&t, &cov);
    END();
}

/* Disarmed breakpoints cost nothing; only blocks still armed report. */
static void test_disarm(void)
{
    BEGIN("disarmed_blocks_do_not_trap");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("maze")) == 0, "load failed");
    CHECK(run_cov(&t, &cov, "FUZA", &res) == 0 && res.status == FATHOM_EXIT_OK, "exec failed");
    size_t full = 0;
    for (size_t i = 0; i < cov.size; i++) {
        if (cov.local[i]) {
            full++;
            fathom_exec_arm(&t.ex, (int)i, false);
        }
    }
    CHECK(full > 0, "no coverage");

    CHECK(run_cov(&t, &cov, "FUZA", &res) == 0 && res.status == FATHOM_EXIT_OK, "exec failed");
    bool any = false;
    for (size_t i = 0; i < cov.size; i++)
        any |= cov.local[i] != 0;
    CHECK(!any, "a disarmed block still trapped");

    CHECK(run_cov(&t, &cov, "FUZZ", &res) == 0 && res.status == FATHOM_EXIT_CRASH, "exec failed");
    any = false;
    for (size_t i = 0; i < cov.size; i++)
        any |= cov.local[i] != 0;
    CHECK(any, "the newly reached block did not trap");

    for (size_t i = 0; i < cov.size; i++)
        fathom_exec_arm(&t.ex, (int)i, true);
    CHECK(run_cov(&t, &cov, "FUZA", &res) == 0, "exec failed");
    size_t again = 0;
    for (size_t i = 0; i < cov.size; i++)
        again += cov.local[i] != 0;
    CHECK(again == full, "re-armed blocks should trap again");
    unload(&t, &cov);
    END();
}

/* `@@` in the arguments becomes the input file's path; stdin is empty. */
static void test_file_input(void)
{
    BEGIN("input_file_argument");
    target_t t;
    fathom_exec_result_t res;
    memset(&t, 0, sizeof(t));
    char *argv[] = { (char *)TARGET("file_input"), "--in=@@", NULL };
    fathom_config_t cfg = { .target_path = argv[0], .target_argv = argv, .timeout_ms = 2000 };
    CHECK(fathom_binary_open(&t.bin, argv[0]) == 0 &&
          fathom_exec_init(&t.ex, &cfg, &t.bin) == 0, "load failed");
    CHECK(fathom_exec_run(&t.ex, NULL, (const uint8_t *)"A", 1, &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "the target did not get a readable file");
    CHECK(fathom_exec_run(&t.ex, NULL, (const uint8_t *)"C", 1, &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_CRASH, "the file did not hold the input");
    fathom_exec_destroy(&t.ex);
    fathom_binary_close(&t.bin);
    END();
}

/* Minimising keeps the crash, not just any crash. */
static void test_minimize(void)
{
    BEGIN("minimize_keeps_crash");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("maze")) == 0, "load failed");
    const char *in = "FUZZ-padding-that-does-not-matter-at-all";
    CHECK(run_cov(&t, &cov, in, &res) == 0 && res.status == FATHOM_EXIT_CRASH, "no crash");

    uint8_t buf[64];
    size_t len = strlen(in);
    memcpy(buf, in, len);
    uint64_t execs = 0;
    CHECK(fathom_minimize(&t.ex, &cov, buf, &len, res.crash_hash, 1000, &execs) == 0,
          "minimize failed");
    CHECK(len == 4 && memcmp(buf, "FUZZ", 4) == 0, "not minimal");
    unload(&t, &cov);
    END();
}

/* Trimming drops bytes that do not change the path. */
static void test_trim(void)
{
    BEGIN("trim_keeps_path");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("maze")) == 0, "load failed");
    const char *in = "FUZAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    CHECK(run_cov(&t, &cov, in, &res) == 0, "exec failed");
    uint64_t want = fathom_coverage_hash(&cov);

    uint8_t buf[128];
    size_t len = strlen(in);
    memcpy(buf, in, len);
    uint64_t execs = 0;
    CHECK(fathom_trim(&t.ex, &cov, buf, &len, want, 1000, &execs) == 0, "trim failed");
    CHECK(len < 16, "trailing bytes were not trimmed");
    CHECK(len >= 4 && memcmp(buf, "FUZ", 3) == 0, "trim changed the path");
    unload(&t, &cov);
    END();
}

#ifndef _WIN32
/* Coverage and crash attribution continue after the target re-executes itself. */
static void test_reexec(void)
{
    BEGIN("coverage_survives_reexec");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("reexec")) == 0, "load failed");
    CHECK(run_cov(&t, &cov, "A", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "clean input should exit normally");
    uint8_t *clean = malloc(cov.size);
    memcpy(clean, cov.local, cov.size);
    CHECK(run_cov(&t, &cov, "C", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_CRASH, "crash after re-exec not detected");
    bool fresh = false;
    for (size_t i = 0; i < cov.size; i++)
        fresh |= cov.local[i] && !clean[i];
    free(clean);
    CHECK(fresh, "blocks after the exec were not covered");
    unload(&t, &cov);
    END();
}

static bool process_named(const char *name)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s >/dev/null 2>&1", name);
    return system(cmd) == 0;
}

/* Children run the same code, and none outlive the run. */
static void test_forked_children(void)
{
    BEGIN("forked_children_run_and_are_killed");
    target_t t;
    fathom_coverage_t cov;
    fathom_exec_result_t res;
    CHECK(load_cov(&t, &cov, TARGET("fork_child")) == 0, "load failed");
    CHECK(run_cov(&t, &cov, "A", &res) == 0, "exec failed");
    CHECK(res.status == FATHOM_EXIT_OK, "the child died running instrumented code");
    CHECK(run_cov(&t, &cov, "S", &res) == 0, "exec failed");
    bool alive = true;
    for (int i = 0; i < 20 && (alive = process_named("fork_child")); i++)
        usleep(50 * 1000);
    unload(&t, &cov);
    CHECK(!alive, "a child process outlived the run");
    END();
}
#endif

static void test_reaps_targets(target_t *maze)
{
    BEGIN("leaves_no_unreaped_targets");
#ifndef _WIN32
    fathom_exec_result_t res;
    for (int i = 0; i < 20; i++)
        CHECK(run(maze, i % 2 ? "FUZZ" : "AAAA", &res) == 0, "exec failed");
    /* Every target must be reaped, or a long run exhausts the process table. */
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD,
          "a finished target was left as a zombie");
#else
    (void)maze;
#endif
    END();
}

int main(void)
{
    target_t maze, hang;

    printf("=== test_exec ===\n");
    if (load(&maze, TARGET("maze"), 2000) < 0 ||
        load(&hang, TARGET("hang"), 300) < 0 ||
        fathom_coverage_init(&g_cov, maze.ex.bp_count > hang.ex.bp_count
                                     ? maze.ex.bp_count : hang.ex.bp_count) < 0) {
        printf("setup failed (did `make targets` run?)\n");
        return 1;
    }

    test_records_coverage(&maze);
    test_coverage_is_deterministic(&maze);
    test_detects_crash(&maze);
    test_detects_hang(&hang);
    test_reaps_targets(&maze);
    test_many_breakpoints();
    test_original_trap();
    test_recovered_fault();
    test_trim();
    test_loop_counts();
    test_disarm();
    test_file_input();
    test_minimize();
#ifndef _WIN32
    test_reexec();
    test_forked_children();
#endif

    free_target(&maze);
    free_target(&hang);
    fathom_coverage_destroy(&g_cov);
    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
