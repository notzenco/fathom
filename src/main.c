/*
 * main.c — CLI driver for Fathom
 *
 * Orchestrates: load binary → disassemble → CFG → analysis → fuzz loop.
 *
 * Usage:
 *   fathom [options] -- /path/to/target [target_args...]
 */

#include "fathom.h"
#include "osdep.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

/* ── Defaults ────────────────────────────────────────────────────────── */

#define FATHOM_BANNER       "fathom — coverage-guided binary fuzzer v%d.%d.%d\n"
#define DEFAULT_TIMEOUT_MS  1000
#define DEFAULT_JOBS        1
#define MAX_INPUT_SIZE      (1 << 20)   /* 1 MB max mutated input */
#define STATS_INTERVAL_US   1000000     /* status line refresh rate */
#define FATHOM_PATH_MAX     4096
#define STATS_FILE          "fuzzer_stats"
#ifdef _WIN32
#define MAX_WORKERS         MAXIMUM_WAIT_OBJECTS
#else
#define MAX_WORKERS         1024
#endif

/* ── Options ─────────────────────────────────────────────────────────── */

typedef struct {
    fathom_config_t cfg;
    uint64_t seed;
    bool     have_seed;
    uint32_t max_secs;       /* 0 = run until stopped */
    bool     until_crash;    /* stop after the first unique crash */
    int      worker_id;      /* -1 unless launched as a worker (Windows) */
    char     stop_event[64];
} fathom_opts_t;

/* ── Shutdown ────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop;

#ifdef _WIN32
static HANDLE g_stop_event;

static BOOL WINAPI console_handler(DWORD type)
{
    (void)type;
    g_stop = 1;
    return TRUE;
}

static int install_stop_handlers(void)
{
    return SetConsoleCtrlHandler(console_handler, TRUE) ? 0 : -1;
}

static bool stop_requested(void)
{
    if (!g_stop && g_stop_event && WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
        g_stop = 1;
    return g_stop;
}
#else
static volatile sig_atomic_t g_stop_signal;

static void stop_handler(int sig)
{
    g_stop = 1;
    g_stop_signal = sig;
}

static int install_stop_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;
    return 0;
}

static bool stop_requested(void)
{
    return g_stop;
}
#endif

/* ── Session state ───────────────────────────────────────────────────── */

typedef struct {
    fathom_binary_t   bin;
    fathom_disasm_t   dis;
    fathom_cfg_t      cfg_graph;
    fathom_analysis_t ana;
} fathom_session_t;

typedef struct {
    uint64_t total_execs;
    uint64_t crashes;
    uint64_t unique_crashes;
    uint64_t hangs;
    size_t   corpus_size;
    size_t   covered;
    size_t   instrumented;
    uint64_t first_crash_execs;     /* 0 until the first unique crash */
    uint64_t first_crash_ms;
    uint64_t start_us;
} fathom_stats_t;

static void cleanup_session(fathom_session_t *s)
{
    fathom_analysis_free(&s->ana);
    fathom_cfg_free(&s->cfg_graph);
    fathom_disasm_close(&s->dis);
    fathom_binary_close(&s->bin);
    memset(s, 0, sizeof(*s));
}

static void print_status(const fathom_stats_t *st, const char *prefix,
                         bool overwrite_line)
{
    double elapsed = (double)(fathom_now_us() - st->start_us) / 1e6;
    if (elapsed < 0.001)
        elapsed = 0.001;
    int secs = (int)elapsed;

    if (overwrite_line)
        fprintf(stderr, "\r\033[2K");
    if (prefix)
        fprintf(stderr, "%s ", prefix);

    fprintf(stderr,
        "[%02d:%02d:%02d] execs: %" PRIu64 " (%.0f/sec) | "
        "coverage: %zu/%zu blocks | corpus: %zu | "
        "crashes: %" PRIu64 " (%" PRIu64 " unique) | hangs: %" PRIu64,
        secs / 3600, (secs % 3600) / 60, secs % 60,
        st->total_execs, (double)st->total_execs / elapsed,
        st->covered, st->instrumented, st->corpus_size,
        st->crashes, st->unique_crashes, st->hangs);

    if (!overwrite_line)
        fputc('\n', stderr);
}

static void describe_crash(char *buf, size_t cap, uint32_t code)
{
#ifdef _WIN32
    snprintf(buf, cap, "exception=0x%08" PRIx32, code);
#else
    snprintf(buf, cap, "signal=%" PRIu32, code);
#endif
}

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_mode & S_IFDIR)
            return 0;
        fprintf(stderr, "fathom: path exists but is not a directory: %s\n", path);
        return -1;
    }
    if (fathom_mkdir(path) == 0)
        return 0;
    fprintf(stderr, "fathom: mkdir(%s): %s\n", path, strerror(errno));
    return -1;
}

static int worker_dir(char *buf, size_t cap, const char *base, uint32_t id)
{
    int n = snprintf(buf, cap, "%s/worker-%03u", base, id);
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "fathom: worker output path too long\n");
        return -1;
    }
    return 0;
}

/* Key/value stats file, read back by the parallel supervisor. */
static void write_stats(const char *dir, const fathom_stats_t *st)
{
    char path[FATHOM_PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", dir, STATS_FILE);
    FILE *fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "execs %" PRIu64 "\ncrashes %" PRIu64 "\nunique_crashes %" PRIu64
                "\nhangs %" PRIu64 "\ncorpus %zu\ncovered %zu\ninstrumented %zu\n"
                "first_crash_execs %" PRIu64 "\nfirst_crash_ms %" PRIu64 "\n",
            st->total_execs, st->crashes, st->unique_crashes, st->hangs,
            st->corpus_size, st->covered, st->instrumented,
            st->first_crash_execs, st->first_crash_ms);
    fclose(fp);
}

static bool read_stats(const char *dir, fathom_stats_t *st)
{
    char path[FATHOM_PATH_MAX + 32], key[32];
    unsigned long long val;
    bool any = false;

    memset(st, 0, sizeof(*st));
    snprintf(path, sizeof(path), "%s/%s", dir, STATS_FILE);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fscanf(fp, "%31s %llu", key, &val) == 2) {
        any = true;
        if (!strcmp(key, "execs"))               st->total_execs = val;
        else if (!strcmp(key, "crashes"))        st->crashes = val;
        else if (!strcmp(key, "unique_crashes")) st->unique_crashes = val;
        else if (!strcmp(key, "hangs"))          st->hangs = val;
        else if (!strcmp(key, "corpus"))         st->corpus_size = (size_t)val;
        else if (!strcmp(key, "covered"))        st->covered = (size_t)val;
        else if (!strcmp(key, "instrumented"))   st->instrumented = (size_t)val;
    }
    fclose(fp);
    return any;
}

static int prepare_session(const fathom_config_t *cfg, bool quiet,
                           fathom_session_t *s)
{
    memset(s, 0, sizeof(*s));

    if (fathom_binary_open(&s->bin, cfg->target_path) < 0)
        return -1;
    if (!quiet)
        fprintf(stderr, "  binary: %s %s%s, entry 0x%" PRIx64 "\n",
                fathom_format_name(s->bin.format), fathom_arch_name(s->bin.arch),
                s->bin.relocatable ? " (relocatable)" : "", s->bin.entry);

    if (fathom_disasm_open(&s->dis, &s->bin) < 0) {
        fprintf(stderr, "fathom: disassembly failed\n");
        goto fail;
    }
    if (fathom_cfg_build(&s->cfg_graph, &s->dis) < 0) {
        fprintf(stderr, "fathom: CFG build failed\n");
        goto fail;
    }
    if (fathom_analyze(&s->ana, &s->cfg_graph, &s->bin, &s->dis) < 0) {
        fprintf(stderr, "fathom: analysis failed\n");
        goto fail;
    }
    if (!quiet)
        fprintf(stderr, "  instructions: %zu, blocks: %zu (%zu instrumentable), "
                        "scored: %zu, dictionary: %zu\n",
                s->dis.count, s->cfg_graph.block_count, s->ana.cov_count,
                s->ana.ranked_count, s->ana.dict.count);

    if (cfg->dict_file && fathom_dict_load(&s->ana.dict, cfg->dict_file) < 0) {
        fprintf(stderr, "fathom: failed to load dictionary: %s\n", cfg->dict_file);
        goto fail;
    }
    return 0;

fail:
    cleanup_session(s);
    return -1;
}

/* ── Usage ───────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] -- /path/to/target [target_args...]\n"
        "\n"
        "Options:\n"
        "  -i <dir>    Input corpus (seeds)\n"
        "  -o <dir>    Output directory (default: ./fathom-out)\n"
        "  -t <ms>     Timeout per exec (default: %d)\n"
        "  -j <n>      Parallel instances (default: %d)\n"
        "  -T <secs>   Stop after this many seconds (default: run until Ctrl-C)\n"
        "  -s <seed>   Random seed, for reproducible runs\n"
        "  --until-crash  Stop after the first unique crash\n"
        "  -a          Analysis-only mode (print CFG + scores, no fuzzing)\n"
        "  -v          Verbose output\n"
        "  --dict <f>  Extra dictionary file\n"
        "  -h          Show this help\n",
        prog, DEFAULT_TIMEOUT_MS, DEFAULT_JOBS);
}

/* ── Analysis-only mode ──────────────────────────────────────────────── */

static int run_analysis(const fathom_config_t *cfg)
{
    fathom_session_t s;
    if (prepare_session(cfg, true, &s) < 0)
        return 1;
    fathom_analysis_print(&s.ana, &s.bin, &s.dis);
    cleanup_session(&s);
    return 0;
}

/*
 * Constants compared in covered blocks whose conditional branch still
 * has an uncovered side: the values most likely to unlock new code.
 * Statically linked runtimes (MinGW, musl) bury the target's own
 * comparisons among hundreds of library ones in the static dictionary.
 */
static void rebuild_frontier(fathom_dict_t *frontier, const fathom_session_t *s,
                             const fathom_coverage_t *cov, const uint32_t *slot_block,
                             const int32_t *block_slot, size_t slots)
{
    fathom_dict_destroy(frontier);
    fathom_dict_init(frontier);

    for (size_t slot = 0; slot < slots && frontier->count < 256; slot++) {
        if (!cov->global[slot])
            continue;
        const fathom_block_t *b = &s->cfg_graph.blocks[slot_block[slot]];
        const fathom_insn_t *insns = &s->dis.insns[b->insn_start];
        const fathom_insn_t *last = &insns[b->insn_count - 1];
        if (last->kind != FATHOM_INSN_BRANCH || !last->is_conditional)
            continue;

        bool open = false;
        for (size_t i = 0; i < b->succ_count; i++) {
            int32_t succ = block_slot[b->succs[i]];
            open |= succ < 0 || !cov->global[succ];
        }
        for (size_t i = 0; open && i < b->insn_count; i++) {
            if (insns[i].has_cmp_imm)
                fathom_dict_add_constant(frontier, insns[i].cmp_imm);
        }
    }
}

/* ── Worker fuzz loop ────────────────────────────────────────────────── */

static int run_worker(const fathom_opts_t *opts, const fathom_config_t *cfg,
                      fathom_session_t *session, int worker_id, bool multi)
{
    int ret = 1;
    char prefix_buf[16];
    const char *prefix = NULL;
    fathom_coverage_t cov;
    fathom_corpus_t corpus;
    fathom_exec_t ex;
    fathom_mutator_t mut;
    bool cov_ready = false, corpus_ready = false, ex_ready = false;
    uint8_t *buf = NULL;
    uint32_t *slot_block = NULL;
    int32_t *block_slot = NULL;
    fathom_dict_t frontier;
    fathom_stats_t stats;

    memset(&stats, 0, sizeof(stats));
    if (multi) {
        snprintf(prefix_buf, sizeof(prefix_buf), "[w%03d]", worker_id);
        prefix = prefix_buf;
    }

    if (install_stop_handlers() < 0) {
        fprintf(stderr, "fathom: cannot install stop handlers\n");
        return 1;
    }

    if (fathom_coverage_init(&cov) < 0) {
        fprintf(stderr, "fathom: coverage init failed\n");
        goto cleanup;
    }
    cov_ready = true;

    if (fathom_corpus_init(&corpus, cfg->input_dir, cfg->output_dir) < 0) {
        fprintf(stderr, "fathom: corpus init failed\n");
        goto cleanup;
    }
    corpus_ready = true;
    if (corpus.count == 0 && fathom_corpus_add(&corpus, (const uint8_t *)"AAAA", 4, 0, 0) < 0)
        goto cleanup;

    fathom_dict_init(&frontier);
    fathom_mutator_init(&mut, &session->ana.dict);
    mut.frontier = &frontier;
    if (opts->have_seed)
        fathom_mutator_seed(&mut, opts->seed + (uint64_t)worker_id);

    if (fathom_exec_init(&ex, cfg, &session->bin) < 0) {
        fprintf(stderr, "fathom: executor init failed\n");
        goto cleanup;
    }
    ex_ready = true;

    /* One breakpoint per instrumentable block; slot i ↔ cov_blocks[i]. */
    slot_block = malloc((session->ana.cov_count + 1) * sizeof(*slot_block));
    block_slot = malloc((session->cfg_graph.block_count + 1) * sizeof(*block_slot));
    if (!slot_block || !block_slot)
        goto cleanup;
    for (size_t i = 0; i < session->cfg_graph.block_count; i++)
        block_slot[i] = -1;
    for (size_t i = 0; i < session->ana.cov_count; i++) {
        uint32_t bid = session->ana.cov_blocks[i];
        int slot = fathom_exec_add_breakpoint(&ex, session->cfg_graph.blocks[bid].start_addr);
        if (slot < 0) {
            fprintf(stderr, "fathom: breakpoint setup failed\n");
            goto cleanup;
        }
        slot_block[slot] = bid;
        block_slot[bid] = slot;
    }
    stats.instrumented = ex.bp_count;

    if (!multi)
        fprintf(stderr, "  seeds: %zu, breakpoints: %zu\n\nfuzzing started%s...\n\n",
                corpus.count, ex.bp_count,
                opts->max_secs ? "" : " (Ctrl-C to stop)");
    else if (cfg->verbose)
        fprintf(stderr, "%s seeds: %zu, output: %s\n", prefix, corpus.count, cfg->output_dir);

    buf = malloc(MAX_INPUT_SIZE);
    if (!buf) {
        fprintf(stderr, "fathom: out of memory\n");
        goto cleanup;
    }

    stats.corpus_size = corpus.count;
    stats.start_us = fathom_now_us();
    uint64_t last_status = stats.start_us;
    uint64_t deadline = opts->max_secs
                      ? stats.start_us + (uint64_t)opts->max_secs * 1000000u : 0;

    while (!stop_requested()) {
        uint64_t now = fathom_now_us();
        if (deadline && now >= deadline)
            break;
        if (now - last_status >= STATS_INTERVAL_US) {
            print_status(&stats, prefix, !multi);
            last_status = now;
        }

        fathom_input_t *seed = fathom_corpus_next(&corpus);
        size_t len = seed->len < MAX_INPUT_SIZE ? seed->len : MAX_INPUT_SIZE;
        memcpy(buf, seed->data, len);

        const fathom_input_t *donor =
            &corpus.inputs[fathom_rand_below(&mut, (uint32_t)corpus.count)];
        bool can_splice = corpus.count > 1 && donor != seed;
        int strategy = fathom_mutate(&mut, buf, &len, MAX_INPUT_SIZE,
                                     can_splice ? donor->data : NULL,
                                     can_splice ? donor->len : 0);

        fathom_exec_result_t result;
        stats.total_execs++;
        if (fathom_exec_run(&ex, &cov, buf, len, &result) < 0) {
            fprintf(stderr, "%sfathom: target execution failed\n", multi ? "" : "\n");
            goto cleanup;
        }

        if (fathom_coverage_has_new(&cov)) {
            /* Weight new blocks by their static score before merging. */
            double score = 0.0;
            for (size_t s = 0; s < ex.bp_count; s++) {
                if (cov.local[s] && !cov.global[s])
                    score += session->cfg_graph.blocks[slot_block[s]].score;
            }
            fathom_coverage_merge(&cov);
            stats.covered = cov.total_blocks;
            rebuild_frontier(&frontier, session, &cov, slot_block, block_slot, ex.bp_count);

            if (fathom_corpus_add(&corpus, buf, len, cov.new_blocks, score) < 0) {
                fprintf(stderr, "fathom: failed to add interesting input\n");
                goto cleanup;
            }
            stats.corpus_size = corpus.count;
            if (strategy >= 0 && strategy < FATHOM_MUT_COUNT)
                fathom_mutator_reward(&mut, (fathom_mutation_t)strategy);
        }

        if (result.status == FATHOM_EXIT_CRASH) {
            stats.crashes++;
            size_t prev = corpus.unique_crashes;
            if (fathom_corpus_save_crash(&corpus, buf, len, result.crash_hash) < 0) {
                fprintf(stderr, "fathom: failed to save crash\n");
                goto cleanup;
            }
            stats.unique_crashes = corpus.unique_crashes;
            if (corpus.unique_crashes > prev && stats.first_crash_execs == 0) {
                stats.first_crash_execs = stats.total_execs;
                stats.first_crash_ms = (fathom_now_us() - stats.start_us) / 1000;
            }
            if (corpus.unique_crashes > prev) {
                char what[48];
                describe_crash(what, sizeof(what), result.crash_code);
                if (multi)
                    fprintf(stderr, "%s new crash: %s pc=0x%" PRIx64 " hash=0x%016" PRIx64 "\n",
                            prefix, what, result.crash_pc, result.crash_hash);
                else
                    fprintf(stderr, "\n*** NEW CRASH: %s pc=0x%" PRIx64 " hash=0x%016" PRIx64 " ***\n",
                            what, result.crash_pc, result.crash_hash);
            }
            if (opts->until_crash && corpus.unique_crashes > 0)
                break;
        } else if (result.status == FATHOM_EXIT_HANG) {
            stats.hangs++;
        }
    }

    if (!multi) {
        fprintf(stderr, "\n\n=== Fathom session complete ===\n");
        fprintf(stderr, "  total execs:    %" PRIu64 "\n", stats.total_execs);
        fprintf(stderr, "  coverage:       %zu/%zu blocks\n", stats.covered, stats.instrumented);
        fprintf(stderr, "  corpus size:    %zu\n", corpus.count);
        fprintf(stderr, "  crashes:        %" PRIu64 " (%" PRIu64 " unique)\n",
                stats.crashes, stats.unique_crashes);
        fprintf(stderr, "  hangs:          %" PRIu64 "\n", stats.hangs);
        fprintf(stderr, "  output dir:     %s\n", cfg->output_dir);
    }
    ret = 0;

cleanup:
    if (corpus_ready) {
        stats.corpus_size = corpus.count;
        write_stats(cfg->output_dir, &stats);
    }
    free(buf);
    free(slot_block);
    free(block_slot);
    fathom_dict_destroy(&frontier);
    if (ex_ready)
        fathom_exec_destroy(&ex);
    if (corpus_ready)
        fathom_corpus_destroy(&corpus);
    if (cov_ready)
        fathom_coverage_destroy(&cov);
    return ret;
}

/* ── Parallel supervisor ─────────────────────────────────────────────── */

#ifdef _WIN32

/* Windows has no fork: re-run this executable once per worker. */
static int spawn_workers(const fathom_opts_t *opts, int argc, char **argv,
                         HANDLE *procs, uint32_t jobs)
{
    char exe[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exe, sizeof(exe)))
        return 0;

    /* exe --worker <id>:<stop event> <original arguments...> */
    char **wargv = calloc((size_t)argc + 3, sizeof(*wargv));
    char idarg[96];
    if (!wargv)
        return 0;
    wargv[0] = exe;
    wargv[1] = "--worker";
    wargv[2] = idarg;
    for (int a = 1; a < argc; a++)
        wargv[a + 2] = argv[a];

    uint32_t launched = 0;
    for (uint32_t i = 0; i < jobs; i++) {
        snprintf(idarg, sizeof(idarg), "%u:%s", i, opts->stop_event);
        char *cmd = fathom_win_cmdline(wargv);
        if (!cmd)
            break;

        STARTUPINFOA si = { .cb = sizeof(si) };
        PROCESS_INFORMATION pi;
        BOOL started = CreateProcessA(exe, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        free(cmd);
        if (!started) {
            fprintf(stderr, "fathom: cannot start worker %u (%lu)\n", i, GetLastError());
            break;
        }
        CloseHandle(pi.hThread);
        procs[launched++] = pi.hProcess;
    }
    free(wargv);
    return (int)launched;
}

static bool supervise(const fathom_opts_t *opts, int argc, char **argv, uint32_t jobs)
{
    HANDLE procs[MAX_WORKERS];
    bool failed = false;

    g_stop_event = CreateEventA(NULL, TRUE, FALSE, opts->stop_event);
    int launched = spawn_workers(opts, argc, argv, procs, jobs);
    if ((uint32_t)launched < jobs)
        failed = true;

    bool signalled = false;
    for (int alive = launched; alive > 0;) {
        if ((stop_requested() || failed) && !signalled) {
            SetEvent(g_stop_event);
            signalled = true;
        }
        DWORD w = WaitForMultipleObjects((DWORD)launched, procs, FALSE, 200);
        if (w < WAIT_OBJECT_0 + (DWORD)launched) {   /* WAIT_OBJECT_0 is 0 */
            DWORD idx = w - WAIT_OBJECT_0, code = 1;
            GetExitCodeProcess(procs[idx], &code);
            failed |= code != 0;
            CloseHandle(procs[idx]);
            procs[idx] = procs[--launched];
            alive--;
        }
    }
    CloseHandle(g_stop_event);
    return !failed;
}

#else

static bool supervise(const fathom_opts_t *opts, const fathom_config_t *cfg,
                      fathom_session_t *session, uint32_t jobs)
{
    pid_t pids[MAX_WORKERS];
    uint32_t launched = 0, alive;
    bool failed = false, forwarded = false;

    for (uint32_t i = 0; i < jobs; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fathom: fork");
            failed = true;
            break;
        }
        if (pid == 0) {
            char dir[FATHOM_PATH_MAX];
            fathom_config_t wcfg = *cfg;
            if (worker_dir(dir, sizeof(dir), cfg->output_dir, i) < 0)
                _exit(1);
            wcfg.output_dir = dir;
            wcfg.jobs = 1;
            _exit(run_worker(opts, &wcfg, session, (int)i, true));
        }
        pids[launched++] = pid;
    }

    for (alive = launched; alive > 0;) {
        if ((g_stop || failed) && !forwarded) {
            int sig = g_stop_signal ? (int)g_stop_signal : SIGTERM;
            for (uint32_t i = 0; i < launched; i++) {
                if (pids[i] > 0)
                    kill(pids[i], sig);
            }
            forwarded = true;
        }

        int status;
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (uint32_t i = 0; i < launched; i++) {
            if (pids[i] == pid) {
                pids[i] = -1;
                alive--;
                failed |= !WIFEXITED(status) || WEXITSTATUS(status) != 0;
            }
        }
    }
    return !failed;
}

#endif

static int run_parallel(const fathom_opts_t *opts, int argc, char **argv,
                        fathom_session_t *session)
{
    const fathom_config_t *cfg = &opts->cfg;
    uint32_t jobs = cfg->jobs;

    if (jobs > MAX_WORKERS) {
        fprintf(stderr, "fathom: at most %d workers are supported\n", MAX_WORKERS);
        return 1;
    }
    if (ensure_dir(cfg->output_dir) < 0 || install_stop_handlers() < 0)
        return 1;

    fprintf(stderr, "  workers: %u\n\nstarting %u workers%s...\n\n", jobs, jobs,
            opts->max_secs ? "" : " (Ctrl-C to stop)");
    fflush(stderr);

#ifdef _WIN32
    (void)session;
    bool ok = supervise(opts, argc, argv, jobs);
#else
    (void)argc;
    (void)argv;
    bool ok = supervise(opts, cfg, session, jobs);
#endif

    fathom_stats_t total, w;
    memset(&total, 0, sizeof(total));
    fprintf(stderr, "\n=== Fathom session complete ===\n  workers:        %u\n", jobs);

    char lines[MAX_WORKERS][160];
    for (uint32_t i = 0; i < jobs; i++) {
        char dir[FATHOM_PATH_MAX];
        if (worker_dir(dir, sizeof(dir), cfg->output_dir, i) < 0 || !read_stats(dir, &w)) {
            snprintf(lines[i], sizeof(lines[i]), "    worker-%03u: no report", i);
            continue;
        }
        total.total_execs += w.total_execs;
        total.crashes += w.crashes;
        total.hangs += w.hangs;
        snprintf(lines[i], sizeof(lines[i]),
                 "    worker-%03u: coverage=%zu/%zu blocks | corpus=%zu | crashes=%" PRIu64,
                 i, w.covered, w.instrumented, w.corpus_size, w.unique_crashes);
    }

    fprintf(stderr, "  total execs:    %" PRIu64 "\n", total.total_execs);
    fprintf(stderr, "  crashes:        %" PRIu64 "\n", total.crashes);
    fprintf(stderr, "  hangs:          %" PRIu64 "\n", total.hangs);
    fprintf(stderr, "  output dir:     %s\n  worker stats:\n", cfg->output_dir);
    for (uint32_t i = 0; i < jobs; i++)
        fprintf(stderr, "%s\n", lines[i]);

    return ok ? 0 : 1;
}

/* ── Main ────────────────────────────────────────────────────────────── */

static uint32_t parse_u32(const char *s, const char *what, bool *ok)
{
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno || *end || v > UINT32_MAX) {
        fprintf(stderr, "fathom: invalid %s: %s\n", what, s);
        *ok = false;
    }
    return (uint32_t)v;
}

int main(int argc, char *argv[])
{
    fathom_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.worker_id = -1;
    opts.cfg.output_dir = "./fathom-out";
    opts.cfg.timeout_ms = DEFAULT_TIMEOUT_MS;
    opts.cfg.jobs = DEFAULT_JOBS;
    bool ok = true;

    static struct option long_opts[] = {
        {"dict",     required_argument, NULL, 'D'},
        {"help",     no_argument,       NULL, 'h'},
        {"max-time", required_argument, NULL, 'T'},
        {"seed",     required_argument, NULL, 's'},
        {"until-crash", no_argument,    NULL, 'U'},
        {"worker",   required_argument, NULL, 'W'},   /* internal (Windows) */
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+i:o:t:j:T:s:avh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': opts.cfg.input_dir  = optarg; break;
        case 'o': opts.cfg.output_dir = optarg; break;
        case 't': opts.cfg.timeout_ms = parse_u32(optarg, "timeout", &ok); break;
        case 'j': opts.cfg.jobs       = parse_u32(optarg, "job count", &ok); break;
        case 'T': opts.max_secs       = parse_u32(optarg, "time limit", &ok); break;
        case 's':
            opts.seed = strtoull(optarg, NULL, 0);
            opts.have_seed = true;
            break;
        case 'U': opts.until_crash = true; break;
        case 'a': opts.cfg.analysis_only = true; break;
        case 'v': opts.cfg.verbose = true; break;
        case 'D': opts.cfg.dict_file = optarg; break;
        case 'W': {
            unsigned id = 0;
            char ev[64] = "";
            if (sscanf(optarg, "%u:%63s", &id, ev) != 2) {
                ok = false;
                break;
            }
            opts.worker_id = (int)id;
            snprintf(opts.stop_event, sizeof(opts.stop_event), "%s", ev);
            break;
        }
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!ok)
        return 1;
    if (opts.cfg.jobs == 0) {
        fprintf(stderr, "fathom: -j must be at least 1\n");
        return 1;
    }
    if (optind >= argc) {
        fprintf(stderr, "fathom: no target specified\n\n");
        usage(argv[0]);
        return 1;
    }

    opts.cfg.target_path = argv[optind];
    opts.cfg.target_argv = &argv[optind];

    bool worker = opts.worker_id >= 0;
    if (!worker) {
        fprintf(stderr, FATHOM_BANNER,
                FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR, FATHOM_VERSION_PATCH);
        fprintf(stderr, "target: %s\n", opts.cfg.target_path);
    }
    if (opts.cfg.analysis_only)
        return run_analysis(&opts.cfg);

    fathom_session_t session;
    if (prepare_session(&opts.cfg, worker, &session) < 0)
        return 1;

    int ret;
    if (worker) {
#ifdef _WIN32
        char dir[FATHOM_PATH_MAX];
        fathom_config_t wcfg = opts.cfg;
        g_stop_event = OpenEventA(SYNCHRONIZE, FALSE, opts.stop_event);
        ret = worker_dir(dir, sizeof(dir), opts.cfg.output_dir, (uint32_t)opts.worker_id);
        if (ret == 0) {
            wcfg.output_dir = dir;
            wcfg.jobs = 1;
            ret = run_worker(&opts, &wcfg, &session, opts.worker_id, true);
        }
#else
        ret = 1;   /* POSIX workers are forked, never launched by flag */
#endif
    } else if (opts.cfg.jobs > 1) {
#ifdef _WIN32
        snprintf(opts.stop_event, sizeof(opts.stop_event), "Local\\fathom-stop-%lu",
                 GetCurrentProcessId());
#endif
        ret = run_parallel(&opts, argc, argv, &session);
    } else {
        ret = run_worker(&opts, &opts.cfg, &session, 0, false);
    }

    cleanup_session(&session);
    return ret;
}
