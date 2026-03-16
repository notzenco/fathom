/*
 * main.c — CLI driver for Fathom
 *
 * Orchestrates: ELF parse → disassemble → CFG build → analysis → fuzz loop.
 *
 * Usage:
 *   fathom [options] -- /path/to/target [target_args...]
 */

#include "fathom.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── Banner ──────────────────────────────────────────────────────────── */

#define FATHOM_BANNER \
    "fathom — hybrid coverage-guided fuzzer v%d.%d.%d\n"

/* ── Defaults ────────────────────────────────────────────────────────── */

#define DEFAULT_TIMEOUT_MS  1000
#define DEFAULT_JOBS        1
#define MAX_INPUT_SIZE      (1 << 20)   /* 1 MB max mutated input */
#define STATS_INTERVAL_MS   1000        /* status line refresh rate */
#define MAX_BREAKPOINTS     256         /* top-scored blocks to instrument */
#define FATHOM_PATH_MAX     4096

/* ── Volatile flags for shutdown ─────────────────────────────────────── */

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_stop_signal;

static void stop_handler(int sig)
{
    g_stop = 1;
    g_stop_signal = sig;
}

/* ── Session state ───────────────────────────────────────────────────── */

typedef struct {
    fathom_elf_t      elf;
    fathom_disasm_t   dis;
    fathom_cfg_t      cfg_graph;
    fathom_analysis_t ana;
} fathom_session_t;

typedef struct {
    uint64_t total_execs;
    uint64_t crashes;
    uint64_t unique_crashes;
    uint64_t hangs;
    uint64_t last_new_cov_exec;
    size_t   corpus_size;
    size_t   total_edges;
    struct timeval start;
} fathom_stats_t;

typedef struct {
    uint64_t total_execs;
    uint64_t crashes;
    uint64_t unique_crashes;
    uint64_t hangs;
    size_t   corpus_size;
    size_t   total_edges;
    int      exit_code;
} fathom_worker_report_t;

/* ── Helpers ─────────────────────────────────────────────────────────── */

static int install_stop_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;

    return 0;
}

static void cleanup_session(fathom_session_t *session)
{
    fathom_analysis_free(&session->ana);
    fathom_cfg_free(&session->cfg_graph);
    fathom_disasm_close(&session->dis);
    fathom_elf_close(&session->elf);
    memset(session, 0, sizeof(*session));
}

static void print_status(const fathom_stats_t *st, const char *prefix,
                         bool overwrite_line)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (double)(now.tv_sec - st->start.tv_sec)
                   + (double)(now.tv_usec - st->start.tv_usec) / 1e6;
    if (elapsed < 0.001)
        elapsed = 0.001;

    double execs_sec = (double)st->total_execs / elapsed;

    int hrs = (int)elapsed / 3600;
    int min = ((int)elapsed % 3600) / 60;
    int sec = (int)elapsed % 60;

    if (overwrite_line)
        fprintf(stderr, "\r\033[2K");

    if (prefix && prefix[0] != '\0')
        fprintf(stderr, "%s ", prefix);

    fprintf(stderr,
        "[%02d:%02d:%02d] "
        "execs: %lu (%.0f/sec) | "
        "coverage: %zu edges | "
        "corpus: %zu | "
        "crashes: %lu (%lu unique) | "
        "hangs: %lu",
        hrs, min, sec,
        (unsigned long)st->total_execs, execs_sec,
        st->total_edges,
        st->corpus_size,
        (unsigned long)st->crashes,
        (unsigned long)st->unique_crashes,
        (unsigned long)st->hangs);

    if (!overwrite_line)
        fputc('\n', stderr);
}

static int ensure_dir(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        fprintf(stderr, "fathom: path exists but is not a directory: %s\n",
                path);
        return -1;
    }

    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;

    fprintf(stderr, "fathom: mkdir(%s): %s\n", path, strerror(errno));
    return -1;
}

static int build_worker_output_dir(char *buf, size_t buf_sz,
                                   const char *base_output_dir,
                                   uint32_t worker_id)
{
    int n = snprintf(buf, buf_sz, "%s/worker-%03u",
                     base_output_dir, worker_id);
    if (n < 0 || (size_t)n >= buf_sz) {
        fprintf(stderr, "fathom: worker output path too long\n");
        return -1;
    }
    return 0;
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t total = 0;

    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += (size_t)n;
    }

    return (ssize_t)total;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t total = 0;

    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }

    return (ssize_t)total;
}

static void forward_stop_to_workers(const pid_t *pids, uint32_t jobs)
{
    int sig = g_stop_signal ? (int)g_stop_signal : SIGTERM;

    for (uint32_t i = 0; i < jobs; i++) {
        if (pids[i] > 0)
            kill(pids[i], sig);
    }
}

static int prepare_session(const fathom_config_t *cfg, bool verbose,
                           fathom_session_t *session)
{
    memset(session, 0, sizeof(*session));

    if (fathom_elf_open(&session->elf, cfg->target_path) < 0) {
        fprintf(stderr, "fathom: failed to parse ELF: %s\n", cfg->target_path);
        return -1;
    }

    fprintf(stderr, "  .text: 0x%lx (%lu bytes)\n",
            (unsigned long)session->elf.text.addr,
            (unsigned long)session->elf.text.size);

    if (fathom_disasm_open(&session->dis, &session->elf) < 0) {
        fprintf(stderr, "fathom: disassembly failed\n");
        cleanup_session(session);
        return -1;
    }
    fprintf(stderr, "  instructions: %zu\n", session->dis.count);

    if (fathom_cfg_build(&session->cfg_graph, &session->dis) < 0) {
        fprintf(stderr, "fathom: CFG build failed\n");
        cleanup_session(session);
        return -1;
    }
    fprintf(stderr, "  blocks: %zu, edges: %zu\n",
            session->cfg_graph.block_count, session->cfg_graph.edge_count);

    if (fathom_analyze(&session->ana, &session->cfg_graph,
                       &session->elf, &session->dis) < 0) {
        fprintf(stderr, "fathom: analysis failed\n");
        cleanup_session(session);
        return -1;
    }
    fprintf(stderr, "  scored blocks: %zu, dictionary: %zu entries\n",
            session->ana.ranked_count, session->ana.dict.count);

    if (cfg->dict_file) {
        if (fathom_dict_load(&session->ana.dict, cfg->dict_file) < 0) {
            fprintf(stderr, "fathom: failed to load dictionary: %s\n",
                    cfg->dict_file);
            cleanup_session(session);
            return -1;
        }

        if (verbose)
            fprintf(stderr, "  dict after load: %zu entries\n",
                    session->ana.dict.count);
    }

    return 0;
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
        "  -a          Analysis-only mode (print CFG + scores, no fuzzing)\n"
        "  -v          Verbose output\n"
        "  --dict <f>  Extra dictionary file\n"
        "  -h          Show this help\n",
        prog, DEFAULT_TIMEOUT_MS, DEFAULT_JOBS);
}

/* ── Analysis-only mode ──────────────────────────────────────────────── */

static int run_analysis(const char *target_path, bool verbose)
{
    fathom_elf_t elf;
    if (fathom_elf_open(&elf, target_path) < 0) {
        fprintf(stderr, "fathom: failed to parse ELF: %s\n", target_path);
        return 1;
    }

    if (verbose) {
        fprintf(stderr, "  entry: 0x%lx\n", (unsigned long)elf.entry);
        fprintf(stderr, "  .text: 0x%lx (%lu bytes)\n",
                (unsigned long)elf.text.addr, (unsigned long)elf.text.size);
        fprintf(stderr, "  symbols: %zu%s\n", elf.symbol_count,
                elf.stripped ? " (stripped, using .dynsym)" : "");
    }

    fathom_disasm_t dis;
    if (fathom_disasm_open(&dis, &elf) < 0) {
        fprintf(stderr, "fathom: disassembly failed\n");
        fathom_elf_close(&elf);
        return 1;
    }

    if (verbose)
        fprintf(stderr, "  instructions: %zu\n", dis.count);

    fathom_cfg_t cfg;
    if (fathom_cfg_build(&cfg, &dis) < 0) {
        fprintf(stderr, "fathom: CFG build failed\n");
        fathom_disasm_close(&dis);
        fathom_elf_close(&elf);
        return 1;
    }

    fathom_analysis_t ana;
    if (fathom_analyze(&ana, &cfg, &elf, &dis) < 0) {
        fprintf(stderr, "fathom: analysis failed\n");
        fathom_cfg_free(&cfg);
        fathom_disasm_close(&dis);
        fathom_elf_close(&elf);
        return 1;
    }

    fathom_analysis_print(&ana, &dis);

    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
    fathom_disasm_close(&dis);
    fathom_elf_close(&elf);

    return 0;
}

/* ── Worker fuzz loop ────────────────────────────────────────────────── */

static int run_worker(const fathom_config_t *cfg,
                      fathom_session_t *session,
                      bool verbose,
                      int worker_id,
                      bool multi_worker,
                      fathom_worker_report_t *report)
{
    int ret = 1;
    const char *prefix = NULL;
    char worker_prefix[16];
    fathom_coverage_t cov;
    fathom_corpus_t corpus;
    fathom_exec_t ex;
    bool cov_ready = false;
    bool corpus_ready = false;
    bool ex_ready = false;
    uint8_t *buf = NULL;

    memset(report, 0, sizeof(*report));
    memset(&cov, 0, sizeof(cov));
    memset(&corpus, 0, sizeof(corpus));
    memset(&ex, 0, sizeof(ex));
    cov.shm_id = -1;
    ex.fork_server_pid = -1;
    ex.ctl_pipe[0] = ex.ctl_pipe[1] = -1;
    ex.st_pipe[0] = ex.st_pipe[1] = -1;

    g_stop = 0;
    g_stop_signal = 0;

    if (multi_worker) {
        snprintf(worker_prefix, sizeof(worker_prefix), "[w%03d]", worker_id);
        prefix = worker_prefix;
    }

    if (install_stop_handlers() < 0) {
        perror("fathom: sigaction");
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

    if (corpus.count == 0) {
        const uint8_t seed[] = "AAAA";
        if (fathom_corpus_add(&corpus, seed, sizeof(seed) - 1, 0) < 0) {
            fprintf(stderr, "fathom: failed to create fallback seed\n");
            goto cleanup;
        }
        if (verbose && !multi_worker)
            fprintf(stderr, "  no seeds found, using default\n");
    }

    if (multi_worker && verbose) {
        fprintf(stderr, "%s seeds: %zu, output: %s\n",
                prefix, corpus.count, cfg->output_dir);
    } else if (!multi_worker) {
        fprintf(stderr, "  seeds: %zu\n", corpus.count);
    }

    fathom_mutator_t mut;
    fathom_mutator_init(&mut, &session->ana.dict);

    if (fathom_exec_init(&ex, cfg) < 0) {
        fprintf(stderr, "fathom: executor init failed\n");
        goto cleanup;
    }
    ex_ready = true;

    size_t bp_limit = session->ana.ranked_count < MAX_BREAKPOINTS
                    ? session->ana.ranked_count : MAX_BREAKPOINTS;
    for (size_t i = 0; i < bp_limit; i++) {
        uint32_t bid = session->ana.ranked_blocks[i];
        if (fathom_exec_add_breakpoint(&ex,
                session->cfg_graph.blocks[bid].start_addr) < 0) {
            fprintf(stderr, "fathom: breakpoint setup failed\n");
            goto cleanup;
        }
    }

    if (verbose) {
        if (multi_worker)
            fprintf(stderr, "%s breakpoints: %zu\n", prefix, ex.bp_count);
        else
            fprintf(stderr, "  breakpoints: %zu\n", ex.bp_count);
    }

    if (!multi_worker)
        fprintf(stderr, "\nfuzzing started (Ctrl-C to stop)...\n\n");

    fathom_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.corpus_size = corpus.count;
    gettimeofday(&stats.start, NULL);

    buf = malloc(MAX_INPUT_SIZE);
    if (!buf) {
        fprintf(stderr, "fathom: out of memory\n");
        goto cleanup;
    }

    struct timeval last_status;
    gettimeofday(&last_status, NULL);

    while (!g_stop) {
        fathom_input_t *seed = fathom_corpus_next(&corpus);
        if (!seed) {
            const uint8_t fallback[] = "AAAA";
            if (fathom_corpus_add(&corpus, fallback, sizeof(fallback) - 1, 0) < 0) {
                fprintf(stderr, "fathom: failed to replenish corpus\n");
                goto cleanup;
            }
            stats.corpus_size = corpus.count;
            continue;
        }

        size_t len = seed->len;
        if (len > MAX_INPUT_SIZE)
            len = MAX_INPUT_SIZE;
        memcpy(buf, seed->data, len);

        int strategy = fathom_mutate(&mut, buf, &len, MAX_INPUT_SIZE, NULL, 0);

        fathom_exec_result_t result;
        if (fathom_exec_run(&ex, &cov, buf, len, &result) < 0) {
            if (verbose) {
                if (multi_worker)
                    fprintf(stderr, "%s exec error, continuing...\n", prefix);
                else
                    fprintf(stderr, "\nexec error, continuing...\n");
            }
            stats.total_execs++;
            continue;
        }

        stats.total_execs++;

        if (fathom_coverage_has_new(&cov)) {
            fathom_coverage_merge(&cov);
            stats.total_edges = cov.total_edges;
            stats.last_new_cov_exec = stats.total_execs;

            if (fathom_corpus_add(&corpus, buf, len, cov.new_edges) < 0) {
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
            if (fathom_corpus_save_crash(&corpus, buf, len,
                                         result.crash_hash) < 0) {
                fprintf(stderr, "fathom: failed to save crash\n");
                goto cleanup;
            }
            stats.unique_crashes = corpus.unique_crashes;

            if (corpus.unique_crashes > prev) {
                if (multi_worker) {
                    fprintf(stderr,
                            "%s new crash: signal=%d hash=0x%lx\n",
                            prefix, result.signal,
                            (unsigned long)result.crash_hash);
                } else {
                    fprintf(stderr,
                            "\n*** NEW CRASH: signal=%d hash=0x%lx ***\n",
                            result.signal,
                            (unsigned long)result.crash_hash);
                }
            }
        } else if (result.status == FATHOM_EXIT_HANG) {
            stats.hangs++;
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        long diff_ms = (now.tv_sec - last_status.tv_sec) * 1000
                     + (now.tv_usec - last_status.tv_usec) / 1000;
        if (diff_ms >= STATS_INTERVAL_MS) {
            print_status(&stats, prefix, !multi_worker);
            last_status = now;
        }
    }

    if (!multi_worker) {
        fprintf(stderr, "\n\n");
        fprintf(stderr, "=== Fathom session complete ===\n");
        fprintf(stderr, "  total execs:    %lu\n",
                (unsigned long)stats.total_execs);
        fprintf(stderr, "  coverage edges: %zu\n", stats.total_edges);
        fprintf(stderr, "  corpus size:    %zu\n", corpus.count);
        fprintf(stderr, "  crashes:        %lu (%lu unique)\n",
                (unsigned long)stats.crashes,
                (unsigned long)stats.unique_crashes);
        fprintf(stderr, "  hangs:          %lu\n",
                (unsigned long)stats.hangs);
        fprintf(stderr, "  output dir:     %s\n", cfg->output_dir);
    }

    report->total_execs = stats.total_execs;
    report->crashes = stats.crashes;
    report->unique_crashes = stats.unique_crashes;
    report->hangs = stats.hangs;
    report->corpus_size = corpus.count;
    report->total_edges = stats.total_edges;
    report->exit_code = 0;
    ret = 0;

cleanup:
    free(buf);
    if (ex_ready)
        fathom_exec_destroy(&ex);
    if (corpus_ready)
        fathom_corpus_destroy(&corpus);
    if (cov_ready)
        fathom_coverage_destroy(&cov);

    return ret;
}

/* ── Parallel supervisor ─────────────────────────────────────────────── */

static int run_parallel_fuzzer(const fathom_config_t *cfg,
                               fathom_session_t *session,
                               bool verbose)
{
    int ret = 1;
    pid_t *worker_pids = NULL;
    int *report_fds = NULL;
    fathom_worker_report_t *reports = NULL;
    bool *have_report = NULL;
    bool forwarded_stop = false;
    bool unexpected_fail = false;
    uint32_t launched = 0;
    uint32_t remaining = 0;

    if (ensure_dir(cfg->output_dir) < 0)
        return 1;

    if (install_stop_handlers() < 0) {
        perror("fathom: sigaction");
        return 1;
    }

    worker_pids = calloc(cfg->jobs, sizeof(*worker_pids));
    report_fds = malloc(cfg->jobs * sizeof(*report_fds));
    reports = calloc(cfg->jobs, sizeof(*reports));
    have_report = calloc(cfg->jobs, sizeof(*have_report));
    if (!worker_pids || !report_fds || !reports || !have_report) {
        fprintf(stderr, "fathom: out of memory\n");
        goto cleanup;
    }

    for (uint32_t i = 0; i < cfg->jobs; i++)
        report_fds[i] = -1;

    fprintf(stderr, "  workers: %u\n", cfg->jobs);
    fprintf(stderr, "\nstarting %u workers (Ctrl-C to stop)...\n\n", cfg->jobs);
    fflush(stderr);

    for (uint32_t i = 0; i < cfg->jobs; i++) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("fathom: pipe");
            unexpected_fail = true;
            break;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fathom: fork");
            close(pipefd[0]);
            close(pipefd[1]);
            unexpected_fail = true;
            break;
        }

        if (pid == 0) {
            char worker_output_dir[FATHOM_PATH_MAX];
            fathom_config_t worker_cfg = *cfg;
            fathom_worker_report_t report;
            int exit_code;

            close(pipefd[0]);

            if (build_worker_output_dir(worker_output_dir,
                                        sizeof(worker_output_dir),
                                        cfg->output_dir, i) < 0) {
                close(pipefd[1]);
                _exit(1);
            }

            worker_cfg.output_dir = worker_output_dir;
            worker_cfg.jobs = 1;
            exit_code = run_worker(&worker_cfg, session, verbose,
                                   (int)i, true, &report);
            report.exit_code = exit_code;

            if (write_full(pipefd[1], &report, sizeof(report)) < 0) {
                close(pipefd[1]);
                _exit(exit_code ? exit_code : 1);
            }

            close(pipefd[1]);
            _exit(exit_code);
        }

        close(pipefd[1]);
        worker_pids[i] = pid;
        report_fds[i] = pipefd[0];
        launched++;
    }

    remaining = launched;

    if (unexpected_fail && launched > 0 && !forwarded_stop) {
        forward_stop_to_workers(worker_pids, launched);
        forwarded_stop = true;
    }

    while (remaining > 0) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0) {
            if (errno == EINTR) {
                if (g_stop && !forwarded_stop) {
                    forward_stop_to_workers(worker_pids, launched);
                    forwarded_stop = true;
                }
                continue;
            }

            perror("fathom: waitpid");
            unexpected_fail = true;
            break;
        }

        uint32_t idx;
        for (idx = 0; idx < launched; idx++) {
            if (worker_pids[idx] == pid)
                break;
        }
        if (idx == launched)
            continue;

        worker_pids[idx] = -1;
        remaining--;

        if (report_fds[idx] >= 0) {
            ssize_t n = read_full(report_fds[idx], &reports[idx],
                                  sizeof(reports[idx]));
            close(report_fds[idx]);
            report_fds[idx] = -1;
            if (n == (ssize_t)sizeof(reports[idx]))
                have_report[idx] = true;
        }

        if (WIFSIGNALED(status)) {
            unexpected_fail = true;
            if (!forwarded_stop && remaining > 0) {
                forward_stop_to_workers(worker_pids, launched);
                forwarded_stop = true;
            }
            continue;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            unexpected_fail = true;
            if (!forwarded_stop && remaining > 0) {
                forward_stop_to_workers(worker_pids, launched);
                forwarded_stop = true;
            }
        }
    }

    for (uint32_t i = 0; i < launched; i++) {
        if (report_fds[i] >= 0) {
            close(report_fds[i]);
            report_fds[i] = -1;
        }
    }

    if (remaining > 0) {
        forward_stop_to_workers(worker_pids, launched);
        while (remaining > 0) {
            if (waitpid(-1, NULL, 0) > 0)
                remaining--;
            else if (errno != EINTR)
                break;
        }
    }

    fprintf(stderr, "\n=== Fathom session complete ===\n");
    fprintf(stderr, "  workers:        %u\n", cfg->jobs);

    uint64_t total_execs = 0;
    uint64_t total_crashes = 0;
    uint64_t total_hangs = 0;
    for (uint32_t i = 0; i < launched; i++) {
        if (!have_report[i])
            continue;
        total_execs += reports[i].total_execs;
        total_crashes += reports[i].crashes;
        total_hangs += reports[i].hangs;
    }

    fprintf(stderr, "  total execs:    %lu\n", (unsigned long)total_execs);
    fprintf(stderr, "  crashes:        %lu\n", (unsigned long)total_crashes);
    fprintf(stderr, "  hangs:          %lu\n", (unsigned long)total_hangs);
    fprintf(stderr, "  output dir:     %s\n", cfg->output_dir);
    fprintf(stderr, "  worker stats:\n");

    for (uint32_t i = 0; i < launched; i++) {
        char worker_output_dir[FATHOM_PATH_MAX];
        if (build_worker_output_dir(worker_output_dir,
                                    sizeof(worker_output_dir),
                                    cfg->output_dir, i) < 0) {
            strcpy(worker_output_dir, "<path error>");
        }

        if (!have_report[i]) {
            fprintf(stderr,
                    "    worker-%03u: no report (%s)\n",
                    i, worker_output_dir);
            continue;
        }

        fprintf(stderr,
                "    worker-%03u: coverage=%zu edges | corpus=%zu | output=%s\n",
                i, reports[i].total_edges, reports[i].corpus_size,
                worker_output_dir);
    }

    ret = unexpected_fail ? 1 : 0;

cleanup:
    free(have_report);
    free(reports);
    free(report_fds);
    free(worker_pids);
    return ret;
}

/* ── Fuzzer entrypoint ───────────────────────────────────────────────── */

static int run_fuzzer(const fathom_config_t *cfg, bool verbose)
{
    int ret;
    fathom_session_t session;

    g_stop = 0;
    g_stop_signal = 0;

    fprintf(stderr, FATHOM_BANNER,
            FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR, FATHOM_VERSION_PATCH);
    fprintf(stderr, "target: %s\n", cfg->target_path);

    if (prepare_session(cfg, verbose, &session) < 0)
        return 1;

    if (cfg->jobs > 1)
        ret = run_parallel_fuzzer(cfg, &session, verbose);
    else {
        fathom_worker_report_t report;
        ret = run_worker(cfg, &session, verbose, 0, false, &report);
    }

    cleanup_session(&session);
    return ret;
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *input_dir  = NULL;
    const char *output_dir = "./fathom-out";
    const char *dict_file  = NULL;
    uint32_t    timeout_ms = DEFAULT_TIMEOUT_MS;
    uint32_t    jobs       = DEFAULT_JOBS;
    bool        analysis   = false;
    bool        verbose    = false;

    static struct option long_opts[] = {
        {"dict", required_argument, NULL, 'D'},
        {"help", no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:t:j:avh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': input_dir  = optarg;                 break;
        case 'o': output_dir = optarg;                 break;
        case 't': timeout_ms = (uint32_t)atoi(optarg); break;
        case 'j': jobs       = (uint32_t)atoi(optarg); break;
        case 'a': analysis   = true;                   break;
        case 'v': verbose    = true;                   break;
        case 'D': dict_file  = optarg;                 break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (jobs == 0) {
        fprintf(stderr, "fathom: -j must be at least 1\n");
        return 1;
    }

    /* After '--', remaining args are the target command */
    if (optind >= argc) {
        fprintf(stderr, "fathom: no target specified\n\n");
        usage(argv[0]);
        return 1;
    }

    const char *target_path = argv[optind];

    if (analysis) {
        fprintf(stderr, FATHOM_BANNER,
                FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR,
                FATHOM_VERSION_PATCH);
        fprintf(stderr, "analysis mode: %s\n\n", target_path);
        return run_analysis(target_path, verbose);
    }

    fathom_config_t cfg = {
        .target_path   = target_path,
        .target_argv   = &argv[optind],
        .input_dir     = input_dir,
        .output_dir    = output_dir,
        .dict_file     = dict_file,
        .timeout_ms    = timeout_ms,
        .jobs          = jobs,
        .analysis_only = false,
        .verbose       = verbose,
    };

    return run_fuzzer(&cfg, verbose);
}
