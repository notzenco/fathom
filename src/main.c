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
#include <sys/time.h>
#include <time.h>
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

/* ── Volatile flag for SIGINT ────────────────────────────────────────── */

static volatile sig_atomic_t g_stop;

static void sigint_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ── Statistics ──────────────────────────────────────────────────────── */

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

static void print_status(const fathom_stats_t *st)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (double)(now.tv_sec - st->start.tv_sec)
                   + (double)(now.tv_usec - st->start.tv_usec) / 1e6;
    if (elapsed < 0.001) elapsed = 0.001;

    double execs_sec = (double)st->total_execs / elapsed;

    int hrs = (int)elapsed / 3600;
    int min = ((int)elapsed % 3600) / 60;
    int sec = (int)elapsed % 60;

    fprintf(stderr,
        "\r\033[2K"
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
        "  -j <n>      Parallel instances (default: %d) [not yet implemented]\n"
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

/* ── Fuzz loop ───────────────────────────────────────────────────────── */

static int run_fuzzer(const fathom_config_t *cfg, bool verbose)
{
    int ret = 1;

    /* ── Phase 1: Static analysis ────────────────────────────────────── */

    fprintf(stderr, FATHOM_BANNER,
            FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR, FATHOM_VERSION_PATCH);
    fprintf(stderr, "target: %s\n", cfg->target_path);

    fathom_elf_t elf;
    if (fathom_elf_open(&elf, cfg->target_path) < 0) {
        fprintf(stderr, "fathom: failed to parse ELF: %s\n", cfg->target_path);
        return 1;
    }

    fprintf(stderr, "  .text: 0x%lx (%lu bytes)\n",
            (unsigned long)elf.text.addr, (unsigned long)elf.text.size);

    fathom_disasm_t dis;
    if (fathom_disasm_open(&dis, &elf) < 0) {
        fprintf(stderr, "fathom: disassembly failed\n");
        fathom_elf_close(&elf);
        return 1;
    }
    fprintf(stderr, "  instructions: %zu\n", dis.count);

    fathom_cfg_t cfg_graph;
    if (fathom_cfg_build(&cfg_graph, &dis) < 0) {
        fprintf(stderr, "fathom: CFG build failed\n");
        fathom_disasm_close(&dis);
        fathom_elf_close(&elf);
        return 1;
    }
    fprintf(stderr, "  blocks: %zu, edges: %zu\n",
            cfg_graph.block_count, cfg_graph.edge_count);

    fathom_analysis_t ana;
    if (fathom_analyze(&ana, &cfg_graph, &elf, &dis) < 0) {
        fprintf(stderr, "fathom: analysis failed\n");
        fathom_cfg_free(&cfg_graph);
        fathom_disasm_close(&dis);
        fathom_elf_close(&elf);
        return 1;
    }
    fprintf(stderr, "  scored blocks: %zu, dictionary: %zu entries\n",
            ana.ranked_count, ana.dict.count);

    /* Load extra dictionary if provided */
    if (cfg->dict_file) {
        fathom_dict_load(&ana.dict, cfg->dict_file);
        if (verbose)
            fprintf(stderr, "  dict after load: %zu entries\n", ana.dict.count);
    }

    /* ── Phase 2: Initialize fuzzer components ───────────────────────── */

    fathom_coverage_t cov;
    if (fathom_coverage_init(&cov) < 0) {
        fprintf(stderr, "fathom: coverage init failed\n");
        goto cleanup_analysis;
    }

    fathom_corpus_t corpus;
    if (fathom_corpus_init(&corpus, cfg->input_dir, cfg->output_dir) < 0) {
        fprintf(stderr, "fathom: corpus init failed\n");
        goto cleanup_coverage;
    }

    /* If no seeds were loaded, create a minimal seed */
    if (corpus.count == 0) {
        const uint8_t seed[] = "AAAA";
        fathom_corpus_add(&corpus, seed, sizeof(seed) - 1, 0);
        if (verbose)
            fprintf(stderr, "  no seeds found, using default\n");
    }
    fprintf(stderr, "  seeds: %zu\n", corpus.count);

    fathom_mutator_t mut;
    fathom_mutator_init(&mut, &ana.dict);

    fathom_exec_t ex;
    if (fathom_exec_init(&ex, cfg) < 0) {
        fprintf(stderr, "fathom: executor init failed\n");
        goto cleanup_corpus;
    }

    /* Set breakpoints at top-scored blocks */
    size_t bp_limit = ana.ranked_count < MAX_BREAKPOINTS
                    ? ana.ranked_count : MAX_BREAKPOINTS;
    for (size_t i = 0; i < bp_limit; i++) {
        uint32_t bid = ana.ranked_blocks[i];
        fathom_exec_add_breakpoint(&ex, cfg_graph.blocks[bid].start_addr);
    }
    if (verbose)
        fprintf(stderr, "  breakpoints: %zu\n", ex.bp_count);

    /* Install SIGINT handler for graceful shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    fprintf(stderr, "\nfuzzing started (Ctrl-C to stop)...\n\n");

    /* ── Phase 3: Fuzz loop ──────────────────────────────────────────── */

    fathom_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    gettimeofday(&stats.start, NULL);

    uint8_t *buf = malloc(MAX_INPUT_SIZE);
    if (!buf) {
        fprintf(stderr, "fathom: out of memory\n");
        goto cleanup_exec;
    }

    struct timeval last_status;
    gettimeofday(&last_status, NULL);

    while (!g_stop) {
        /* Pick next input from corpus */
        fathom_input_t *seed = fathom_corpus_next(&corpus);
        if (!seed) {
            const uint8_t fallback[] = "AAAA";
            fathom_corpus_add(&corpus, fallback, 4, 0);
            continue;
        }

        /* Copy seed into mutation buffer */
        size_t len = seed->len;
        if (len > MAX_INPUT_SIZE)
            len = MAX_INPUT_SIZE;
        memcpy(buf, seed->data, len);

        /* Mutate */
        int strategy = fathom_mutate(&mut, buf, &len, MAX_INPUT_SIZE,
                                     NULL, 0);

        /* Execute */
        fathom_exec_result_t result;
        if (fathom_exec_run(&ex, &cov, buf, len, &result) < 0) {
            if (verbose)
                fprintf(stderr, "\nexec error, continuing...\n");
            stats.total_execs++;
            continue;
        }

        stats.total_execs++;

        /* Check for new coverage */
        if (fathom_coverage_has_new(&cov)) {
            fathom_coverage_merge(&cov);
            stats.total_edges = cov.total_edges;
            stats.last_new_cov_exec = stats.total_execs;

            fathom_corpus_add(&corpus, buf, len, cov.new_edges);
            stats.corpus_size = corpus.count;

            if (strategy >= 0 && strategy < FATHOM_MUT_COUNT)
                fathom_mutator_reward(&mut, (fathom_mutation_t)strategy);
        }

        /* Handle crashes */
        if (result.status == FATHOM_EXIT_CRASH) {
            stats.crashes++;
            size_t prev = corpus.unique_crashes;
            fathom_corpus_save_crash(&corpus, buf, len, result.crash_hash);
            stats.unique_crashes = corpus.unique_crashes;

            if (corpus.unique_crashes > prev) {
                fprintf(stderr, "\n*** NEW CRASH: signal=%d hash=0x%lx ***\n",
                        result.signal,
                        (unsigned long)result.crash_hash);
            }
        } else if (result.status == FATHOM_EXIT_HANG) {
            stats.hangs++;
        }

        /* Periodic status update */
        struct timeval now;
        gettimeofday(&now, NULL);
        long diff_ms = (now.tv_sec - last_status.tv_sec) * 1000
                     + (now.tv_usec - last_status.tv_usec) / 1000;
        if (diff_ms >= STATS_INTERVAL_MS) {
            print_status(&stats);
            last_status = now;
        }
    }

    /* ── Shutdown ────────────────────────────────────────────────────── */

    fprintf(stderr, "\n\n");
    fprintf(stderr, "=== Fathom session complete ===\n");
    fprintf(stderr, "  total execs:    %lu\n", (unsigned long)stats.total_execs);
    fprintf(stderr, "  coverage edges: %zu\n", stats.total_edges);
    fprintf(stderr, "  corpus size:    %zu\n", corpus.count);
    fprintf(stderr, "  crashes:        %lu (%lu unique)\n",
            (unsigned long)stats.crashes, (unsigned long)stats.unique_crashes);
    fprintf(stderr, "  hangs:          %lu\n", (unsigned long)stats.hangs);
    fprintf(stderr, "  output dir:     %s\n", cfg->output_dir);

    ret = 0;

    free(buf);
cleanup_exec:
    fathom_exec_destroy(&ex);
cleanup_corpus:
    fathom_corpus_destroy(&corpus);
cleanup_coverage:
    fathom_coverage_destroy(&cov);
cleanup_analysis:
    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg_graph);
    fathom_disasm_close(&dis);
    fathom_elf_close(&elf);

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
        case 'i': input_dir  = optarg;                break;
        case 'o': output_dir = optarg;                break;
        case 't': timeout_ms = (uint32_t)atoi(optarg); break;
        case 'j': jobs       = (uint32_t)atoi(optarg); break;
        case 'a': analysis   = true;                  break;
        case 'v': verbose    = true;                  break;
        case 'D': dict_file  = optarg;                break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* After '--', remaining args are the target command */
    if (optind >= argc) {
        fprintf(stderr, "fathom: no target specified\n\n");
        usage(argv[0]);
        return 1;
    }

    const char *target_path = argv[optind];

    /* Analysis-only mode */
    if (analysis) {
        fprintf(stderr, FATHOM_BANNER,
                FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR,
                FATHOM_VERSION_PATCH);
        fprintf(stderr, "analysis mode: %s\n\n", target_path);
        return run_analysis(target_path, verbose);
    }

    /* Build config for fuzz mode */
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

    (void)jobs;  /* TODO: parallel fuzzing not yet implemented */

    return run_fuzzer(&cfg, verbose);
}
