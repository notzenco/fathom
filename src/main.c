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

#include <dirent.h>
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
#define DEFAULT_MAX_INPUT   (1 << 20)   /* 1 MB max mutated input */
#define STATS_INTERVAL_US   1000000     /* status line refresh rate */
#define FATHOM_PATH_MAX     4096
#define STATS_FILE          "fuzzer_stats"
#define SYNC_INTERVAL_US    10000000    /* how often parallel workers import peers' finds */
#ifdef _WIN32
#define MAX_WORKERS         MAXIMUM_WAIT_OBJECTS
#else
#define MAX_WORKERS         1024
#endif

/* ── Options ─────────────────────────────────────────────────────────── */

static size_t g_max_input = DEFAULT_MAX_INPUT;   /* --max-input */

typedef struct {
    fathom_config_t cfg;
    uint64_t seed;
    bool     have_seed;
    uint32_t max_secs;       /* 0 = run until stopped */
    bool     until_crash;    /* stop after the first unique crash */
    /*
     * Shrink queue inputs while their blocks stay the same.  Off by
     * default: breakpoints fire once per run, so coverage cannot see loop
     * counts, and trimming would cut inputs below the length a buffer
     * overflow needs.
     */
    bool     trim;
    const char *replay;      /* --replay: run this input once and report */
    const char *minimize;    /* --minimize: shrink this crashing input */
    uint64_t max_execs;      /* --max-execs: stop after this many runs, 0 = no limit */
    bool     fail_on_crash;  /* --fail-on-crash: exit status 2 if any unique crash */
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
    uint64_t last_gain_us;          /* when coverage last grew */
    size_t   unique_hangs;
    const fathom_mutator_t *mut;    /* per-strategy counters, when known */
} fathom_stats_t;

static const char *const strategy_names[FATHOM_MUT_COUNT] = {
    "bitflip", "byteflip", "arith", "interesting", "dictionary",
    "havoc", "splice", "insert", "delete", "clone",
};

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

/* "SIGSEGV" or "EXCEPTION_ACCESS_VIOLATION (0xc0000005)", for people. */
static void describe_crash(char *buf, size_t cap, uint32_t code)
{
    static const struct { uint32_t code; const char *name; } names[] = {
#ifdef _WIN32
        { 0xC0000005u, "EXCEPTION_ACCESS_VIOLATION" },
        { 0xC000001Du, "EXCEPTION_ILLEGAL_INSTRUCTION" },
        { 0xC0000096u, "EXCEPTION_PRIV_INSTRUCTION" },
        { 0xC0000094u, "EXCEPTION_INT_DIVIDE_BY_ZERO" },
        { 0xC0000095u, "EXCEPTION_INT_OVERFLOW" },
        { 0xC00000FDu, "EXCEPTION_STACK_OVERFLOW" },
        { 0xC000008Cu, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED" },
        { 0x80000002u, "EXCEPTION_DATATYPE_MISALIGNMENT" },
        { 0xC0000006u, "EXCEPTION_IN_PAGE_ERROR" },
        { 0x80000003u, "EXCEPTION_BREAKPOINT" },
        { 0xC0000374u, "STATUS_HEAP_CORRUPTION" },
        { 0xC0000409u, "STATUS_STACK_BUFFER_OVERRUN" },
        { 0xC0000602u, "STATUS_FAIL_FAST_EXCEPTION" },
#else
        { SIGSEGV, "SIGSEGV" }, { SIGBUS, "SIGBUS" }, { SIGILL, "SIGILL" },
        { SIGFPE, "SIGFPE" }, { SIGABRT, "SIGABRT" }, { SIGTRAP, "SIGTRAP" },
        { SIGSYS, "SIGSYS" },
#endif
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (names[i].code == code) {
#ifdef _WIN32
            snprintf(buf, cap, "%s (0x%08" PRIx32 ")", names[i].name, code);
#else
            snprintf(buf, cap, "%s", names[i].name);
#endif
            return;
        }
    }
#ifdef _WIN32
    snprintf(buf, cap, "exception 0x%08" PRIx32, code);
#else
    snprintf(buf, cap, "signal %" PRIu32, code);
#endif
}

/* "0x100000abc (main+0x24)", or a note that the PC was outside the image. */
static void describe_pc(char *buf, size_t cap, const fathom_binary_t *bin, uint64_t pc)
{
    uint64_t off = 0;
    const char *sym = pc ? fathom_symbol_near(bin, pc, &off) : NULL;
    if (!pc)
        snprintf(buf, cap, "outside the target image (a library, or a smashed stack)");
    else if (sym)
        snprintf(buf, cap, "0x%" PRIx64 " (%s+0x%" PRIx64 ")", pc, sym, off);
    else
        snprintf(buf, cap, "0x%" PRIx64, pc);
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
    uint64_t now = fathom_now_us();
    uint64_t run_ms = st->start_us ? (now - st->start_us) / 1000 : 0;
    fprintf(fp, "execs %" PRIu64 "\ncrashes %" PRIu64 "\nunique_crashes %" PRIu64
                "\nhangs %" PRIu64 "\nunique_hangs %zu\ncorpus %zu\ncovered %zu\n"
                "instrumented %zu\nfirst_crash_execs %" PRIu64 "\nfirst_crash_ms %" PRIu64
                "\nrun_ms %" PRIu64 "\nexecs_per_sec %" PRIu64 "\nlast_gain_ms %" PRIu64 "\n",
            st->total_execs, st->crashes, st->unique_crashes, st->hangs, st->unique_hangs,
            st->corpus_size, st->covered, st->instrumented,
            st->first_crash_execs, st->first_crash_ms, run_ms,
            run_ms ? st->total_execs * 1000 / run_ms : 0,
            st->last_gain_us > st->start_us ? (st->last_gain_us - st->start_us) / 1000 : 0);
    for (int i = 0; st->mut && i < FATHOM_MUT_COUNT; i++)
        fprintf(fp, "mut_%s_uses %" PRIu64 "\nmut_%s_hits %" PRIu64 "\n",
                strategy_names[i], st->mut->uses[i], strategy_names[i], st->mut->hits[i]);
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
        else if (!strcmp(key, "unique_hangs"))   st->unique_hangs = (size_t)val;
        else if (!strcmp(key, "first_crash_execs")) st->first_crash_execs = val;
        else if (!strcmp(key, "first_crash_ms")) st->first_crash_ms = val;
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
    if (fathom_cfg_build(&s->cfg_graph, &s->dis, &s->bin) < 0) {
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
        "Input reaches the target on stdin, or as a file whose path replaces\n"
        "every @@ in target_args (then stdin is empty).\n"
        "\n"
        "Options:\n"
        "  -i <dir>    Input corpus (seeds)\n"
        "  -o <dir>    Output directory (default: ./fathom-out)\n"
        "  -t <ms>     Timeout per exec (default: %d)\n"
        "  -j <n>      Parallel instances (default: %d)\n"
        "  -T <secs>   Stop after this many seconds (default: run until Ctrl-C)\n"
        "  -s <seed>   Random seed, for reproducible runs\n"
        "  --until-crash  Stop after the first unique crash\n"
        "  --trim      Shrink queue inputs that keep the same blocks (off by\n"
        "              default: coverage cannot see loop counts)\n"
        "  -a          Analysis-only mode (print CFG + scores, no fuzzing)\n"
        "  --max-execs <n> Stop after n target runs\n"
        "  --max-input <n> Largest input to generate, in bytes (default: %d)\n"
        "  --fail-on-crash Exit with status 2 if any unique crash was found\n"
        "  --version   Show the version\n"
        "  --replay <f>    Run input f once and report the outcome (exit\n"
        "                  status 0 ok, 2 crash, 3 hang)\n"
        "  --minimize <f>  Shrink crashing input f to f.min, keeping the crash\n"
        "  -v          Verbose output\n"
        "  --dict <f>  Extra dictionary file\n"
        "  -h          Show this help\n",
        prog, DEFAULT_TIMEOUT_MS, DEFAULT_JOBS, DEFAULT_MAX_INPUT);
}

/* ── Replay and minimise ─────────────────────────────────────────────── */

#define MINIMIZE_MAX_EXECS  20000

static uint8_t *read_input(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "fathom: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    uint8_t *buf = malloc(g_max_input);
    *len = buf ? fread(buf, 1, g_max_input, fp) : 0;
    fclose(fp);
    return buf;
}

/*
 * Run one input as the fuzzer would and report what happened.  Exit
 * status: 0 normal exit, 2 crash, 3 hang, 1 error.  With minimize, shrink
 * a crashing input to <file>.min while it keeps the same crash.
 */
static int run_replay(const fathom_opts_t *opts, const char *path, bool minimize)
{
    const fathom_config_t *cfg = &opts->cfg;
    fathom_session_t s;
    fathom_exec_t ex;
    fathom_coverage_t cov;
    size_t len = 0;
    uint8_t *buf = read_input(path, &len);
    if (!buf || prepare_session(cfg, true, &s) < 0) {
        free(buf);
        return 1;
    }
    int ret = 1;
    bool ex_ready = false, cov_ready = false;
    if (fathom_exec_init(&ex, cfg, &s.bin) < 0)
        goto done;
    ex_ready = true;
    for (size_t i = 0; i < s.ana.cov_count; i++) {
        if (fathom_exec_add_breakpoint(&ex, s.cfg_graph.blocks[s.ana.cov_blocks[i]].start_addr) < 0)
            goto done;
    }
    if (fathom_coverage_init(&cov, ex.bp_count) < 0)
        goto done;
    cov_ready = true;

    fathom_exec_result_t res;
    if (fathom_exec_run(&ex, &cov, buf, len, &res) < 0)
        goto done;
    size_t covered = 0;
    for (size_t i = 0; i < cov.size; i++)
        covered += cov.local[i] != 0;

    char what[64], where[160];
    fprintf(stderr, "input:    %s (%zu bytes)\n", path, len);
    fprintf(stderr, "coverage: %zu/%zu blocks, %.1f ms\n", covered, ex.bp_count,
            (double)res.exec_us / 1000);
    if (res.status == FATHOM_EXIT_CRASH) {
        describe_crash(what, sizeof(what), res.crash_code);
        describe_pc(where, sizeof(where), &s.bin, res.crash_pc);
        fprintf(stderr, "result:   crash, %s at %s\nhash:     0x%016" PRIx64 "\n",
                what, where, res.crash_hash);
        ret = 2;
    } else if (res.status == FATHOM_EXIT_HANG) {
        fprintf(stderr, "result:   hang (no exit within %u ms)\n", cfg->timeout_ms);
        ret = 3;
    } else {
        fprintf(stderr, "result:   exited normally\n");
        ret = 0;
    }
    if (!minimize)
        goto done;

    if (res.status != FATHOM_EXIT_CRASH) {
        fprintf(stderr, "fathom: --minimize needs an input that crashes\n");
        ret = 1;
        goto done;
    }
    uint64_t execs = 0;
    size_t before = len;
    if (fathom_minimize(&ex, &cov, buf, &len, res.crash_hash, MINIMIZE_MAX_EXECS, &execs) < 0) {
        ret = 1;
        goto done;
    }
    char out[FATHOM_PATH_MAX + 8];
    snprintf(out, sizeof(out), "%s.min", path);
    FILE *fp = fopen(out, "wb");
    if (!fp || (len && fwrite(buf, 1, len, fp) != len)) {
        fprintf(stderr, "fathom: cannot write %s\n", out);
        if (fp)
            fclose(fp);
        ret = 1;
        goto done;
    }
    fclose(fp);
    fprintf(stderr, "minimized: %zu -> %zu bytes in %" PRIu64 " execs: %s\n",
            before, len, execs, out);
    ret = 0;

done:
    if (cov_ready)
        fathom_coverage_destroy(&cov);
    if (ex_ready)
        fathom_exec_destroy(&ex);
    cleanup_session(&s);
    free(buf);
    return ret;
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
 * comparisons among hundreds of library ones, and their startup
 * branches stay open forever without depending on the input.  So
 * prefer blocks first reached in the latest coverage gains, and only
 * fall back to the whole frontier when those offer nothing.
 */
#define FRONTIER_RECENT 2   /* coverage gains that count as "recent" */

static void rebuild_frontier(fathom_dict_t *frontier, const fathom_session_t *s,
                             const fathom_coverage_t *cov, const uint32_t *slot_block,
                             const int32_t *block_slot, const uint32_t *epoch,
                             uint32_t now, size_t slots)
{
    for (int pass = 0; pass < 2; pass++) {
        fathom_dict_destroy(frontier);
        fathom_dict_init(frontier);
        uint32_t since = pass == 0 && now > FRONTIER_RECENT ? now - FRONTIER_RECENT + 1 : 1;

        for (size_t slot = 0; slot < slots && frontier->count < 256; slot++) {
            if (!cov->global[slot] || epoch[slot] < since)
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
        if (frontier->count > 0)
            return;
    }
}

/* ── Worker fuzz loop ────────────────────────────────────────────────── */

#define TRIM_MAX_EXECS  1024   /* runs one input may spend on trimming */

typedef struct {
    const fathom_opts_t   *opts;
    const fathom_config_t *cfg;
    fathom_session_t      *session;
    const char            *prefix;
    bool                   multi;

    fathom_coverage_t      cov;
    fathom_corpus_t        corpus;
    fathom_exec_t          ex;
    fathom_mutator_t       mut;
    fathom_dict_t          frontier;
    fathom_stats_t         stats;

    uint32_t              *slot_block;
    int32_t               *block_slot;
    uint32_t              *epoch;       /* coverage gain in which each slot was first hit */
    bool                  *counted;     /* slot counts loop iterations, so stays armed */
    bool                  *block_covered;
    double                *block_steer;
    uint32_t               gains;
    uint64_t               deadline;
    uint64_t               last_status;
    bool                   done;        /* --until-crash satisfied */

    /* Parallel mode: peers are base_out/worker-NNN for every other id. */
    int                    id;
    uint64_t               last_sync;
    size_t                *peer_next;   /* per peer: first queue id not imported yet */
} worker_t;

static bool out_of_time(worker_t *w)
{
    uint64_t now = fathom_now_us();
    if (now - w->last_status >= STATS_INTERVAL_US) {
        print_status(&w->stats, w->prefix, !w->multi);
        w->stats.corpus_size = w->corpus.count;
        w->stats.unique_hangs = w->corpus.unique_hangs;
        write_stats(w->cfg->output_dir, &w->stats);
        w->last_status = now;
    }
    return stop_requested() || w->done || (w->deadline && now >= w->deadline) ||
           (w->opts->max_execs && w->stats.total_execs >= w->opts->max_execs);
}

/*
 * Fold a run with new coverage into the global map.  Returns the static
 * score of the blocks it reached first.
 */
static double take_coverage(worker_t *w)
{
    double score = 0.0;
    w->gains++;
    for (size_t s = 0; s < w->cov.size; s++) {
        if (w->cov.local[s] && !w->cov.global[s]) {
            score += w->session->cfg_graph.blocks[w->slot_block[s]].score;
            w->epoch[s] = w->gains;
        }
    }
    fathom_coverage_merge(&w->cov);
    w->stats.covered = w->cov.total_blocks;
    w->stats.last_gain_us = fathom_now_us();
    rebuild_frontier(&w->frontier, w->session, &w->cov, w->slot_block, w->block_slot,
                     w->epoch, w->gains, w->cov.size);
    return score;
}

/*
 * Fuzzing runs leave covered blocks disarmed, so most runs only trap on
 * blocks not reached yet.  Calibration, trimming and recording a new
 * input need the full path, so they arm everything first.
 */
static void arm_all(worker_t *w)
{
    for (size_t s = 0; s < w->cov.size; s++)
        fathom_exec_arm(&w->ex, (int)s, true);
}

static void disarm_covered(worker_t *w)
{
    for (size_t s = 0; s < w->cov.size; s++)
        fathom_exec_arm(&w->ex, (int)s, !w->cov.global[s] || w->counted[s]);
}

/* Recompute every input's steer after coverage changed (see fathom_steer). */
static void update_steer(worker_t *w)
{
    const fathom_cfg_t *cfg = &w->session->cfg_graph;
    for (size_t b = 0; b < cfg->block_count; b++) {
        int32_t s = w->block_slot[b];
        w->block_covered[b] = s >= 0 && w->cov.global[s];
    }
    fathom_steer(cfg, w->block_covered, w->block_steer);
    for (size_t i = 0; i < w->corpus.count; i++) {
        fathom_input_t *inp = &w->corpus.inputs[i];
        inp->steer = 0;
        for (size_t k = 0; k < inp->slot_count; k++) {
            double v = w->block_steer[w->slot_block[inp->slots[k]]];
            if (v > inp->steer)
                inp->steer = v;
        }
    }
}

/* Whether another worker already saved this crash. */
static bool peer_has_crash(const worker_t *w, uint64_t hash)
{
    for (uint32_t i = 0; w->multi && i < w->opts->cfg.jobs; i++) {
        char path[FATHOM_PATH_MAX + 64], dir[FATHOM_PATH_MAX];
        struct stat st;
        if ((int)i == w->id || worker_dir(dir, sizeof(dir), w->opts->cfg.output_dir, i) < 0)
            continue;
        snprintf(path, sizeof(path), "%s/crashes/crash_%016" PRIx64, dir, hash);
        if (stat(path, &st) == 0)
            return true;
    }
    return false;
}

/* Returns -1 on a fatal error, 1 if this was a new unique crash, else 0. */
static int note_crash(worker_t *w, const uint8_t *buf, size_t len,
                      const fathom_exec_result_t *res)
{
    fathom_corpus_t *corpus = &w->corpus;
    w->stats.crashes++;
    if (peer_has_crash(w, res->crash_hash)) {
        /* A peer found it first: remember it, but it is not ours to save. */
        if (fathom_corpus_mark_crash(corpus, res->crash_hash) < 0)
            return -1;
        if (w->opts->until_crash)
            w->done = true;
        return 0;
    }
    size_t prev = corpus->unique_crashes;
    if (fathom_corpus_save_crash(corpus, buf, len, res->crash_hash) < 0) {
        fprintf(stderr, "fathom: failed to save crash\n");
        return -1;
    }
    w->stats.unique_crashes = corpus->unique_crashes;
    if (corpus->unique_crashes == prev)
        return 0;

    if (w->stats.first_crash_execs == 0) {
        w->stats.first_crash_execs = w->stats.total_execs;
        w->stats.first_crash_ms = (fathom_now_us() - w->stats.start_us) / 1000;
    }
    char what[64], where[160];
    describe_crash(what, sizeof(what), res->crash_code);
    describe_pc(where, sizeof(where), &w->session->bin, res->crash_pc);
    if (w->multi)
        fprintf(stderr, "%s new crash: %s at %s hash=0x%016" PRIx64 "\n",
                w->prefix, what, where, res->crash_hash);
    else
        fprintf(stderr, "\n*** NEW CRASH: %s at %s hash=0x%016" PRIx64 " ***\n",
                what, where, res->crash_hash);

    /* A report next to the input: what, where, when, and how to replay it. */
    char report[4096];
    int n = snprintf(report, sizeof(report),
                     "crash:  %s\npc:     %s\nhash:   0x%016" PRIx64 "\n"
                     "found:  after %" PRIu64 " execs, %.1f s\ninput:  %zu bytes\n"
                     "replay: fathom --replay %s/crashes/crash_%016" PRIx64 " --",
                     what, where, res->crash_hash, w->stats.total_execs,
                     (double)(fathom_now_us() - w->stats.start_us) / 1e6, len,
                     w->cfg->output_dir, res->crash_hash);
    for (size_t i = 0; w->cfg->target_argv[i] && n > 0 && (size_t)n < sizeof(report); i++)
        n += snprintf(report + n, sizeof(report) - (size_t)n, " %s", w->cfg->target_argv[i]);
    if (n > 0 && (size_t)n < sizeof(report) - 1)
        strcat(report, "\n");
    if (fathom_corpus_describe_crash(corpus, res->crash_hash, report) < 0)
        fprintf(stderr, "fathom: failed to write the crash report\n");
    if (w->opts->until_crash)
        w->done = true;
    return 1;
}

/*
 * Run every seed unmutated before fuzzing: its coverage seeds the global
 * map, its speed and blocks feed scheduling, and seeds that crash (saved
 * as crashes) or hang are dropped from the queue.
 */
static int calibrate(worker_t *w)
{
    fathom_corpus_t *corpus = &w->corpus;
    size_t dropped_hangs = 0;
    for (size_t i = 0; i < corpus->count && !stop_requested();) {
        fathom_input_t *inp = &corpus->inputs[i];
        fathom_exec_result_t res;
        w->stats.total_execs++;
        if (fathom_exec_run(&w->ex, &w->cov, inp->data, inp->len, &res) < 0)
            return -1;

        if (res.status == FATHOM_EXIT_CRASH) {
            if (note_crash(w, inp->data, inp->len, &res) < 0)
                return -1;
            fathom_corpus_remove(corpus, i);
            continue;
        }
        if (res.status == FATHOM_EXIT_HANG) {
            w->stats.hangs++;
            dropped_hangs++;
            if (fathom_corpus_save_hang(corpus, inp->data, inp->len,
                                        fathom_coverage_hash(&w->cov)) < 0)
                return -1;
            fathom_corpus_remove(corpus, i);
            continue;
        }
        if (fathom_coverage_has_new(&w->cov)) {
            take_coverage(w);
            inp = &corpus->inputs[i];
            inp->new_coverage = w->cov.new_blocks;
        }
        if (fathom_corpus_record(corpus, i, &w->cov, res.exec_us) < 0)
            return -1;
        i++;
    }
    if (dropped_hangs)
        fprintf(stderr, "%s%sfathom: dropped %zu seed(s) that time out at -t %u ms\n",
                w->prefix ? w->prefix : "", w->prefix ? " " : "", dropped_hangs,
                w->cfg->timeout_ms);
    return 0;
}

/* Trim input idx once, the first time it is picked. */
static int trim_input(worker_t *w, size_t idx, uint8_t *buf)
{
    fathom_input_t *inp = &w->corpus.inputs[idx];
    inp->trimmed = true;
    if (!inp->slots)
        return 0;
    size_t len = inp->len < g_max_input ? inp->len : g_max_input, orig = len;
    memcpy(buf, inp->data, len);
    arm_all(w);
    int rc = fathom_trim(&w->ex, &w->cov, buf, &len, inp->trace_hash, TRIM_MAX_EXECS,
                         &w->stats.total_execs);
    disarm_covered(w);
    if (rc < 0)
        return -1;
    if (len < orig && fathom_corpus_update(&w->corpus, idx, buf, len) < 0)
        return -1;
    return 0;
}

/* One mutated run of input idx.  Returns -1 on a fatal error. */
static int fuzz_one(worker_t *w, size_t idx, uint8_t *buf)
{
    fathom_corpus_t *corpus = &w->corpus;
    const fathom_input_t *seed = &corpus->inputs[idx];
    size_t len = seed->len < g_max_input ? seed->len : g_max_input;
    memcpy(buf, seed->data, len);

    const fathom_input_t *donor =
        &corpus->inputs[fathom_rand_below(&w->mut, (uint32_t)corpus->count)];
    bool can_splice = corpus->count > 1 && donor != seed;
    int strategy = fathom_mutate(&w->mut, buf, &len, g_max_input,
                                 can_splice ? donor->data : NULL,
                                 can_splice ? donor->len : 0);

    fathom_exec_result_t res;
    w->stats.total_execs++;
    if (fathom_exec_run(&w->ex, &w->cov, buf, len, &res) < 0) {
        fprintf(stderr, "%sfathom: target execution failed\n", w->multi ? "" : "\n");
        return -1;
    }

    if (fathom_coverage_has_new(&w->cov)) {
        double score = take_coverage(w);
        size_t fresh = w->cov.new_blocks;

        /* The run saw only armed blocks: run it again in full for its trace. */
        fathom_exec_result_t full;
        arm_all(w);
        w->stats.total_execs++;
        int rc = fathom_exec_run(&w->ex, &w->cov, buf, len, &full);
        disarm_covered(w);
        if (rc < 0)
            return -1;
        fathom_coverage_merge(&w->cov);

        if (fathom_corpus_add(corpus, buf, len, fresh, score) < 0 ||
            fathom_corpus_record(corpus, corpus->count - 1, &w->cov, full.exec_us) < 0) {
            fprintf(stderr, "fathom: failed to add interesting input\n");
            return -1;
        }
        w->stats.corpus_size = corpus->count;
        update_steer(w);
        if (strategy >= 0 && strategy < FATHOM_MUT_COUNT)
            fathom_mutator_reward(&w->mut, (fathom_mutation_t)strategy);
        if (w->cfg->verbose)
            fprintf(stderr, "%s%s[+] %zu new block(s), %zu/%zu covered, by %s, %zu bytes\n",
                    w->multi ? "" : "\n", w->prefix ? w->prefix : "", fresh,
                    w->stats.covered, w->stats.instrumented,
                    strategy >= 0 && strategy < FATHOM_MUT_COUNT ? strategy_names[strategy]
                                                                  : "?", len);
    }

    if (res.status == FATHOM_EXIT_CRASH)
        return note_crash(w, buf, len, &res) < 0 ? -1 : 0;
    if (res.status == FATHOM_EXIT_HANG) {
        w->stats.hangs++;
        if (fathom_corpus_save_hang(corpus, buf, len, fathom_coverage_hash(&w->cov)) < 0)
            return -1;
    }
    return 0;
}

/*
 * Parallel mode: run the queue entries peers added since the last sync
 * and keep those that reach something new here, as AFL's -M/-S do.
 */
static int sync_peers(worker_t *w, uint8_t *buf)
{
    for (uint32_t p = 0; p < w->opts->cfg.jobs; p++) {
        char dir[FATHOM_PATH_MAX], qdir[FATHOM_PATH_MAX + 16];
        if ((int)p == w->id || worker_dir(dir, sizeof(dir), w->opts->cfg.output_dir, p) < 0)
            continue;
        snprintf(qdir, sizeof(qdir), "%s/queue", dir);
        DIR *d = opendir(qdir);
        if (!d)
            continue;
        size_t next = w->peer_next[p];
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL && !stop_requested()) {
            size_t id, cov;
            if (sscanf(ent->d_name, "id_%zu_cov_%zu", &id, &cov) != 2 || id < w->peer_next[p])
                continue;
            if (id >= next)
                next = id + 1;

            char path[FATHOM_PATH_MAX + 300];
            snprintf(path, sizeof(path), "%s/%s", qdir, ent->d_name);
            FILE *fp = fopen(path, "rb");
            if (!fp)
                continue;
            size_t len = fread(buf, 1, g_max_input, fp);
            fclose(fp);

            fathom_exec_result_t res;
            arm_all(w);
            w->stats.total_execs++;
            int rc = fathom_exec_run(&w->ex, &w->cov, buf, len, &res);
            disarm_covered(w);
            if (rc < 0) {
                closedir(d);
                return -1;
            }
            if (res.status == FATHOM_EXIT_OK && fathom_coverage_has_new(&w->cov)) {
                double score = take_coverage(w);
                if (fathom_corpus_add(&w->corpus, buf, len, w->cov.new_blocks, score) < 0 ||
                    fathom_corpus_record(&w->corpus, w->corpus.count - 1, &w->cov,
                                         res.exec_us) < 0) {
                    closedir(d);
                    return -1;
                }
                disarm_covered(w);
                update_steer(w);
            }
        }
        closedir(d);
        w->peer_next[p] = next;
    }
    w->stats.corpus_size = w->corpus.count;
    return 0;
}

static int run_worker(const fathom_opts_t *opts, const fathom_config_t *cfg,
                      fathom_session_t *session, int worker_id, bool multi)
{
    int ret = 1;
    char prefix_buf[16];
    bool cov_ready = false, corpus_ready = false, ex_ready = false;
    uint8_t *buf = NULL;
    worker_t *w = calloc(1, sizeof(*w));
    if (!w)
        return 1;
    w->opts = opts;
    w->cfg = cfg;
    w->session = session;
    w->multi = multi;
    w->id = worker_id;
    fathom_dict_init(&w->frontier);
    if (multi) {
        snprintf(prefix_buf, sizeof(prefix_buf), "[w%03d]", worker_id);
        w->prefix = prefix_buf;
    }

    if (install_stop_handlers() < 0) {
        fprintf(stderr, "fathom: cannot install stop handlers\n");
        goto cleanup;
    }

    if (fathom_coverage_init(&w->cov, session->ana.cov_count) < 0) {
        fprintf(stderr, "fathom: coverage init failed\n");
        goto cleanup;
    }
    cov_ready = true;

    if (fathom_corpus_init(&w->corpus, cfg->input_dir, cfg->output_dir) < 0) {
        fprintf(stderr, "fathom: corpus init failed\n");
        goto cleanup;
    }
    corpus_ready = true;
    if (w->corpus.count == 0 &&
        fathom_corpus_add(&w->corpus, (const uint8_t *)"AAAA", 4, 0, 0) < 0)
        goto cleanup;

    fathom_mutator_init(&w->mut, &session->ana.dict);
    w->stats.mut = &w->mut;
    w->mut.frontier = &w->frontier;
    if (opts->have_seed) {
        fathom_mutator_seed(&w->mut, opts->seed + (uint64_t)worker_id);
        fathom_corpus_seed(&w->corpus, ~(opts->seed + (uint64_t)worker_id));
    }

    if (fathom_exec_init(&w->ex, cfg, &session->bin) < 0) {
        fprintf(stderr, "fathom: executor init failed\n");
        goto cleanup;
    }
    ex_ready = true;

    /* One breakpoint per instrumentable block; slot i ↔ cov_blocks[i]. */
    w->slot_block = malloc((session->ana.cov_count + 1) * sizeof(*w->slot_block));
    w->block_slot = malloc((session->cfg_graph.block_count + 1) * sizeof(*w->block_slot));
    w->epoch = calloc(session->ana.cov_count + 1, sizeof(*w->epoch));
    buf = malloc(g_max_input);
    if (!w->slot_block || !w->block_slot || !w->epoch || !buf) {
        fprintf(stderr, "fathom: out of memory\n");
        goto cleanup;
    }
    for (size_t i = 0; i < session->cfg_graph.block_count; i++)
        w->block_slot[i] = -1;
    for (size_t i = 0; i < session->ana.cov_count; i++) {
        uint32_t bid = session->ana.cov_blocks[i];
        int slot = fathom_exec_add_breakpoint(&w->ex, session->cfg_graph.blocks[bid].start_addr);
        if (slot < 0) {
            fprintf(stderr, "fathom: breakpoint setup failed\n");
            goto cleanup;
        }
        w->slot_block[slot] = bid;
        w->block_slot[bid] = slot;
    }
    /* Loop headers count their iterations, so a different trip count is new coverage. */
    w->peer_next = calloc(opts->cfg.jobs + 1, sizeof(*w->peer_next));
    w->counted = calloc(session->ana.cov_count + 1, sizeof(*w->counted));
    w->block_covered = calloc(session->cfg_graph.block_count + 1, sizeof(*w->block_covered));
    w->block_steer = calloc(session->cfg_graph.block_count + 1, sizeof(*w->block_steer));
    if (!w->counted || !w->block_covered || !w->block_steer || !w->peer_next)
        goto cleanup;
    for (size_t i = 0; i < session->ana.cov_count; i++) {
        const fathom_block_t *b = &session->cfg_graph.blocks[session->ana.cov_blocks[i]];
        if (b->is_loop_header && b->insn_count > 1)
            w->counted[i] = fathom_exec_count_hits(&w->ex, (int)i,
                                session->dis.insns[b->insn_start + 1].addr) == 0;
    }
    w->stats.instrumented = w->ex.bp_count;

    if (w->corpus.resumed)
        fprintf(stderr, "%s%sresuming %s: %zu queue entries, %zu unique crashes\n",
                w->prefix ? w->prefix : "", w->prefix ? " " : "  ", cfg->output_dir,
                w->corpus.count, w->corpus.unique_crashes);
    if (!multi)
        fprintf(stderr, "  seeds: %zu, breakpoints: %zu\n\nfuzzing started%s...\n\n",
                w->corpus.count, w->ex.bp_count,
                opts->max_secs ? "" : " (Ctrl-C to stop)");
    else if (cfg->verbose)
        fprintf(stderr, "%s seeds: %zu, output: %s\n", w->prefix, w->corpus.count,
                cfg->output_dir);

    w->stats.start_us = fathom_now_us();
    w->last_status = w->stats.start_us;
    w->deadline = opts->max_secs
                ? w->stats.start_us + (uint64_t)opts->max_secs * 1000000u : 0;

    if (calibrate(w) < 0) {
        fprintf(stderr, "fathom: target execution failed\n");
        goto cleanup;
    }
    if (w->corpus.count == 0 && !w->done && !stop_requested()) {
        /* Every seed crashed or hung: carry on from a neutral input. */
        if (fathom_corpus_add(&w->corpus, (const uint8_t *)"AAAA", 4, 0, 0) < 0 ||
            calibrate(w) < 0)
            goto cleanup;
        if (w->corpus.count == 0) {
            fprintf(stderr, "fathom: every seed crashes or hangs; nothing to fuzz\n");
            ret = w->corpus.unique_crashes > 0 ? 0 : 1;
            goto cleanup;
        }
    }
    w->stats.corpus_size = w->corpus.count;
    disarm_covered(w);
    update_steer(w);

    w->last_sync = fathom_now_us();
    while (!out_of_time(w)) {
        if (multi && fathom_now_us() - w->last_sync >= SYNC_INTERVAL_US) {
            if (sync_peers(w, buf) < 0) {
                fprintf(stderr, "fathom: target execution failed\n");
                goto cleanup;
            }
            w->last_sync = fathom_now_us();
        }
        fathom_input_t *inp = fathom_corpus_next(&w->corpus);
        size_t idx = (size_t)(inp - w->corpus.inputs);
        if (opts->trim && !inp->trimmed && trim_input(w, idx, buf) < 0) {
            fprintf(stderr, "fathom: target execution failed\n");
            goto cleanup;
        }
        uint32_t energy = fathom_corpus_energy(&w->corpus, idx);
        for (uint32_t e = 0; e < energy && !out_of_time(w); e++) {
            if (fuzz_one(w, idx, buf) < 0)
                goto cleanup;
        }
        w->corpus.inputs[idx].fuzz_count++;
    }

    if (!multi) {
        fathom_stats_t *st = &w->stats;
        fprintf(stderr, "\n\n=== Fathom session complete ===\n");
        fprintf(stderr, "  total execs:    %" PRIu64 "\n", st->total_execs);
        fprintf(stderr, "  coverage:       %zu/%zu blocks\n", st->covered, st->instrumented);
        fprintf(stderr, "  corpus size:    %zu\n", w->corpus.count);
        fprintf(stderr, "  crashes:        %" PRIu64 " (%" PRIu64 " unique)\n",
                st->crashes, st->unique_crashes);
        fprintf(stderr, "  hangs:          %" PRIu64 " (%zu saved)\n", st->hangs,
                w->corpus.unique_hangs);
        fprintf(stderr, "  output dir:     %s\n", cfg->output_dir);
    }
    /* Workers report crashes through their stats; the supervisor decides. */
    ret = !multi && opts->fail_on_crash && w->corpus.unique_crashes > 0 ? 2 : 0;

cleanup:
    if (corpus_ready) {
        w->stats.corpus_size = w->corpus.count;
        write_stats(cfg->output_dir, &w->stats);
    }
    free(buf);
    free(w->slot_block);
    free(w->block_slot);
    free(w->epoch);
    free(w->counted);
    free(w->peer_next);
    free(w->block_covered);
    free(w->block_steer);
    fathom_dict_destroy(&w->frontier);
    if (ex_ready)
        fathom_exec_destroy(&w->ex);
    if (corpus_ready)
        fathom_corpus_destroy(&w->corpus);
    if (cov_ready)
        fathom_coverage_destroy(&w->cov);
    free(w);
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

    bool signalled = false, first_done = false;
    for (int alive = launched; alive > 0;) {
        if ((stop_requested() || failed || first_done) && !signalled) {
            SetEvent(g_stop_event);
            signalled = true;
        }
        DWORD w = WaitForMultipleObjects((DWORD)launched, procs, FALSE, 200);
        if (w < WAIT_OBJECT_0 + (DWORD)launched) {   /* WAIT_OBJECT_0 is 0 */
            DWORD idx = w - WAIT_OBJECT_0, code = 1;
            GetExitCodeProcess(procs[idx], &code);
            failed |= code != 0;
            first_done |= opts->until_crash;   /* one finished worker stops all */
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

    bool first_done = false;   /* with --until-crash, one finished worker stops all */
    for (alive = launched; alive > 0;) {
        if ((g_stop || failed || first_done) && !forwarded) {
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
                first_done |= opts->until_crash;
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
        total.unique_crashes += w.unique_crashes;
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

    if (!ok)
        return 1;
    return opts->fail_on_crash && total.unique_crashes > 0 ? 2 : 0;
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
        {"trim",     no_argument,       NULL, 'R'},
        {"replay",   required_argument, NULL, 'P'},
        {"max-execs", required_argument, NULL, 'E'},
        {"max-input", required_argument, NULL, 'I'},
        {"fail-on-crash", no_argument,  NULL, 'F'},
        {"version",  no_argument,       NULL, 'V'},
        {"minimize", required_argument, NULL, 'M'},
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
        case 'R': opts.trim = true; break;
        case 'P': opts.replay = optarg; break;
        case 'E': opts.max_execs = strtoull(optarg, NULL, 0); break;
        case 'I':
            g_max_input = parse_u32(optarg, "input size", &ok);
            if (g_max_input == 0) {
                fprintf(stderr, "fathom: --max-input must be at least 1\n");
                ok = false;
            }
            break;
        case 'F': opts.fail_on_crash = true; break;
        case 'V':
            printf("fathom %d.%d.%d\n", FATHOM_VERSION_MAJOR, FATHOM_VERSION_MINOR,
                   FATHOM_VERSION_PATCH);
            return 0;
        case 'M': opts.minimize = optarg; break;
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
    if (opts.replay || opts.minimize)
        return run_replay(&opts, opts.minimize ? opts.minimize : opts.replay,
                          opts.minimize != NULL);

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
