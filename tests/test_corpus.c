/*
 * test_corpus.c — Unit tests for the corpus manager
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ftw.h>

#define PASS(name) fprintf(stderr, "  PASS  %s\n", (name))

/* ── Helpers ─────────────────────────────────────────────────────────── */

/*
 * nftw callback to remove files and directories.
 */
static int rm_cb(const char *path, const struct stat *sb,
                 int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

static void rmrf(const char *path)
{
    nftw(path, rm_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static char g_tmpdir[256];

static void make_tmpdir(void)
{
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/fathom_test_corpus_XXXXXX");
    assert(mkdtemp(g_tmpdir) != NULL);
}

static int dir_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/*
 * Count regular files in a directory (non-recursive).
 */
static int count_files(const char *dirpath)
{
    DIR *d = opendir(dirpath);
    if (!d) return -1;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            n++;
    }
    closedir(d);
    return n;
}

/* ── Test: init creates directories ─────────────────────────────────── */

static void test_init_creates_dirs(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    char qpath[PATH_MAX], cpath[PATH_MAX];
    snprintf(qpath, sizeof(qpath), "%s/queue", outdir);
    snprintf(cpath, sizeof(cpath), "%s/crashes", outdir);

    assert(dir_exists(qpath));
    assert(dir_exists(cpath));
    assert(corpus.count == 0);
    assert(corpus.capacity > 0);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("init_creates_dirs");
}

/* ── Test: init reads seed files ────────────────────────────────────── */

static void test_init_reads_seeds(void)
{
    make_tmpdir();
    char indir[512], outdir[512];
    snprintf(indir,  sizeof(indir),  "%s/in",  g_tmpdir);
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    mkdir(indir, 0755);

    /* Create a few seed files of different sizes. */
    const char *seeds[] = {"AAA", "B", "CCCCCC"};
    for (int i = 0; i < 3; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/seed_%d", indir, i);
        FILE *fp = fopen(path, "w");
        assert(fp);
        fwrite(seeds[i], 1, strlen(seeds[i]), fp);
        fclose(fp);
    }

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, indir, outdir) == 0);
    assert(corpus.count == 3);

    /* After init, seeds should be sorted by size: "B" (1), "AAA" (3), "CCCCCC" (6). */
    assert(corpus.inputs[0].len == 1);
    assert(corpus.inputs[1].len == 3);
    assert(corpus.inputs[2].len == 6);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("init_reads_seeds");
}

/* ── Test: add grows and writes to disk ─────────────────────────────── */

static void test_add_and_disk(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t data1[] = "hello";
    const uint8_t data2[] = "world!!!";
    assert(fathom_corpus_add(&corpus, data1, 5, 3) == 0);
    assert(fathom_corpus_add(&corpus, data2, 8, 10) == 0);

    assert(corpus.count == 2);

    /* Check that data was properly copied. */
    assert(corpus.inputs[0].len == 5);
    assert(memcmp(corpus.inputs[0].data, "hello", 5) == 0);
    assert(corpus.inputs[1].len == 8);
    assert(memcmp(corpus.inputs[1].data, "world!!!", 8) == 0);

    /* Input with more new edges should have higher priority. */
    assert(corpus.inputs[1].priority > corpus.inputs[0].priority);

    /* Queue directory should have 2 files. */
    char qpath[PATH_MAX];
    snprintf(qpath, sizeof(qpath), "%s/queue", outdir);
    assert(count_files(qpath) == 2);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("add_and_disk");
}

/* ── Test: add can grow beyond initial capacity ─────────────────────── */

static void test_add_grow(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    size_t initial_cap = corpus.capacity;
    for (size_t i = 0; i < initial_cap + 10; i++) {
        uint8_t byte = (uint8_t)(i & 0xFF);
        assert(fathom_corpus_add(&corpus, &byte, 1, 0) == 0);
    }

    assert(corpus.count == initial_cap + 10);
    assert(corpus.capacity > initial_cap);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("add_grow");
}

/* ── Test: next returns unfuzzed inputs first ───────────────────────── */

static void test_next_unfuzzed_first(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    /* Add three inputs with different priorities.
     * Edges:  data_a=1, data_b=5, data_c=0
     * Priority: a=11.0, b=51.0, c=1.0
     */
    const uint8_t a[] = "aaa";
    const uint8_t b[] = "bbbbb";
    const uint8_t c[] = "c";
    fathom_corpus_add(&corpus, a, 3, 1);
    fathom_corpus_add(&corpus, b, 5, 5);
    fathom_corpus_add(&corpus, c, 1, 0);

    /* First call: should return highest-priority unfuzzed => b (edges=5). */
    fathom_input_t *inp1 = fathom_corpus_next(&corpus);
    assert(inp1 != NULL);
    assert(inp1->len == 5);  /* b */
    assert(inp1->was_fuzzed == true);

    /* Second call: next highest unfuzzed => a (edges=1). */
    fathom_input_t *inp2 = fathom_corpus_next(&corpus);
    assert(inp2 != NULL);
    assert(inp2->len == 3);  /* a */
    assert(inp2->was_fuzzed == true);

    /* Third call: last unfuzzed => c (edges=0). */
    fathom_input_t *inp3 = fathom_corpus_next(&corpus);
    assert(inp3 != NULL);
    assert(inp3->len == 1);  /* c */
    assert(inp3->was_fuzzed == true);

    /* Fourth call: all fuzzed — round-robin. */
    fathom_input_t *inp4 = fathom_corpus_next(&corpus);
    assert(inp4 != NULL);

    /* Fifth call: should advance round-robin. */
    fathom_input_t *inp5 = fathom_corpus_next(&corpus);
    assert(inp5 != NULL);
    assert(inp5 != inp4);  /* different from previous */

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("next_unfuzzed_first");
}

/* ── Test: next on empty corpus returns NULL ────────────────────────── */

static void test_next_empty(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    assert(fathom_corpus_next(&corpus) == NULL);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("next_empty");
}

/* ── Test: crash dedup — same hash ──────────────────────────────────── */

static void test_crash_dedup_same_hash(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t crash_data[] = "CRASH_INPUT";
    uint64_t hash = 0xDEADBEEFCAFE0001ULL;

    /* First save — new. */
    int rc = fathom_corpus_save_crash(&corpus, crash_data,
                                      sizeof(crash_data) - 1, hash);
    assert(rc == 1);  /* 1 = newly inserted */
    assert(corpus.crash_count == 1);
    assert(corpus.unique_crashes == 1);

    /* Second save with same hash — duplicate. */
    rc = fathom_corpus_save_crash(&corpus, crash_data,
                                  sizeof(crash_data) - 1, hash);
    assert(rc == 0);  /* 0 = duplicate */
    assert(corpus.crash_count == 2);
    assert(corpus.unique_crashes == 1);  /* still 1 unique */

    /* Crash file should exist on disk. */
    char cpath[PATH_MAX];
    snprintf(cpath, sizeof(cpath), "%s/crashes", outdir);
    assert(count_files(cpath) == 1);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("crash_dedup_same_hash");
}

/* ── Test: crash dedup — different hashes ───────────────────────────── */

static void test_crash_dedup_diff_hash(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t crash1[] = "CRASH_A";
    const uint8_t crash2[] = "CRASH_B";
    const uint8_t crash3[] = "CRASH_C";

    assert(fathom_corpus_save_crash(&corpus, crash1, 7, 0xAAAA) == 1);
    assert(fathom_corpus_save_crash(&corpus, crash2, 7, 0xBBBB) == 1);
    assert(fathom_corpus_save_crash(&corpus, crash3, 7, 0xCCCC) == 1);

    assert(corpus.crash_count == 3);
    assert(corpus.unique_crashes == 3);

    /* Three crash files on disk. */
    char cpath[PATH_MAX];
    snprintf(cpath, sizeof(cpath), "%s/crashes", outdir);
    assert(count_files(cpath) == 3);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("crash_dedup_diff_hash");
}

/* ── Test: crash with hash 0 (edge case) ────────────────────────────── */

static void test_crash_hash_zero(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t data[] = "ZERO";

    /* Hash 0 should still work (internally mapped to 1). */
    int rc = fathom_corpus_save_crash(&corpus, data, 4, 0);
    assert(rc == 1);
    assert(corpus.unique_crashes == 1);

    /* Duplicate. */
    rc = fathom_corpus_save_crash(&corpus, data, 4, 0);
    assert(rc == 0);
    assert(corpus.unique_crashes == 1);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("crash_hash_zero");
}

/* ── Test: verify crash file contents ───────────────────────────────── */

static void test_crash_file_contents(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t data[] = "VERIFY_CONTENTS";
    uint64_t hash = 0x1234567890ABCDEFULL;

    fathom_corpus_save_crash(&corpus, data, sizeof(data) - 1, hash);

    char fpath[PATH_MAX];
    snprintf(fpath, sizeof(fpath), "%s/crashes/crash_%016lx",
             outdir, (unsigned long)hash);
    assert(file_exists(fpath));

    /* Read back and verify. */
    FILE *fp = fopen(fpath, "rb");
    assert(fp);
    uint8_t buf[64];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    assert(n == sizeof(data) - 1);
    assert(memcmp(buf, data, n) == 0);

    fathom_corpus_destroy(&corpus);
    rmrf(g_tmpdir);
    PASS("crash_file_contents");
}

/* ── Test: destroy cleans up state ──────────────────────────────────── */

static void test_destroy(void)
{
    make_tmpdir();
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/out", g_tmpdir);

    fathom_corpus_t corpus;
    assert(fathom_corpus_init(&corpus, NULL, outdir) == 0);

    const uint8_t data[] = "test";
    fathom_corpus_add(&corpus, data, 4, 1);
    fathom_corpus_add(&corpus, data, 4, 2);

    fathom_corpus_destroy(&corpus);

    assert(corpus.inputs == NULL);
    assert(corpus.out_dir == NULL);
    assert(corpus.count == 0);
    assert(corpus.capacity == 0);

    rmrf(g_tmpdir);
    PASS("destroy");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    fprintf(stderr, "=== test_corpus ===\n");

    test_init_creates_dirs();
    test_init_reads_seeds();
    test_add_and_disk();
    test_add_grow();
    test_next_unfuzzed_first();
    test_next_empty();
    test_crash_dedup_same_hash();
    test_crash_dedup_diff_hash();
    test_crash_hash_zero();
    test_crash_file_contents();
    test_destroy();

    fprintf(stderr, "All corpus tests passed.\n");
    return 0;
}
