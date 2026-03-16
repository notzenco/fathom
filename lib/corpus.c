/*
 * corpus.c — Seed queue and crash management
 *
 * Maintains the set of interesting inputs (seeds), prioritises them
 * for fuzzing, and saves crash inputs to disk with deduplication via
 * a lightweight hash set.
 */

#include "corpus.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

/* ── Hash set (open-addressing, linear probing) ─────────────────────── */

int fathom_hashset_init(fathom_hashset_t *hs, size_t capacity)
{
    hs->slots = calloc(capacity, sizeof(uint64_t));
    if (!hs->slots)
        return -1;
    hs->capacity = capacity;
    hs->count    = 0;
    return 0;
}

void fathom_hashset_destroy(fathom_hashset_t *hs)
{
    free(hs->slots);
    hs->slots    = NULL;
    hs->capacity = 0;
    hs->count    = 0;
}

/*
 * Map 0 -> 1 so that 0 can serve as the empty sentinel.
 */
static uint64_t sanitize_hash(uint64_t h)
{
    return h == 0 ? 1 : h;
}

int fathom_hashset_insert(fathom_hashset_t *hs, uint64_t hash)
{
    hash = sanitize_hash(hash);

    if (hs->count >= hs->capacity * 3 / 4)
        return -1;  /* too full */

    size_t idx = (size_t)(hash % hs->capacity);
    for (size_t i = 0; i < hs->capacity; i++) {
        size_t slot = (idx + i) % hs->capacity;
        if (hs->slots[slot] == 0) {
            hs->slots[slot] = hash;
            hs->count++;
            return 1;   /* newly inserted */
        }
        if (hs->slots[slot] == hash)
            return 0;   /* already present */
    }
    return -1;  /* should not reach here if load < 75% */
}

bool fathom_hashset_contains(const fathom_hashset_t *hs, uint64_t hash)
{
    hash = sanitize_hash(hash);

    size_t idx = (size_t)(hash % hs->capacity);
    for (size_t i = 0; i < hs->capacity; i++) {
        size_t slot = (idx + i) % hs->capacity;
        if (hs->slots[slot] == 0)
            return false;
        if (hs->slots[slot] == hash)
            return true;
    }
    return false;
}

/* ── File helpers ───────────────────────────────────────────────────── */

/*
 * Create a directory (and parents as needed).  Returns 0 on success or
 * if the directory already exists.
 */
static int mkdirs(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;

    /* Try to create; EEXIST is fine (race with another process). */
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;

    return -1;
}

/*
 * Read an entire file into a malloc'd buffer.  Caller frees.
 * Returns the number of bytes read, or -1 on failure.
 */
static ssize_t read_file(const char *path, uint8_t **out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = malloc((size_t)sz > 0 ? (size_t)sz : 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    *out = buf;
    return (ssize_t)n;
}

/*
 * Write a buffer to a file.  Returns 0 on success.
 */
static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/* ── qsort comparator: smaller inputs first ─────────────────────────── */

static int cmp_input_by_size(const void *a, const void *b)
{
    const fathom_input_t *ia = a;
    const fathom_input_t *ib = b;
    if (ia->len < ib->len) return -1;
    if (ia->len > ib->len) return  1;
    return 0;
}

/* ── Corpus hash set (stored alongside corpus; static file scope) ──── */

/*
 * We embed the crash hash set as a file-scope variable keyed by the
 * corpus pointer's out_dir.  For simplicity (single-fuzzer process),
 * we use a single global instance.
 */
static fathom_hashset_t g_crash_hashes;
static bool             g_crash_hashes_ready;

/* ── Public API ─────────────────────────────────────────────────────── */

int fathom_corpus_init(fathom_corpus_t *corpus, const char *input_dir,
                       const char *output_dir)
{
    memset(corpus, 0, sizeof(*corpus));

    corpus->inputs   = calloc(FATHOM_CORPUS_INIT_CAP, sizeof(fathom_input_t));
    if (!corpus->inputs)
        return -1;
    corpus->capacity = FATHOM_CORPUS_INIT_CAP;
    corpus->count    = 0;
    corpus->current  = 0;

    /* Duplicate the output dir string so corpus owns it. */
    if (output_dir) {
        corpus->out_dir = strdup(output_dir);
        if (!corpus->out_dir) {
            free(corpus->inputs);
            return -1;
        }

        /* Create output directory structure. */
        char path[4096];

        snprintf(path, sizeof(path), "%s", output_dir);
        mkdirs(path);

        snprintf(path, sizeof(path), "%s/queue", output_dir);
        mkdirs(path);

        snprintf(path, sizeof(path), "%s/crashes", output_dir);
        mkdirs(path);
    }

    /* Initialise crash hash set. */
    if (!g_crash_hashes_ready) {
        if (fathom_hashset_init(&g_crash_hashes, FATHOM_CRASH_HASHSET_CAP) < 0) {
            free(corpus->inputs);
            free((void *)corpus->out_dir);
            return -1;
        }
        g_crash_hashes_ready = true;
    }

    /* If input_dir provided, read all files from it as initial seeds. */
    if (input_dir) {
        DIR *dir = opendir(input_dir);
        if (!dir) {
            /* Not fatal — caller may add seeds manually. */
            fprintf(stderr, "fathom: cannot open input dir '%s': %s\n",
                    input_dir, strerror(errno));
            return 0;
        }

        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            /* Skip . and .. and hidden files. */
            if (ent->d_name[0] == '.')
                continue;

            char filepath[4096];
            snprintf(filepath, sizeof(filepath), "%s/%s",
                     input_dir, ent->d_name);

            struct stat st;
            if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
                continue;

            uint8_t *data = NULL;
            ssize_t  sz   = read_file(filepath, &data);
            if (sz < 0)
                continue;

            fathom_corpus_add(corpus, data, (size_t)sz, 0);
            free(data);
        }
        closedir(dir);

        /* Sort seeds by size (smaller first — faster to fuzz). */
        if (corpus->count > 1)
            qsort(corpus->inputs, corpus->count,
                  sizeof(fathom_input_t), cmp_input_by_size);
    }

    return 0;
}

void fathom_corpus_destroy(fathom_corpus_t *corpus)
{
    for (size_t i = 0; i < corpus->count; i++)
        free(corpus->inputs[i].data);

    free(corpus->inputs);
    free((void *)corpus->out_dir);

    corpus->inputs   = NULL;
    corpus->out_dir  = NULL;
    corpus->count    = 0;
    corpus->capacity = 0;
    corpus->current  = 0;

    if (g_crash_hashes_ready) {
        fathom_hashset_destroy(&g_crash_hashes);
        g_crash_hashes_ready = false;
    }
}

int fathom_corpus_add(fathom_corpus_t *corpus, const uint8_t *data,
                      size_t len, size_t new_edges)
{
    /* Grow if needed. */
    if (corpus->count >= corpus->capacity) {
        size_t new_cap = corpus->capacity * FATHOM_CORPUS_GROW;
        fathom_input_t *tmp = realloc(corpus->inputs,
                                       new_cap * sizeof(fathom_input_t));
        if (!tmp)
            return -1;
        corpus->inputs   = tmp;
        corpus->capacity = new_cap;
    }

    fathom_input_t *inp = &corpus->inputs[corpus->count];
    memset(inp, 0, sizeof(*inp));

    inp->data = malloc(len > 0 ? len : 1);
    if (!inp->data)
        return -1;

    if (len > 0)
        memcpy(inp->data, data, len);
    inp->len          = len;
    inp->new_coverage = new_edges;
    inp->was_fuzzed   = false;
    inp->exec_us      = 0;

    /*
     * Priority: inputs that discover more new edges get a higher
     * priority.  Base priority of 1.0 so even 0-edge seeds are usable.
     */
    inp->priority = 1.0 + (double)new_edges * 10.0;

    /* Save to queue directory if we have an output dir. */
    if (corpus->out_dir) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/queue/id:%06zu,edges:%zu",
                 corpus->out_dir, corpus->count, new_edges);
        write_file(path, data, len);
    }

    corpus->count++;
    return 0;
}

fathom_input_t *fathom_corpus_next(fathom_corpus_t *corpus)
{
    if (corpus->count == 0)
        return NULL;

    /*
     * Phase 1: find the next unfuzzed input with highest priority.
     * We scan starting from corpus->current and wrap around.
     */
    fathom_input_t *best_unfuzzed = NULL;
    for (size_t i = 0; i < corpus->count; i++) {
        size_t idx = (corpus->current + i) % corpus->count;
        fathom_input_t *inp = &corpus->inputs[idx];
        if (!inp->was_fuzzed) {
            if (!best_unfuzzed || inp->priority > best_unfuzzed->priority)
                best_unfuzzed = inp;
        }
    }

    if (best_unfuzzed) {
        best_unfuzzed->was_fuzzed = true;
        /* Advance current past this input for next call's starting scan. */
        for (size_t i = 0; i < corpus->count; i++) {
            if (&corpus->inputs[i] == best_unfuzzed) {
                corpus->current = (i + 1) % corpus->count;
                break;
            }
        }
        return best_unfuzzed;
    }

    /*
     * Phase 2: all inputs have been fuzzed — round-robin cycle.
     */
    fathom_input_t *inp = &corpus->inputs[corpus->current];
    corpus->current = (corpus->current + 1) % corpus->count;
    return inp;
}

int fathom_corpus_save_crash(fathom_corpus_t *corpus, const uint8_t *data,
                             size_t len, uint64_t hash)
{
    corpus->crash_count++;

    if (!g_crash_hashes_ready)
        return -1;

    int rc = fathom_hashset_insert(&g_crash_hashes, hash);
    if (rc == 0) {
        /* Duplicate hash — already seen. */
        return 0;
    }
    if (rc < 0)
        return -1;

    /* New unique crash. */
    corpus->unique_crashes++;

    if (corpus->out_dir) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/crashes/crash_%016lx",
                 corpus->out_dir, (unsigned long)hash);
        if (write_file(path, data, len) < 0)
            return -1;
    }

    return 1;
}
