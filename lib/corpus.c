/*
 * corpus.c — Seed queue and crash management
 *
 * Maintains the set of interesting inputs (seeds), prioritises them
 * for fuzzing, and saves crash inputs to disk with deduplication via
 * a lightweight hash set.
 */

#include "corpus.h"
#include "osdep.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
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

static int hashset_grow(fathom_hashset_t *hs)
{
    size_t cap = hs->capacity * 2;
    uint64_t *slots = calloc(cap, sizeof(uint64_t));
    if (!slots)
        return -1;
    for (size_t i = 0; i < hs->capacity; i++) {
        uint64_t h = hs->slots[i];
        if (!h)
            continue;
        size_t idx = (size_t)(h % cap);
        while (slots[idx])
            idx = (idx + 1) % cap;
        slots[idx] = h;
    }
    free(hs->slots);
    hs->slots    = slots;
    hs->capacity = cap;
    return 0;
}

int fathom_hashset_insert(fathom_hashset_t *hs, uint64_t hash)
{
    if (fathom_hashset_contains(hs, hash))
        return 0;   /* already present */

    if (hs->count + 1 > hs->capacity * 3 / 4 && hashset_grow(hs) < 0)
        return -1;

    hash = sanitize_hash(hash);
    size_t idx = (size_t)(hash % hs->capacity);
    while (hs->slots[idx])
        idx = (idx + 1) % hs->capacity;
    hs->slots[idx] = hash;
    hs->count++;
    return 1;
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
static fathom_hashset_t g_hang_hashes;
static bool             g_crash_hashes_ready;

/* ── Loading ────────────────────────────────────────────────────────── */

static int add_existing(fathom_corpus_t *corpus, const uint8_t *data, size_t len,
                        const char *path, size_t id, size_t cov)
{
    const char *out = corpus->out_dir;
    corpus->out_dir = NULL;   /* already on disk: do not write it again */
    int rc = fathom_corpus_add(corpus, data, len, cov, 0);
    corpus->out_dir = out;
    if (rc < 0)
        return -1;
    fathom_input_t *inp = &corpus->inputs[corpus->count - 1];
    if (!(inp->path = strdup(path)))
        return -1;
    if (id >= corpus->next_id)
        corpus->next_id = id + 1;
    return 0;
}

/*
 * Read every regular, non-hidden file in dir as an input, smallest
 * first.  With queue set, dir is our own queue: names carry the id and
 * coverage, and the files stay where they are.
 */
static int load_dir(fathom_corpus_t *corpus, const char *dir_path, bool queue)
{
    DIR *dir = opendir(dir_path);
    if (!dir) {
        if (!queue)   /* not fatal: the caller may add seeds itself */
            fprintf(stderr, "fathom: cannot open input dir '%s': %s\n",
                    dir_path, strerror(errno));
        return 0;
    }

    size_t first = corpus->count;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        size_t id = 0, cov = 0;
        if (queue && sscanf(ent->d_name, "id_%zu_cov_%zu", &id, &cov) != 2)
            continue;

        char filepath[4096];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, ent->d_name);
        struct stat st;
        if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        uint8_t *data = NULL;
        ssize_t  sz   = read_file(filepath, &data);
        if (sz < 0)
            continue;
        int rc = queue ? add_existing(corpus, data, (size_t)sz, filepath, id, cov)
                       : fathom_corpus_add(corpus, data, (size_t)sz, 0, 0);
        free(data);
        if (rc < 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);

    /* Smaller inputs first: faster to fuzz. */
    if (corpus->count - first > 1)
        qsort(corpus->inputs + first, corpus->count - first,
              sizeof(fathom_input_t), cmp_input_by_size);
    return 0;
}

/* Rebuild a dedup set from file names "<prefix><16 hex digits>" in dir. */
static int load_hashes(const char *dir_path, const char *prefix, fathom_hashset_t *set,
                       size_t *count)
{
    DIR *dir = opendir(dir_path);
    if (!dir)
        return 0;
    struct dirent *ent;
    int rc = 0;
    size_t plen = strlen(prefix);
    while (rc == 0 && (ent = readdir(dir)) != NULL) {
        unsigned long long hash;
        char rest;
        if (strncmp(ent->d_name, prefix, plen) != 0 ||
            sscanf(ent->d_name + plen, "%16llx%c", &hash, &rest) != 1)
            continue;   /* reports and anything else */
        int r = fathom_hashset_insert(set, (uint64_t)hash);
        if (r < 0)
            rc = -1;
        else if (r == 1)
            (*count)++;
    }
    closedir(dir);
    return rc;
}

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
    fathom_corpus_seed(corpus, fathom_entropy());

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
        fathom_mkdir(path);

        snprintf(path, sizeof(path), "%s/queue", output_dir);
        fathom_mkdir(path);

        snprintf(path, sizeof(path), "%s/crashes", output_dir);
        fathom_mkdir(path);

        snprintf(path, sizeof(path), "%s/hangs", output_dir);
        fathom_mkdir(path);
    }

    /* Initialise crash hash set. */
    if (!g_crash_hashes_ready) {
        if (fathom_hashset_init(&g_crash_hashes, FATHOM_CRASH_HASHSET_CAP) < 0 ||
            fathom_hashset_init(&g_hang_hashes, FATHOM_CRASH_HASHSET_CAP) < 0) {
            fathom_hashset_destroy(&g_crash_hashes);
            free(corpus->inputs);
            free((void *)corpus->out_dir);
            return -1;
        }
        g_crash_hashes_ready = true;
    }

    /*
     * An output directory that already has a queue is resumed: its queue
     * replaces the seeds, numbering continues after it, and crashes
     * already saved stay known.
     */
    if (output_dir) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/queue", output_dir);
        if (load_dir(corpus, path, true) < 0)
            return -1;
        corpus->resumed = corpus->count > 0;
        snprintf(path, sizeof(path), "%s/crashes", output_dir);
        if (load_hashes(path, "crash_", &g_crash_hashes, &corpus->unique_crashes) < 0)
            return -1;
        snprintf(path, sizeof(path), "%s/hangs", output_dir);
        if (load_hashes(path, "hang_", &g_hang_hashes, &corpus->unique_hangs) < 0)
            return -1;
    }
    if (input_dir && !corpus->resumed && load_dir(corpus, input_dir, false) < 0)
        return -1;
    return 0;
}

void fathom_corpus_destroy(fathom_corpus_t *corpus)
{
    for (size_t i = 0; i < corpus->count; i++) {
        free(corpus->inputs[i].data);
        free(corpus->inputs[i].path);
        free(corpus->inputs[i].slots);
    }

    free(corpus->inputs);
    free((void *)corpus->out_dir);

    corpus->inputs   = NULL;
    corpus->out_dir  = NULL;
    corpus->count    = 0;
    corpus->capacity = 0;
    corpus->current  = 0;

    if (g_crash_hashes_ready) {
        fathom_hashset_destroy(&g_crash_hashes);
        fathom_hashset_destroy(&g_hang_hashes);
        g_crash_hashes_ready = false;
    }
}

int fathom_corpus_add(fathom_corpus_t *corpus, const uint8_t *data,
                      size_t len, size_t new_blocks, double score)
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
    inp->new_coverage = new_blocks;
    inp->was_fuzzed   = false;
    inp->exec_us      = 0;

    /*
     * Priority: inputs that reach more new blocks, and blocks the static
     * analysis scored as interesting (dangerous calls, loops, error
     * paths), are fuzzed first.  Base priority of 1.0 keeps seeds usable.
     */
    inp->priority = 1.0 + (double)new_blocks * 10.0 + score;

    inp->favored      = true;   /* until a recorded run says otherwise */

    /* Save to queue directory if we have an output dir. */
    if (corpus->out_dir) {
        char path[4096];
        /* AFL uses "id:...", but ':' is not allowed in Windows file names. */
        snprintf(path, sizeof(path), "%s/queue/id_%06zu_cov_%zu",
                 corpus->out_dir, corpus->next_id, new_blocks);
        inp->path = strdup(path);
        write_file(path, data, len);
    }

    corpus->next_id++;
    corpus->count++;
    corpus->cull_dirty = true;
    return 0;
}

/* ── Scheduling ─────────────────────────────────────────────────────── */

static uint64_t corpus_rand(fathom_corpus_t *corpus)
{
    uint64_t x = corpus->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    corpus->rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}

void fathom_corpus_seed(fathom_corpus_t *corpus, uint64_t seed)
{
    seed += 0x9E3779B97F4A7C15ULL;
    seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
    seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EBULL;
    seed ^= seed >> 31;
    corpus->rng = seed ? seed : 1;
}

int fathom_corpus_record(fathom_corpus_t *corpus, size_t idx,
                         const fathom_coverage_t *cov, uint64_t exec_us)
{
    fathom_input_t *inp = &corpus->inputs[idx];
    size_t n = 0;
    for (size_t i = 0; i < cov->size; i++)
        n += cov->local[i] != 0;
    uint32_t *slots = malloc((n ? n : 1) * sizeof(*slots));
    if (!slots)
        return -1;
    n = 0;
    for (size_t i = 0; i < cov->size; i++) {
        if (cov->local[i])
            slots[n++] = (uint32_t)i;
    }
    free(inp->slots);
    inp->slots = slots;
    inp->slot_count = n;
    inp->trace_hash = fathom_coverage_hash(cov);
    inp->exec_us = exec_us ? exec_us : 1;
    corpus->map_size = cov->size;
    corpus->cull_dirty = true;
    return 0;
}

int fathom_corpus_update(fathom_corpus_t *corpus, size_t idx,
                         const uint8_t *data, size_t len)
{
    fathom_input_t *inp = &corpus->inputs[idx];
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy)
        return -1;
    if (len)
        memcpy(copy, data, len);
    free(inp->data);
    inp->data = copy;
    inp->len = len;
    inp->trimmed = true;
    corpus->cull_dirty = true;
    if (inp->path && write_file(inp->path, data, len) < 0)
        return -1;
    return 0;
}

void fathom_corpus_remove(fathom_corpus_t *corpus, size_t idx)
{
    fathom_input_t *inp = &corpus->inputs[idx];
    if (inp->path)
        remove(inp->path);
    free(inp->data);
    free(inp->path);
    free(inp->slots);
    memmove(inp, inp + 1, (corpus->count - idx - 1) * sizeof(*inp));
    corpus->count--;
    if (corpus->current > idx)
        corpus->current--;
    if (corpus->current >= corpus->count)
        corpus->current = 0;
    corpus->cull_dirty = true;
}

static double input_cost(const fathom_input_t *inp)
{
    return (double)(inp->exec_us + 1) * (double)(inp->len + 1);
}

/*
 * AFL's queue culling: give every reached slot its cheapest input, then
 * favor a greedy subset of those that together reach every slot.
 */
static void cull(fathom_corpus_t *corpus)
{
    if (!corpus->cull_dirty)
        return;
    corpus->cull_dirty = false;

    size_t m = corpus->map_size;
    size_t *top = m ? malloc(m * sizeof(*top)) : NULL;
    bool *done = m ? calloc(m, sizeof(*done)) : NULL;
    for (size_t i = 0; i < corpus->count; i++)
        corpus->inputs[i].favored = corpus->inputs[i].slots == NULL;
    if (!top || !done) {
        free(top);
        free(done);
        for (size_t i = 0; i < corpus->count; i++)
            corpus->inputs[i].favored = true;   /* no memory: fuzz everything */
        return;
    }

    for (size_t s = 0; s < m; s++)
        top[s] = SIZE_MAX;
    for (size_t i = 0; i < corpus->count; i++) {
        const fathom_input_t *inp = &corpus->inputs[i];
        for (size_t k = 0; k < inp->slot_count; k++) {
            size_t s = inp->slots[k];
            if (s < m && (top[s] == SIZE_MAX ||
                          input_cost(inp) < input_cost(&corpus->inputs[top[s]])))
                top[s] = i;
        }
    }
    for (size_t s = 0; s < m; s++) {
        if (top[s] == SIZE_MAX || done[s])
            continue;
        fathom_input_t *inp = &corpus->inputs[top[s]];
        inp->favored = true;
        for (size_t k = 0; k < inp->slot_count; k++) {
            if (inp->slots[k] < m)
                done[inp->slots[k]] = true;
        }
    }
    free(top);
    free(done);
}

uint32_t fathom_corpus_energy(const fathom_corpus_t *corpus, size_t idx)
{
    const fathom_input_t *inp = &corpus->inputs[idx];
    double sum_us = 0, sum_cov = 0;
    size_t traced = 0;
    for (size_t i = 0; i < corpus->count; i++) {
        if (corpus->inputs[i].slots) {
            sum_us += (double)corpus->inputs[i].exec_us;
            sum_cov += (double)corpus->inputs[i].slot_count;
            traced++;
        }
    }

    /* AFL's calculate_score, in spirit: speed and coverage relative to the queue. */
    double e = FATHOM_ENERGY_BASE;
    if (inp->slots && traced) {
        double us = (double)inp->exec_us, avg_us = sum_us / (double)traced;
        if (us * 0.1 > avg_us)       e *= 0.1;
        else if (us * 0.25 > avg_us) e *= 0.25;
        else if (us * 0.5 > avg_us)  e *= 0.5;
        else if (us * 0.75 > avg_us) e *= 0.75;
        else if (us * 4 < avg_us)    e *= 3;
        else if (us * 3 < avg_us)    e *= 2;
        else if (us * 2 < avg_us)    e *= 1.5;

        double c = (double)inp->slot_count, avg_c = sum_cov / (double)traced;
        if (c * 0.3 > avg_c)         e *= 3;
        else if (c * 0.5 > avg_c)    e *= 2;
        else if (c * 0.75 > avg_c)   e *= 1.5;
        else if (c * 3 < avg_c)      e *= 0.25;
        else if (c * 2 < avg_c)      e *= 0.5;
        else if (c * 1.5 < avg_c)    e *= 0.75;
    }

    /* Static analysis: new blocks and high-scoring ones (see fathom_corpus_add). */
    double bonus = inp->priority - 1.0;
    if (bonus > 40)
        bonus = 40;
    e *= 1.0 + bonus / 20.0;
    double steer = inp->steer > FATHOM_STEER_MAX ? FATHOM_STEER_MAX : inp->steer;
    e *= 1.0 + steer / (FATHOM_STEER_MAX / 2);
    if (inp->fuzz_count == 0)
        e *= 2;

    if (e < 1)
        e = 1;
    if (e > FATHOM_ENERGY_MAX)
        e = FATHOM_ENERGY_MAX;
    return (uint32_t)e;
}

fathom_input_t *fathom_corpus_next(fathom_corpus_t *corpus)
{
    if (corpus->count == 0)
        return NULL;
    cull(corpus);

    /* Unfuzzed favored inputs first, highest priority first. */
    size_t best = SIZE_MAX;
    for (size_t i = 0; i < corpus->count; i++) {
        const fathom_input_t *inp = &corpus->inputs[i];
        if (inp->favored && !inp->was_fuzzed &&
            (best == SIZE_MAX || inp->priority > corpus->inputs[best].priority))
            best = i;
    }

    /*
     * Otherwise cycle through the queue, taking favored inputs and only
     * occasionally the rest: 25% for an input never fuzzed, 5% after.
     */
    for (size_t tries = 0; best == SIZE_MAX && tries < 64 * corpus->count; tries++) {
        size_t i = corpus->current;
        corpus->current = (corpus->current + 1) % corpus->count;
        const fathom_input_t *inp = &corpus->inputs[i];
        uint32_t pct = inp->was_fuzzed ? 5 : 25;
        if (inp->favored || corpus_rand(corpus) % 100 < pct)
            best = i;
    }
    if (best == SIZE_MAX)
        best = corpus->current;

    corpus->current = (best + 1) % corpus->count;
    corpus->inputs[best].was_fuzzed = true;
    return &corpus->inputs[best];
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
        snprintf(path, sizeof(path), "%s/crashes/crash_%016" PRIx64,
                 corpus->out_dir, hash);
        if (write_file(path, data, len) < 0)
            return -1;
    }

    return 1;
}

int fathom_corpus_describe_crash(fathom_corpus_t *corpus, uint64_t hash, const char *text)
{
    if (!corpus->out_dir)
        return 0;
    char path[4096];
    snprintf(path, sizeof(path), "%s/crashes/crash_%016" PRIx64 ".txt", corpus->out_dir, hash);
    return write_file(path, (const uint8_t *)text, strlen(text));
}

int fathom_corpus_save_hang(fathom_corpus_t *corpus, const uint8_t *data,
                            size_t len, uint64_t hash)
{
    if (!g_crash_hashes_ready || corpus->unique_hangs >= FATHOM_MAX_HANGS)
        return 0;
    int rc = fathom_hashset_insert(&g_hang_hashes, hash);
    if (rc <= 0)
        return rc;
    corpus->unique_hangs++;
    if (corpus->out_dir) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/hangs/hang_%016" PRIx64, corpus->out_dir, hash);
        if (write_file(path, data, len) < 0)
            return -1;
    }
    return 1;
}
