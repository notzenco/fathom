/*
 * trim.c — Shrink an input while it keeps the same behaviour
 *
 * AFL's trimming: delete chunks from large to small, keeping each
 * deletion that leaves the run's path (fathom_coverage_hash) unchanged.
 * Smaller inputs are faster to run and give mutations fewer bytes that
 * do not matter.  Minimising a crash is the same search, keeping
 * deletions that still crash with the same crash hash.
 */

#include "fathom.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TRIM_MIN_BYTES   4      /* never trim inputs smaller than this */
#define TRIM_START_STEPS 16     /* first chunk is len/16 */
#define TRIM_END_STEPS   1024   /* last chunk is len/1024, at least TRIM_MIN_BYTES */

static size_t next_pow2(size_t v)
{
    size_t p = 1;
    while (p < v)
        p <<= 1;
    return p;
}

typedef struct {
    bool     crash;   /* keep runs that crash with hash, not ones that exit with path hash */
    uint64_t hash;
} keep_t;

static bool keeps(fathom_coverage_t *cov, const fathom_exec_result_t *res, const keep_t *k)
{
    if (k->crash)
        return res->status == FATHOM_EXIT_CRASH && res->crash_hash == k->hash;
    return res->status == FATHOM_EXIT_OK && fathom_coverage_hash(cov) == k->hash;
}

static int shrink(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf, size_t *len,
                  const keep_t *k, size_t min_step, uint32_t max_execs, uint64_t *execs)
{
    size_t step = next_pow2(*len) / TRIM_START_STEPS;
    if (step < min_step)
        step = min_step;
    size_t last = next_pow2(*len) / TRIM_END_STEPS;
    if (last < min_step)
        last = min_step;

    uint8_t *trial = NULL;
    for (; step >= last && *execs < max_execs; step /= 2) {
        for (size_t pos = 0; pos < *len && *execs < max_execs;) {
            size_t cut = step < *len - pos ? step : *len - pos;
            size_t n = *len - cut;
            if (!trial && !(trial = malloc(*len)))
                return -1;
            memcpy(trial, buf, pos);
            memcpy(trial + pos, buf + pos + cut, *len - pos - cut);

            fathom_exec_result_t res;
            (*execs)++;
            if (fathom_exec_run(ex, cov, trial, n, &res) < 0) {
                free(trial);
                return -1;
            }
            if (keeps(cov, &res, k)) {
                memcpy(buf, trial, n);
                *len = n;   /* the next chunk has moved to pos */
            } else {
                pos += step;
            }
        }
        if (step == last)
            break;
    }
    free(trial);
    return 0;
}

int fathom_trim(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf, size_t *len,
                uint64_t want_hash, uint32_t max_execs, uint64_t *execs)
{
    if (*len < TRIM_MIN_BYTES)
        return 0;
    keep_t k = { false, want_hash };
    return shrink(ex, cov, buf, len, &k, TRIM_MIN_BYTES, max_execs, execs);
}

int fathom_minimize(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf,
                    size_t *len, uint64_t crash_hash, uint32_t max_execs,
                    uint64_t *execs)
{
    keep_t k = { true, crash_hash };
    /* Repeat until a pass removes nothing: each removal can enable others. */
    for (size_t before = SIZE_MAX; *len && *len != before && *execs < max_execs;) {
        before = *len;
        if (shrink(ex, cov, buf, len, &k, 1, max_execs, execs) < 0)
            return -1;
    }
    return 0;
}
