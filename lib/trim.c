/*
 * trim.c — Shrink an input while it keeps the same coverage
 *
 * AFL's trimming: delete chunks from large to small, keeping each
 * deletion that leaves the run's path (fathom_coverage_hash) unchanged.
 * Smaller inputs are faster to run and give mutations fewer bytes that
 * do not matter.
 */

#include "fathom.h"

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

int fathom_trim(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf, size_t *len,
                uint64_t want_hash, uint32_t max_execs, uint64_t *execs)
{
    if (*len < TRIM_MIN_BYTES)
        return 0;

    size_t step = next_pow2(*len) / TRIM_START_STEPS;
    if (step < TRIM_MIN_BYTES)
        step = TRIM_MIN_BYTES;
    size_t last = next_pow2(*len) / TRIM_END_STEPS;
    if (last < TRIM_MIN_BYTES)
        last = TRIM_MIN_BYTES;

    uint8_t *trial = NULL;
    for (; step >= last && *execs < max_execs; step /= 2) {
        for (size_t pos = step; pos < *len && *execs < max_execs;) {
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
            if (res.status == FATHOM_EXIT_OK && fathom_coverage_hash(cov) == want_hash) {
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
