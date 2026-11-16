/*
 * coverage.c — Block coverage map
 *
 * The executor marks slot i of the local map when breakpoint i is hit
 * during a run.  After each run the fuzzer compares the local map with
 * the cumulative global map to detect newly reached blocks.  Values are
 * classified into AFL-style buckets so the map can also carry hit
 * counts if a future backend records them.
 */

#include "coverage.h"

#include <stdlib.h>
#include <string.h>

int fathom_coverage_init(fathom_coverage_t *cov, size_t size)
{
    memset(cov, 0, sizeof(*cov));
    cov->size   = size ? size : 1;
    cov->local  = calloc(1, cov->size);
    cov->global = calloc(1, cov->size);
    if (!cov->local || !cov->global) {
        fathom_coverage_destroy(cov);
        return -1;
    }
    return 0;
}

void fathom_coverage_destroy(fathom_coverage_t *cov)
{
    free(cov->local);
    free(cov->global);
    cov->local  = NULL;
    cov->global = NULL;
    cov->size   = 0;
}

void fathom_coverage_reset_local(fathom_coverage_t *cov)
{
    memset(cov->local, 0, cov->size);
}

/*
 * A run is new when any classified local value has a bit the global
 * map has not yet recorded.
 */
bool fathom_coverage_has_new(fathom_coverage_t *cov)
{
    for (size_t i = 0; i < cov->size; i++) {
        if (cov->local[i] &&
            (fathom_classify_count(cov->local[i]) & ~cov->global[i]))
            return true;
    }
    return false;
}

/* OR the classified local map into the global map and count new blocks. */
void fathom_coverage_merge(fathom_coverage_t *cov)
{
    size_t fresh = 0;

    for (size_t i = 0; i < cov->size; i++) {
        if (cov->local[i] == 0)
            continue;
        if (cov->global[i] == 0) {
            fresh++;
            cov->total_blocks++;
        }
        cov->global[i] |= fathom_classify_count(cov->local[i]);
    }
    cov->new_blocks = fresh;
}
