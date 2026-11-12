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

int fathom_coverage_init(fathom_coverage_t *cov)
{
    memset(cov, 0, sizeof(*cov));
    cov->local  = calloc(1, FATHOM_MAP_SIZE);
    cov->global = calloc(1, FATHOM_MAP_SIZE);
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
}

void fathom_coverage_reset_local(fathom_coverage_t *cov)
{
    memset(cov->local, 0, FATHOM_MAP_SIZE);
}

/*
 * A run is new when any classified local value has a bit the global
 * map has not yet recorded.
 */
bool fathom_coverage_has_new(fathom_coverage_t *cov)
{
    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++) {
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

    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++) {
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
