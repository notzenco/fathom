/*
 * coverage.c — AFL-style shared memory coverage bitmap
 *
 * The local bitmap lives in a SysV shared memory segment so that a
 * child process (the target under test) can attach and write edge hits
 * directly.  After each execution the fuzzer compares the local bitmap
 * against a cumulative global bitmap to detect new coverage.
 */

#include "coverage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/* ── Init / Destroy ──────────────────────────────────────────────────── */

int fathom_coverage_init(fathom_coverage_t *cov)
{
    /* Create a SysV shared memory segment for the local (per-exec) bitmap. */
    cov->shm_id = shmget(IPC_PRIVATE, FATHOM_MAP_SIZE,
                          IPC_CREAT | IPC_EXCL | 0600);
    if (cov->shm_id < 0) {
        perror("fathom: shmget");
        return -1;
    }

    cov->local = shmat(cov->shm_id, NULL, 0);
    if (cov->local == (void *)-1) {
        perror("fathom: shmat");
        shmctl(cov->shm_id, IPC_RMID, NULL);
        return -1;
    }

    memset(cov->local, 0, FATHOM_MAP_SIZE);

    /* Allocate the global (cumulative) bitmap on the heap. */
    cov->global = calloc(1, FATHOM_MAP_SIZE);
    if (!cov->global) {
        shmdt(cov->local);
        shmctl(cov->shm_id, IPC_RMID, NULL);
        return -1;
    }

    cov->total_edges = 0;
    cov->new_edges   = 0;
    cov->prev_loc    = 0;

    /* Export the shm id so child processes can attach. */
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", cov->shm_id);
    setenv(FATHOM_SHM_ENV, id_str, 1);

    return 0;
}

void fathom_coverage_destroy(fathom_coverage_t *cov)
{
    if (cov->local && cov->local != (void *)-1) {
        shmdt(cov->local);
    }

    if (cov->shm_id >= 0) {
        shmctl(cov->shm_id, IPC_RMID, NULL);
    }

    free(cov->global);

    cov->local  = NULL;
    cov->global = NULL;
    cov->shm_id = -1;

    unsetenv(FATHOM_SHM_ENV);
}

/* ── Per-exec helpers ────────────────────────────────────────────────── */

void fathom_coverage_reset_local(fathom_coverage_t *cov)
{
    memset(cov->local, 0, FATHOM_MAP_SIZE);
    cov->prev_loc = 0;
}

/*
 * Check whether the local bitmap contains any edge that the global
 * bitmap has not yet recorded.  We classify hit counts into AFL-style
 * buckets so that genuinely new hit-count patterns are detected while
 * small count jitter is ignored.
 *
 * The global bitmap stores the OR of classified hit-count values from
 * all prior executions.  A new pattern is detected when the classified
 * local value has any bit not yet set in the global entry.
 */
bool fathom_coverage_has_new(fathom_coverage_t *cov)
{
    const uint8_t *local  = cov->local;
    const uint8_t *global = cov->global;

    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++) {
        if (local[i] == 0)
            continue;

        uint8_t lclass = fathom_classify_count(local[i]);

        if (lclass & ~global[i])
            return true;
    }

    return false;
}

/*
 * OR the (classified) local bitmap into the global bitmap.
 * Count how many bytes transition from 0 -> non-zero in the global
 * bitmap and record that as new_edges for this cycle.
 */
void fathom_coverage_merge(fathom_coverage_t *cov)
{
    uint8_t *local  = cov->local;
    uint8_t *global = cov->global;
    size_t   new_this_cycle = 0;

    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++) {
        if (local[i] == 0)
            continue;

        uint8_t lclass = fathom_classify_count(local[i]);

        if (global[i] == 0) {
            /* Brand-new edge — count it. */
            new_this_cycle++;
            cov->total_edges++;
        }

        /* OR in the classified local value so that new hit-count
         * buckets are accumulated in the global bitmap. */
        global[i] |= lclass;
    }

    cov->new_edges = new_this_cycle;
}
