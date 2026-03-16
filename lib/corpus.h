/*
 * corpus.h — Internal declarations for the corpus manager
 */

#ifndef FATHOM_CORPUS_INTERNAL_H
#define FATHOM_CORPUS_INTERNAL_H

#include "fathom.h"

/*
 * Initial capacity for the inputs array.
 */
#define FATHOM_CORPUS_INIT_CAP  64

/*
 * Growth factor when the inputs array needs to expand.
 */
#define FATHOM_CORPUS_GROW      2

/*
 * Maximum number of unique crash hashes tracked for dedup.
 * Must be a power of two for the open-addressing hash set.
 */
#define FATHOM_CRASH_HASHSET_CAP  4096

/*
 * Simple open-addressing hash set for crash dedup.
 * Stores 64-bit crash hashes; 0 is treated as empty.
 */
typedef struct {
    uint64_t *slots;
    size_t    capacity;
    size_t    count;
} fathom_hashset_t;

/*
 * Initialise the hash set.  Returns 0 on success, -1 on allocation failure.
 */
int  fathom_hashset_init(fathom_hashset_t *hs, size_t capacity);

/*
 * Free the hash set.
 */
void fathom_hashset_destroy(fathom_hashset_t *hs);

/*
 * Insert a hash.  Returns 1 if newly inserted, 0 if already present,
 * -1 on error (full).  Hash value 0 is reserved as the empty sentinel;
 * if the caller provides 0 it is silently mapped to 1.
 */
int  fathom_hashset_insert(fathom_hashset_t *hs, uint64_t hash);

/*
 * Check whether a hash is present.
 */
bool fathom_hashset_contains(const fathom_hashset_t *hs, uint64_t hash);

#endif /* FATHOM_CORPUS_INTERNAL_H */
