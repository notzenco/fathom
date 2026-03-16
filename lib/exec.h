/*
 * exec.h — Internal declarations for the target executor
 */

#ifndef FATHOM_EXEC_INTERNAL_H
#define FATHOM_EXEC_INTERNAL_H

#include "fathom.h"

/*
 * Default timeout in milliseconds if none is specified in config.
 */
#define FATHOM_DEFAULT_TIMEOUT_MS  1000

/*
 * Initial capacity for the breakpoint table.
 */
#define FATHOM_BP_INIT_CAP  64

/*
 * Maximum number of stack frames to unwind for crash hashing.
 */
#define FATHOM_STACK_HASH_DEPTH  8

/*
 * FNV-1a 64-bit parameters used for crash stack hashing.
 */
#define FATHOM_FNV_OFFSET  0xcbf29ce484222325ULL
#define FATHOM_FNV_PRIME   0x100000001b3ULL

/*
 * Name of the temporary file written for each execution.
 * Placed in /tmp so it resides on tmpfs where available.
 */
#define FATHOM_INPUT_FILE  "/tmp/.fathom-input"

/*
 * Hash a single 64-bit value into an ongoing FNV-1a state.
 */
static inline uint64_t fathom_fnv_mix(uint64_t hash, uint64_t val)
{
    const uint8_t *p = (const uint8_t *)&val;
    for (size_t i = 0; i < sizeof(val); i++) {
        hash ^= p[i];
        hash *= FATHOM_FNV_PRIME;
    }
    return hash;
}

#endif /* FATHOM_EXEC_INTERNAL_H */
