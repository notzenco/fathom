/*
 * coverage.h — Internal declarations for the coverage tracker
 */

#ifndef FATHOM_COVERAGE_INTERNAL_H
#define FATHOM_COVERAGE_INTERNAL_H

#include <sys/types.h>
#include "fathom.h"

/*
 * Environment variable name used to pass the shared memory ID
 * to child processes so they can attach to the coverage bitmap.
 */
#define FATHOM_SHM_ENV  "__FATHOM_SHM_ID"

/*
 * Classify hit counts into buckets (AFL-style).
 * This coarsens exact counts into power-of-two ranges so that
 * small count variations don't flood the fuzzer with false novelty.
 *
 *   0          -> 0
 *   1          -> 1
 *   2          -> 2
 *   3          -> 4
 *   4..7       -> 8
 *   8..15      -> 16
 *   16..31     -> 32
 *   32..127    -> 64
 *   128..255   -> 128
 */
static inline uint8_t fathom_classify_count(uint8_t n)
{
    if (n == 0)   return 0;
    if (n == 1)   return 1;
    if (n == 2)   return 2;
    if (n == 3)   return 4;
    if (n <= 7)   return 8;
    if (n <= 15)  return 16;
    if (n <= 31)  return 32;
    if (n <= 127) return 64;
    return 128;
}

#endif /* FATHOM_COVERAGE_INTERNAL_H */
