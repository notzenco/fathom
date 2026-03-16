/*
 * mutate.h — Internal declarations for the mutation engine
 */

#ifndef FATHOM_MUTATE_INTERNAL_H
#define FATHOM_MUTATE_INTERNAL_H

#include "fathom.h"

/*
 * Weight decay factor applied during adaptive weight normalization.
 * Recent hits are blended with prior weights at this ratio.
 */
#define FATHOM_WEIGHT_DECAY   0.95

/*
 * Bonus multiplier when a strategy discovers new coverage.
 */
#define FATHOM_WEIGHT_BONUS   2.0

/*
 * Minimum weight floor to prevent any strategy from being starved.
 */
#define FATHOM_WEIGHT_MIN     0.01

/*
 * Havoc: min and max number of stacked atomic mutations.
 */
#define FATHOM_HAVOC_MIN      2
#define FATHOM_HAVOC_MAX      16

/*
 * Arithmetic mutation range: +/- this value.
 */
#define FATHOM_ARITH_MAX      35

/*
 * Maximum dictionary entry length.
 */
#define FATHOM_DICT_MAX_ENTRY 128

#endif /* FATHOM_MUTATE_INTERNAL_H */
