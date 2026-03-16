/*
 * analyze.h — Internal declarations for static analysis pass
 */

#ifndef FATHOM_ANALYZE_INTERNAL_H
#define FATHOM_ANALYZE_INTERNAL_H

#include "fathom.h"

/* ── Scoring weights ────────────────────────────────────────────────── */

#define SCORE_DANGEROUS_CALL   10.0
#define SCORE_LOOP_HEADER       5.0
#define SCORE_ERROR_PATH        3.0
#define SCORE_HIGH_FANOUT       2.0   /* per successor beyond 2 */

/* ── Dangerous / error function lists ───────────────────────────────── */

/*
 * Minimum printable-string length for .rodata dictionary extraction.
 */
#define RODATA_MIN_STR_LEN     4

/*
 * Maximum number of top-scored blocks shown by fathom_analysis_print.
 */
#define ANALYSIS_TOP_N         20

#endif /* FATHOM_ANALYZE_INTERNAL_H */
