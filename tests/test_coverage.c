/*
 * test_coverage.c — Unit tests for the coverage tracking module
 */

#include "fathom.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define PASS(name) fprintf(stderr, "  PASS  %s\n", (name))

static void test_init_zeroed(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    /* Both maps should be entirely zero after init. */
    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++) {
        assert(cov.local[i] == 0);
        assert(cov.global[i] == 0);
    }
    assert(cov.total_blocks == 0);
    assert(cov.new_blocks == 0);

    fathom_coverage_destroy(&cov);
    PASS("init_zeroed");
}

static void test_has_new_detects_new(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    /* Simulate a block hit at slot 42. */
    cov.local[42] = 1;

    assert(fathom_coverage_has_new(&cov) == true);

    fathom_coverage_destroy(&cov);
    PASS("has_new_detects_new");
}

static void test_merge_updates_global(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    cov.local[100] = 1;
    cov.local[200] = 3;

    fathom_coverage_merge(&cov);

    /* Global should now have classified values at those indices. */
    assert(cov.global[100] != 0);
    assert(cov.global[200] != 0);
    assert(cov.new_blocks == 2);
    assert(cov.total_blocks == 2);

    fathom_coverage_destroy(&cov);
    PASS("merge_updates_global");
}

static void test_reset_local(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    cov.local[100] = 1;
    cov.local[200] = 3;

    fathom_coverage_reset_local(&cov);

    for (size_t i = 0; i < FATHOM_MAP_SIZE; i++)
        assert(cov.local[i] == 0);

    fathom_coverage_destroy(&cov);
    PASS("reset_local");
}

static void test_same_pattern_not_new(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    /* First execution: hit blocks at slots 10 and 20. */
    cov.local[10] = 1;
    cov.local[20] = 5;

    assert(fathom_coverage_has_new(&cov) == true);
    fathom_coverage_merge(&cov);
    assert(cov.new_blocks == 2);
    assert(cov.total_blocks == 2);

    /* Second execution: exact same pattern. */
    fathom_coverage_reset_local(&cov);
    cov.local[10] = 1;
    cov.local[20] = 5;

    /* Same classified buckets -> nothing new. */
    assert(fathom_coverage_has_new(&cov) == false);

    fathom_coverage_merge(&cov);
    assert(cov.new_blocks == 0);
    /* total_blocks should remain unchanged. */
    assert(cov.total_blocks == 2);

    fathom_coverage_destroy(&cov);
    PASS("same_pattern_not_new");
}

static void test_new_pattern_is_new(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    /* First execution. */
    cov.local[10] = 1;
    fathom_coverage_merge(&cov);
    assert(cov.total_blocks == 1);

    /* Second execution: different block. */
    fathom_coverage_reset_local(&cov);
    cov.local[999] = 2;

    assert(fathom_coverage_has_new(&cov) == true);

    fathom_coverage_merge(&cov);
    assert(cov.new_blocks == 1);
    assert(cov.total_blocks == 2);

    fathom_coverage_destroy(&cov);
    PASS("new_pattern_is_new");
}

static void test_destroy_is_clean(void)
{
    fathom_coverage_t cov;
    assert(fathom_coverage_init(&cov) == 0);

    fathom_coverage_destroy(&cov);

    assert(cov.local == NULL);
    assert(cov.global == NULL);

    PASS("destroy_is_clean");
}

int main(void)
{
    fprintf(stderr, "=== test_coverage ===\n");

    test_init_zeroed();
    test_has_new_detects_new();
    test_merge_updates_global();
    test_reset_local();
    test_same_pattern_not_new();
    test_new_pattern_is_new();
    test_destroy_is_clean();

    fprintf(stderr, "All coverage tests passed.\n");
    return 0;
}
