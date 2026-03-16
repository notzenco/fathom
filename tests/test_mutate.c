/*
 * test_mutate.c — Tests for the mutation engine
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ─────────────────────────────────────────────────────────── */

static int tests_run    = 0;
static int tests_passed = 0;

#define CHECK(cond, msg)                                        \
    do {                                                        \
        tests_run++;                                            \
        if (cond) {                                             \
            tests_passed++;                                     \
        } else {                                                \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
        }                                                       \
    } while (0)

/* Make a fresh copy of data to mutate. */
static void fill_buf(uint8_t *buf, size_t len, uint8_t pattern)
{
    memset(buf, pattern, len);
}

/* Check whether buf differs from a uniform fill of the given pattern. */
static int buf_changed(const uint8_t *buf, size_t len, uint8_t pattern)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != pattern)
            return 1;
    }
    return 0;
}

/* ── Test: mutator init ──────────────────────────────────────────────── */

static void test_mutator_init(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    int all_equal = 1;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
        if (mut.weights[i] != 1.0)
            all_equal = 0;
        if (mut.hits[i] != 0 || mut.uses[i] != 0)
            all_equal = 0;
    }
    CHECK(all_equal, "mutator_init sets equal weights and zero counters");
}

/* ── Test: each strategy doesn't crash and modifies buffer ───────────── */

static void test_bitflip(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    uint8_t buf[64];
    fill_buf(buf, sizeof(buf), 0xAA);
    size_t len = sizeof(buf);

    /* Force bitflip by calling many times; at least one should change. */
    int changed = 0;
    for (int i = 0; i < 100; i++) {
        fill_buf(buf, sizeof(buf), 0xAA);
        len = sizeof(buf);
        fathom_mutate(&mut, buf, &len, sizeof(buf), NULL, 0);
        if (buf_changed(buf, sizeof(buf), 0xAA))
            changed = 1;
    }
    CHECK(changed, "mutation changes buffer (over 100 attempts)");
}

static void test_each_strategy_no_crash(void)
{
    fathom_dict_t dict;
    fathom_dict_init(&dict);
    fathom_dict_add(&dict, (const uint8_t *)"FUZZ", 4);
    fathom_dict_add(&dict, (const uint8_t *)"\x00\xFF", 2);

    fathom_mutator_t mut;
    fathom_mutator_init(&mut, &dict);

    uint8_t splice_data[] = "SPLICE_DONOR_DATA_HERE";
    size_t splice_len = sizeof(splice_data) - 1;

    /* Run many mutations to exercise all strategies. */
    int strat_seen[FATHOM_MUT_COUNT] = {0};
    for (int i = 0; i < 5000; i++) {
        uint8_t buf[256];
        fill_buf(buf, 64, 0x55);
        size_t len = 64;
        int which = fathom_mutate(&mut, buf, &len, sizeof(buf),
                                  splice_data, splice_len);
        if (which >= 0 && which < FATHOM_MUT_COUNT)
            strat_seen[which] = 1;
    }

    /* Verify we exercised all strategies. */
    int all_seen = 1;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
        if (!strat_seen[i]) {
            fprintf(stderr, "  strategy %d never selected\n", i);
            all_seen = 0;
        }
    }
    CHECK(all_seen, "all 7 strategies exercised over 5000 iterations");

    fathom_dict_destroy(&dict);
}

/* ── Test: dictionary add ────────────────────────────────────────────── */

static void test_dict_add(void)
{
    fathom_dict_t dict;
    fathom_dict_init(&dict);

    int rc = fathom_dict_add(&dict, (const uint8_t *)"test", 4);
    CHECK(rc == 0, "dict_add returns 0 on success");
    CHECK(dict.count == 1, "dict has 1 entry after add");
    CHECK(dict.entries[0].len == 4, "entry length is 4");
    CHECK(memcmp(dict.entries[0].data, "test", 4) == 0,
          "entry data matches");

    /* Adding NULL or zero-length should fail. */
    rc = fathom_dict_add(&dict, NULL, 0);
    CHECK(rc == -1, "dict_add rejects NULL data");
    rc = fathom_dict_add(&dict, (const uint8_t *)"x", 0);
    CHECK(rc == -1, "dict_add rejects zero-length");

    CHECK(dict.count == 1, "dict count unchanged after failed adds");

    fathom_dict_destroy(&dict);
    CHECK(dict.count == 0, "dict_destroy zeroes count");
}

/* ── Test: dictionary load ───────────────────────────────────────────── */

static void test_dict_load(void)
{
    fathom_dict_t dict;
    fathom_dict_init(&dict);

    int rc = fathom_dict_load(&dict, "tests/test_dict.txt");
    CHECK(rc > 0, "dict_load returns positive count on success");
    CHECK(dict.count == (size_t)rc, "dict.count matches loaded count");

    /* We expect: "hello", "world\n", "test_token", ABC (hex), "raw_line" */
    CHECK(dict.count == 5, "dict loaded 5 entries from test file");

    /* Verify "hello" */
    int found_hello = 0;
    for (size_t i = 0; i < dict.count; i++) {
        if (dict.entries[i].len == 5 &&
            memcmp(dict.entries[i].data, "hello", 5) == 0)
            found_hello = 1;
    }
    CHECK(found_hello, "dict contains 'hello' entry");

    /* Verify hex-encoded ABC */
    int found_abc = 0;
    for (size_t i = 0; i < dict.count; i++) {
        if (dict.entries[i].len == 3 &&
            memcmp(dict.entries[i].data, "ABC", 3) == 0)
            found_abc = 1;
    }
    CHECK(found_abc, "dict contains hex-decoded ABC entry");

    /* Load nonexistent file should fail. */
    fathom_dict_t d2;
    fathom_dict_init(&d2);
    rc = fathom_dict_load(&d2, "/nonexistent/dict.txt");
    CHECK(rc == -1, "dict_load returns -1 for missing file");

    fathom_dict_destroy(&dict);
    fathom_dict_destroy(&d2);
}

/* ── Test: mutator_reward changes weights ────────────────────────────── */

static void test_reward(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    double before = mut.weights[FATHOM_MUT_ARITH];
    fathom_mutator_reward(&mut, FATHOM_MUT_ARITH);

    CHECK(mut.hits[FATHOM_MUT_ARITH] == 1, "reward increments hit count");
    CHECK(mut.weights[FATHOM_MUT_ARITH] > before,
          "reward boosts weight of rewarded strategy");

    /* Other strategies should have decayed. */
    CHECK(mut.weights[FATHOM_MUT_BITFLIP] < 1.0,
          "unrewarded strategy weight decayed");

    /* Multiple rewards should make the strategy dominant. */
    for (int i = 0; i < 50; i++)
        fathom_mutator_reward(&mut, FATHOM_MUT_ARITH);

    double arith_w = mut.weights[FATHOM_MUT_ARITH];
    double other_w = mut.weights[FATHOM_MUT_BITFLIP];
    CHECK(arith_w > other_w * 10,
          "heavily rewarded strategy dominates others");
}

/* ── Test: splice with donor ─────────────────────────────────────────── */

static void test_splice(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    /* Give splice a very high weight to force selection. */
    for (int i = 0; i < FATHOM_MUT_COUNT; i++)
        mut.weights[i] = 0.001;
    mut.weights[FATHOM_MUT_SPLICE] = 100.0;

    uint8_t buf[128];
    memset(buf, 'A', 64);
    size_t len = 64;

    uint8_t donor[64];
    memset(donor, 'B', sizeof(donor));

    int which = fathom_mutate(&mut, buf, &len, sizeof(buf),
                              donor, sizeof(donor));
    CHECK(which == FATHOM_MUT_SPLICE, "forced splice strategy selected");

    /* After splice, buffer should contain some 'B' bytes from the donor. */
    int has_b = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 'B')
            has_b = 1;
    }
    CHECK(has_b, "splice inserts donor data into buffer");

    /* Buffer should still start with some 'A' bytes. */
    CHECK(buf[0] == 'A', "splice preserves prefix from original buffer");
}

/* ── Test: splice skipped when donor is NULL ─────────────────────────── */

static void test_splice_null(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    /* Many mutations without splice donor should never pick splice. */
    int splice_count = 0;
    for (int i = 0; i < 1000; i++) {
        uint8_t buf[32];
        fill_buf(buf, sizeof(buf), 0x42);
        size_t len = sizeof(buf);
        int which = fathom_mutate(&mut, buf, &len, sizeof(buf), NULL, 0);
        if (which == FATHOM_MUT_SPLICE)
            splice_count++;
    }
    CHECK(splice_count == 0,
          "splice never selected when donor is NULL");
}

/* ── Test: empty input (len=0) doesn't crash ─────────────────────────── */

static void test_empty_input(void)
{
    fathom_dict_t dict;
    fathom_dict_init(&dict);
    fathom_dict_add(&dict, (const uint8_t *)"X", 1);

    fathom_mutator_t mut;
    fathom_mutator_init(&mut, &dict);

    uint8_t buf[64] = {0};
    size_t len = 0;

    /* Run multiple times to exercise different strategies. */
    for (int i = 0; i < 500; i++) {
        len = 0;
        int which = fathom_mutate(&mut, buf, &len, sizeof(buf), NULL, 0);
        (void)which;
    }
    CHECK(1, "empty input (len=0) does not crash");

    /* Also test with splice donor. */
    uint8_t donor[] = "donor";
    for (int i = 0; i < 500; i++) {
        len = 0;
        fathom_mutate(&mut, buf, &len, sizeof(buf), donor, sizeof(donor) - 1);
    }
    CHECK(1, "empty input with splice donor does not crash");

    fathom_dict_destroy(&dict);
}

/* ── Test: mutation respects max_len ─────────────────────────────────── */

static void test_max_len(void)
{
    fathom_dict_t dict;
    fathom_dict_init(&dict);
    fathom_dict_add(&dict, (const uint8_t *)"LONGTOKEN1234567", 16);

    fathom_mutator_t mut;
    fathom_mutator_init(&mut, &dict);

    uint8_t buf[32];
    int exceeded = 0;
    for (int i = 0; i < 2000; i++) {
        fill_buf(buf, 16, 0x33);
        size_t len = 16;
        size_t max_len = 24;
        fathom_mutate(&mut, buf, &len, max_len, NULL, 0);
        if (len > max_len)
            exceeded = 1;
    }
    CHECK(!exceeded, "mutation never exceeds max_len");

    fathom_dict_destroy(&dict);
}

/* ── Test: uses counter is incremented ───────────────────────────────── */

static void test_uses_counter(void)
{
    fathom_mutator_t mut;
    fathom_mutator_init(&mut, NULL);

    uint8_t buf[32];
    fill_buf(buf, sizeof(buf), 0x11);
    size_t len = sizeof(buf);

    uint64_t total_before = 0;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++)
        total_before += mut.uses[i];

    fathom_mutate(&mut, buf, &len, sizeof(buf), NULL, 0);

    uint64_t total_after = 0;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++)
        total_after += mut.uses[i];

    CHECK(total_after == total_before + 1,
          "uses counter incremented by exactly 1");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== test_mutate ===\n");

    test_mutator_init();
    test_bitflip();
    test_each_strategy_no_crash();
    test_dict_add();
    test_dict_load();
    test_reward();
    test_splice();
    test_splice_null();
    test_empty_input();
    test_max_len();
    test_uses_counter();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
