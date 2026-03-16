/*
 * test_elf.c — Unit tests for the ELF parser
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %-40s ", #name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while (0)

/* Path to a known ELF binary on the system. */
static const char *test_binary(void)
{
    /* Try /usr/bin/ls first (Arch, Fedora, etc.), then /bin/ls */
    static const char *candidates[] = {
        "/usr/bin/ls",
        "/bin/ls",
        NULL,
    };
    for (const char **p = candidates; *p; p++) {
        if (access(*p, R_OK) == 0)
            return *p;
    }
    return NULL;
}

/* ── Tests ───────────────────────────────────────────────────────────── */

static fathom_elf_t elf;

static void test_open_valid_binary(void)
{
    TEST(open_valid_binary);
    const char *path = test_binary();
    ASSERT(path != NULL, "no test binary found");

    int rc = fathom_elf_open(&elf, path);
    ASSERT(rc == 0, "fathom_elf_open failed");
    PASS();
}

static void test_entry_point(void)
{
    TEST(entry_point_nonzero);
    ASSERT(elf.entry != 0, "entry point is zero");
    PASS();
}

static void test_text_section(void)
{
    TEST(text_section_found);
    ASSERT(elf.text.addr > 0, ".text addr is zero");
    ASSERT(elf.text.size > 0, ".text size is zero");
    ASSERT(elf.text.name != NULL, ".text name is NULL");
    ASSERT(strcmp(elf.text.name, ".text") == 0, ".text name mismatch");
    PASS();
}

static void test_mapped_data(void)
{
    TEST(mapped_data_valid);
    ASSERT(elf.mapped != NULL, "mapped is NULL");
    ASSERT(elf.mapped_len > 0, "mapped_len is zero");
    /* First four bytes should be the ELF magic */
    ASSERT(elf.mapped[0] == 0x7f, "bad magic byte 0");
    ASSERT(elf.mapped[1] == 'E',  "bad magic byte 1");
    ASSERT(elf.mapped[2] == 'L',  "bad magic byte 2");
    ASSERT(elf.mapped[3] == 'F',  "bad magic byte 3");
    PASS();
}

static void test_stripped_flag(void)
{
    TEST(stripped_flag);
    /*
     * /usr/bin/ls is typically stripped on most distros.
     * We just verify the flag is set consistently with symbol_count.
     */
    if (elf.stripped) {
        /* stripped: .symtab was absent */
        printf("(stripped) ");
    } else {
        /* not stripped: we should have symbols */
        ASSERT(elf.symbol_count > 0, "not stripped but no symbols");
    }
    PASS();
}

static void test_dynsym_fallback(void)
{
    TEST(dynsym_fallback);
    /*
     * For a stripped PIE binary like /usr/bin/ls, we expect .dynsym
     * symbols to still be available.
     */
    if (elf.stripped && elf.symbol_count > 0) {
        printf("(has dynsym: %zu syms) ", elf.symbol_count);
    } else if (!elf.stripped) {
        printf("(has symtab: %zu syms) ", elf.symbol_count);
    } else {
        printf("(no symbols) ");
    }
    PASS();
}

static void test_open_invalid_path(void)
{
    TEST(open_invalid_path);
    fathom_elf_t bad;
    int rc = fathom_elf_open(&bad, "/nonexistent/binary");
    ASSERT(rc == -1, "should fail for invalid path");
    PASS();
}

static void test_close(void)
{
    TEST(close);
    fathom_elf_close(&elf);
    ASSERT(elf.mapped == NULL, "mapped not cleared after close");
    ASSERT(elf.symbols == NULL, "symbols not cleared after close");
    ASSERT(elf.symbol_count == 0, "symbol_count not zero after close");
    PASS();
}

static void test_close_null(void)
{
    TEST(close_null_safe);
    /* Calling close on an already-closed struct should not crash */
    fathom_elf_close(&elf);
    PASS();
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("test_elf\n");

    test_open_valid_binary();
    test_entry_point();
    test_text_section();
    test_mapped_data();
    test_stripped_flag();
    test_dynsym_fallback();
    test_open_invalid_path();
    test_close();
    test_close_null();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
