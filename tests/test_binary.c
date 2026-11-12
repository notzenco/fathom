/*
 * test_binary.c — Loader, disassembler and analysis tests on every format
 *
 * Runs against the prebuilt fixtures (tests/fixtures/fixture.c compiled
 * for ELF, Mach-O and PE on x86-64 and arm64), so every host checks
 * every format.
 */

#include "fathom.h"
#include "test_util.h"

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_failed;

#define CHECK(cond, ...) \
    do { \
        tests_run++; \
        if (!(cond)) { \
            tests_failed++; \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__); \
            printf("\n"); \
        } \
    } while (0)

typedef struct {
    const char     *path;
    fathom_format_t format;
    fathom_arch_t   arch;
    bool            stripped;
    const char     *copy_name;   /* fortified on macOS; zig's MinGW defines memcpy itself */
} fixture_t;

static const fixture_t fixtures[] = {
    { FIXTURE("elf-x86_64"),              FATHOM_FMT_ELF,   FATHOM_ARCH_X86_64, false, "memcpy" },
    { FIXTURE("elf-arm64"),               FATHOM_FMT_ELF,   FATHOM_ARCH_ARM64,  false, "memcpy" },
    { FIXTURE("elf-x86_64-gcc-stripped"), FATHOM_FMT_ELF,   FATHOM_ARCH_X86_64, true,  "memcpy" },
    { FIXTURE("macho-x86_64"),            FATHOM_FMT_MACHO, FATHOM_ARCH_X86_64, false, "__memcpy_chk" },
    { FIXTURE("macho-arm64"),             FATHOM_FMT_MACHO, FATHOM_ARCH_ARM64,  false, "__memcpy_chk" },
    { FIXTURE("pe-x86_64.exe"),           FATHOM_FMT_PE,    FATHOM_ARCH_X86_64, true,  "strcpy" },
    { FIXTURE("pe-arm64.exe"),            FATHOM_FMT_PE,    FATHOM_ARCH_ARM64,  true,  "strcpy" },
};

static bool in_code(const fathom_binary_t *b, uint64_t addr)
{
    for (size_t i = 0; i < b->section_count; i++) {
        const fathom_section_t *s = &b->sections[i];
        if ((s->flags & FATHOM_SEC_CODE) && addr >= s->addr && addr < s->addr + s->size)
            return true;
    }
    return false;
}

static bool has_import(const fathom_binary_t *b, const char *name)
{
    for (size_t i = 0; i < b->import_count; i++) {
        if (strcmp(b->imports[i].name, name) == 0)
            return true;
    }
    return false;
}

static bool dict_has(const fathom_dict_t *d, const void *bytes, size_t len)
{
    for (size_t i = 0; i < d->count; i++) {
        if (d->entries[i].len >= len && memcmp(d->entries[i].data, bytes, len) == 0)
            return true;
    }
    return false;
}

static void test_fixture(const fixture_t *fx)
{
    printf("  %s\n", fx->path);

    fathom_binary_t bin;
    fathom_disasm_t dis;
    fathom_cfg_t cfg;
    fathom_analysis_t ana;

    if (fathom_binary_open(&bin, fx->path) != 0) {
        CHECK(false, "%s: open failed", fx->path);
        return;
    }
    CHECK(bin.format == fx->format, "format %d", bin.format);
    CHECK(bin.arch == fx->arch, "arch %d", bin.arch);
    CHECK(bin.stripped == fx->stripped, "stripped %d", bin.stripped);
    CHECK(in_code(&bin, bin.entry), "entry 0x%llx not in code", (unsigned long long)bin.entry);
    CHECK(bin.image_size > 0, "image size");
    CHECK(has_import(&bin, "malloc"), "malloc import");
    CHECK(has_import(&bin, fx->copy_name), "%s import", fx->copy_name);
    if (!fx->stripped) {
        bool main_found = false;
        for (size_t i = 0; i < bin.symbol_count; i++)
            main_found |= strcmp(bin.symbols[i].name, "main") == 0 &&
                          bin.symbols[i].type == FATHOM_SYM_FUNC;
        CHECK(main_found, "main symbol");
    }

    if (fathom_disasm_open(&dis, &bin) != 0) {
        CHECK(false, "disasm failed");
        fathom_binary_close(&bin);
        return;
    }
    CHECK(dis.arch == fx->arch, "disasm arch");
    bool sorted = true;
    for (size_t i = 1; i < dis.count; i++)
        sorted &= dis.insns[i - 1].addr < dis.insns[i].addr;
    CHECK(sorted, "instructions sorted by address");

    /* Every import stub style must resolve: PLT, Mach-O stub, MinGW thunk. */
    bool saw_malloc = false, saw_copy = false;
    for (size_t i = 0; i < dis.count; i++) {
        if (dis.insns[i].kind != FATHOM_INSN_CALL)
            continue;
        const char *name = fathom_resolve_call(&bin, &dis, &dis.insns[i]);
        saw_malloc |= name && strcmp(name, "malloc") == 0;
        saw_copy |= name && strcmp(name, fx->copy_name) == 0;
    }
    CHECK(saw_malloc, "a call resolves to malloc");
    CHECK(saw_copy, "a call resolves to %s", fx->copy_name);

    CHECK(fathom_cfg_build(&cfg, &dis) == 0, "cfg");
    CHECK(fathom_analyze(&ana, &cfg, &bin, &dis) == 0, "analyze");

    CHECK(dict_has(&ana.dict, "FIXTURE-MAGIC", 13), "rodata string in dictionary");
    const uint8_t cmp_const = 0x37;
    CHECK(dict_has(&ana.dict, &cmp_const, 1), "comparison constant 0x37 in dictionary");

    /*
     * The block calling malloc lives in main.  In stripped binaries main
     * is only referenced by address (from _start / the CRT), so finding it
     * instrumentable shows reachability follows address references.
     */
    bool malloc_block_instrumented = false;
    for (size_t i = 0; i < ana.cov_count; i++) {
        const fathom_block_t *b = &cfg.blocks[ana.cov_blocks[i]];
        for (size_t k = 0; k < b->insn_count; k++) {
            const fathom_insn_t *insn = &dis.insns[b->insn_start + k];
            const char *name = insn->kind == FATHOM_INSN_CALL
                             ? fathom_resolve_call(&bin, &dis, insn) : NULL;
            malloc_block_instrumented |= name && strcmp(name, "malloc") == 0;
        }
    }
    CHECK(malloc_block_instrumented, "main's malloc call block is instrumentable");

    bool sorted_cov = true;
    for (size_t i = 1; i < ana.cov_count; i++)
        sorted_cov &= ana.cov_blocks[i - 1] < ana.cov_blocks[i];
    CHECK(sorted_cov, "instrumentable blocks sorted");

    fathom_analysis_free(&ana);
    fathom_cfg_free(&cfg);
    fathom_disasm_close(&dis);
    fathom_binary_close(&bin);
}

static void test_universal_picks_host_slice(void)
{
    printf("  %s\n", FIXTURE("macho-universal"));
    fathom_binary_t bin;
    CHECK(fathom_binary_open(&bin, FIXTURE("macho-universal")) == 0, "open universal");
    fathom_arch_t want = fathom_host_arch() == FATHOM_ARCH_X86_64
                       ? FATHOM_ARCH_X86_64 : FATHOM_ARCH_ARM64;
    CHECK(bin.arch == want, "universal slice arch %d, want %d", bin.arch, want);
    CHECK(has_import(&bin, "malloc"), "slice imports");
    fathom_binary_close(&bin);
}

static void test_rejects_bad_input(void)
{
    printf("  malformed inputs\n");
    fathom_binary_t bin;
    CHECK(fathom_binary_open(&bin, "tests/fixtures/does-not-exist") != 0, "missing file");
    CHECK(fathom_binary_open(&bin, FIXTURE("fixture.c")) != 0, "source file");

    /* A real header with the rest of the file cut off. */
    char dir[1024], path[1100];
    CHECK(tu_make_tmpdir(dir, sizeof(dir), "binary") == 0, "tmpdir");
    const char *names[] = { "elf-x86_64", "macho-arm64", "pe-x86_64.exe" };
    for (size_t i = 0; i < 3; i++) {
        char src[256];
        uint8_t head[96];
        snprintf(src, sizeof(src), "tests/fixtures/%s", names[i]);
        FILE *in = fopen(src, "rb");
        size_t n = in ? fread(head, 1, sizeof(head), in) : 0;
        if (in)
            fclose(in);
        snprintf(path, sizeof(path), "%s/truncated", dir);
        FILE *out = fopen(path, "wb");
        if (out) {
            fwrite(head, 1, n, out);
            fclose(out);
        }
        CHECK(fathom_binary_open(&bin, path) != 0, "truncated %s", names[i]);
    }
    tu_rm_tree(dir);
}

int main(void)
{
    printf("=== test_binary ===\n");
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++)
        test_fixture(&fixtures[i]);
    test_universal_picks_host_slice();
    test_rejects_bad_input();

    printf("\n%d checks, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
