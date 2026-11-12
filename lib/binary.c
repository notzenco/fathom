/*
 * binary.c — Format-neutral executable loader
 *
 * Reads the whole file, detects ELF / Mach-O / PE from its magic bytes,
 * and hands it to the matching parser.  Every parser fills the same
 * fathom_binary_t: code and read-only data sections, symbols, and
 * imports keyed by the address code uses to reach them.
 */

#include "binary_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Growable arrays ─────────────────────────────────────────────────── */

/* Grow *arr so it can hold count + 1 elements; capacity doubles at powers of two. */
static int grow(void **arr, size_t count, size_t elem)
{
    if (count != 0 && (count < 16 || (count & (count - 1)) != 0))
        return 0;
    size_t cap = count < 16 ? 16 : count * 2;
    void *p = realloc(*arr, cap * elem);
    if (!p)
        return -1;
    *arr = p;
    return 0;
}

static char *copy_name(const char *name, size_t len)
{
    const char *nul = memchr(name, '\0', len);
    if (nul)
        len = (size_t)(nul - name);
    char *s = malloc(len + 1);
    if (!s)
        return NULL;
    memcpy(s, name, len);
    s[len] = '\0';
    return s;
}

int bin_add_section(fathom_binary_t *b, uint64_t addr, uint64_t size,
                    uint64_t offset, uint32_t flags, const char *name,
                    size_t name_len)
{
    if (offset > b->image_len)
        return 0;
    if (size > b->image_len - offset)
        size = b->image_len - offset;
    if (size == 0)
        return 0;

    if (grow((void **)&b->sections, b->section_count, sizeof(*b->sections)) < 0)
        return -1;

    fathom_section_t *s = &b->sections[b->section_count++];
    memset(s, 0, sizeof(*s));
    s->addr   = addr;
    s->size   = size;
    s->offset = offset;
    s->flags  = flags;
    if (name_len >= sizeof(s->name))
        name_len = sizeof(s->name) - 1;
    memcpy(s->name, name, name_len);
    return 0;
}

int bin_add_symbol(fathom_binary_t *b, uint64_t addr, const char *name,
                   size_t name_len, uint8_t type, uint64_t size)
{
    if (grow((void **)&b->symbols, b->symbol_count, sizeof(*b->symbols)) < 0)
        return -1;
    char *copy = copy_name(name, name_len);
    if (!copy)
        return -1;
    b->symbols[b->symbol_count++] = (fathom_symbol_t){
        .addr = addr, .name = copy, .type = type, .size = size,
    };
    return 0;
}

int bin_add_import(fathom_binary_t *b, uint64_t addr, const char *name,
                   size_t name_len)
{
    if (grow((void **)&b->imports, b->import_count, sizeof(*b->imports)) < 0)
        return -1;
    char *copy = copy_name(name, name_len);
    if (!copy)
        return -1;
    b->imports[b->import_count++] = (fathom_import_t){ .addr = addr, .name = copy };
    return 0;
}

/* ── Sorting and lookup ──────────────────────────────────────────────── */

static int cmp_symbol(const void *a, const void *b)
{
    uint64_t x = ((const fathom_symbol_t *)a)->addr;
    uint64_t y = ((const fathom_symbol_t *)b)->addr;
    return (x > y) - (x < y);
}

static int cmp_import(const void *a, const void *b)
{
    uint64_t x = ((const fathom_import_t *)a)->addr;
    uint64_t y = ((const fathom_import_t *)b)->addr;
    return (x > y) - (x < y);
}

static int cmp_section(const void *a, const void *b)
{
    uint64_t x = ((const fathom_section_t *)a)->addr;
    uint64_t y = ((const fathom_section_t *)b)->addr;
    return (x > y) - (x < y);
}

const char *fathom_import_at(const fathom_binary_t *bin, uint64_t addr)
{
    size_t lo = 0, hi = bin->import_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (bin->imports[mid].addr < addr)
            lo = mid + 1;
        else if (bin->imports[mid].addr > addr)
            hi = mid;
        else
            return bin->imports[mid].name;
    }
    return NULL;
}

const fathom_section_t *fathom_binary_find_section(const fathom_binary_t *bin,
                                                   const char *name)
{
    for (size_t i = 0; i < bin->section_count; i++) {
        if (strcmp(bin->sections[i].name, name) == 0)
            return &bin->sections[i];
    }
    return NULL;
}

/* ── Names ───────────────────────────────────────────────────────────── */

const char *fathom_format_name(fathom_format_t fmt)
{
    switch (fmt) {
    case FATHOM_FMT_ELF:   return "ELF";
    case FATHOM_FMT_MACHO: return "Mach-O";
    case FATHOM_FMT_PE:    return "PE";
    default:               return "unknown";
    }
}

const char *fathom_arch_name(fathom_arch_t arch)
{
    switch (arch) {
    case FATHOM_ARCH_X86_64: return "x86-64";
    case FATHOM_ARCH_ARM64:  return "arm64";
    default:                 return "unknown";
    }
}

fathom_arch_t fathom_host_arch(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return FATHOM_ARCH_X86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return FATHOM_ARCH_ARM64;
#else
    return FATHOM_ARCH_UNKNOWN;
#endif
}

/* ── Open / close ────────────────────────────────────────────────────── */

static int read_whole_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "fathom: open(%s): %s\n", path, strerror(errno));
        return -1;
    }

    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    while (buf) {
        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (len < cap)
            break;
        uint8_t *bigger = realloc(buf, cap * 2);
        if (!bigger) {
            free(buf);
            buf = NULL;
            break;
        }
        buf = bigger;
        cap *= 2;
    }
    bool failed = ferror(fp) != 0;
    fclose(fp);

    if (!buf || failed) {
        free(buf);
        fprintf(stderr, "fathom: failed to read %s\n", path);
        return -1;
    }
    *out = buf;
    *out_len = len;
    return 0;
}

int fathom_binary_open(fathom_binary_t *bin, const char *path)
{
    memset(bin, 0, sizeof(*bin));

    if (read_whole_file(path, &bin->data, &bin->data_len) < 0)
        return -1;
    bin->image = bin->data;
    bin->image_len = bin->data_len;

    const uint8_t *d = bin->data;
    size_t n = bin->data_len;
    int rc = -1;

    if (n >= 4 && memcmp(d, "\x7f" "ELF", 4) == 0) {
        bin->format = FATHOM_FMT_ELF;
        rc = fathom_elf_parse(bin);
    } else if (n >= 4 && (memcmp(d, "\xcf\xfa\xed\xfe", 4) == 0 ||
                          memcmp(d, "\xca\xfe\xba\xbe", 4) == 0 ||
                          memcmp(d, "\xca\xfe\xba\xbf", 4) == 0)) {
        bin->format = FATHOM_FMT_MACHO;
        rc = fathom_macho_parse(bin);
    } else if (n >= 2 && d[0] == 'M' && d[1] == 'Z') {
        bin->format = FATHOM_FMT_PE;
        rc = fathom_pe_parse(bin);
    } else {
        fprintf(stderr, "fathom: %s: not an ELF, Mach-O or PE executable\n", path);
    }

    if (rc == 0 && bin->arch == FATHOM_ARCH_UNKNOWN) {
        fprintf(stderr, "fathom: %s: unsupported CPU architecture "
                        "(x86-64 and arm64 are supported)\n", path);
        rc = -1;
    }

    bool have_code = false;
    for (size_t i = 0; i < bin->section_count; i++)
        have_code |= (bin->sections[i].flags & FATHOM_SEC_CODE) != 0;
    if (rc == 0 && !have_code) {
        fprintf(stderr, "fathom: %s: no code sections found\n", path);
        rc = -1;
    }

    if (rc < 0) {
        fathom_binary_close(bin);
        return -1;
    }

    qsort(bin->sections, bin->section_count, sizeof(*bin->sections), cmp_section);
    qsort(bin->symbols, bin->symbol_count, sizeof(*bin->symbols), cmp_symbol);
    qsort(bin->imports, bin->import_count, sizeof(*bin->imports), cmp_import);
    return 0;
}

void fathom_binary_close(fathom_binary_t *bin)
{
    for (size_t i = 0; i < bin->symbol_count; i++)
        free(bin->symbols[i].name);
    for (size_t i = 0; i < bin->import_count; i++)
        free(bin->imports[i].name);
    free(bin->symbols);
    free(bin->imports);
    free(bin->sections);
    free(bin->data);
    memset(bin, 0, sizeof(*bin));
}
