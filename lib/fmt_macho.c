/*
 * fmt_macho.c — Mach-O 64 loader (thin and universal binaries)
 *
 * For a universal binary the slice matching the host CPU is chosen,
 * falling back to the first supported one.
 *
 * Imports come from the indirect symbol table, which names each entry
 * of the __stubs section (what `call`/`bl` targets) and of the lazy and
 * non-lazy pointer sections (what the stubs load from).
 */

#include "binary_internal.h"

#include <stdio.h>

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} macho_header_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} macho_lc_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} macho_section_t;

typedef struct {
    uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize;
} macho_symtab_t;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym;
    uint32_t tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms;
    uint32_t indirectsymoff, nindirectsyms;
    uint32_t extreloff, nextrel, locreloff, nlocrel;
} macho_dysymtab_t;

typedef struct {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} macho_nlist_t;

#define MH_MAGIC_64              0xfeedfacfu
#define MH_EXECUTE               2
#define MH_PIE                   0x200000u
#define CPU_TYPE_X86_64          0x01000007
#define CPU_TYPE_ARM64           0x0100000c
#define LC_SYMTAB                0x2
#define LC_UNIXTHREAD            0x5
#define LC_DYSYMTAB              0xb
#define LC_SEGMENT_64            0x19
#define LC_MAIN                  0x80000028u
#define SECTION_TYPE             0xff
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define S_LAZY_SYMBOL_POINTERS   0x7
#define S_SYMBOL_STUBS           0x8
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400u
#define INDIRECT_SYMBOL_LOCAL    0x80000000u
#define INDIRECT_SYMBOL_ABS      0x40000000u
#define N_STAB                   0xe0
#define N_TYPE                   0x0e
#define N_SECT                   0x0e

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}

static uint64_t be64(const uint8_t *p)
{
    return (uint64_t)be32(p) << 32 | be32(p + 4);
}

static fathom_arch_t arch_of(int32_t cputype)
{
    return cputype == CPU_TYPE_X86_64 ? FATHOM_ARCH_X86_64
         : cputype == CPU_TYPE_ARM64  ? FATHOM_ARCH_ARM64
         : FATHOM_ARCH_UNKNOWN;
}

/* Point b->image at the best slice of a universal binary. */
static int select_slice(fathom_binary_t *b)
{
    const uint8_t *d = b->data;
    bool is64 = d[3] == 0xbf;
    size_t ent = is64 ? 32 : 20;

    if (b->data_len < 8)
        return -1;
    uint32_t n = be32(d + 4);
    if (n == 0 || n > 32 || 8 + (uint64_t)n * ent > b->data_len)
        return -1;   /* also rejects Java class files, which share 0xcafebabe */

    int64_t pick = -1;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *fa = d + 8 + (size_t)i * ent;
        fathom_arch_t a = arch_of((int32_t)be32(fa));
        if (a == FATHOM_ARCH_UNKNOWN)
            continue;
        if (pick < 0 || a == fathom_host_arch())
            pick = i;
        if (a == fathom_host_arch())
            break;
    }
    if (pick < 0) {
        fprintf(stderr, "fathom: universal binary has no x86-64 or arm64 slice\n");
        return -1;
    }

    const uint8_t *fa = d + 8 + (size_t)pick * ent;
    uint64_t off  = is64 ? be64(fa + 8)  : be32(fa + 8);
    uint64_t size = is64 ? be64(fa + 16) : be32(fa + 12);
    if (off > b->data_len || size > b->data_len - off)
        return -1;

    b->image = d + off;
    b->image_len = (size_t)size;
    return 0;
}

static void section_name(const macho_section_t *s, char *out, size_t cap)
{
    snprintf(out, cap, "%.16s,%.16s", s->segname, s->sectname);
}

typedef struct {
    macho_symtab_t   symtab;
    macho_dysymtab_t dysymtab;
    bool             have_symtab;
    bool             have_dysymtab;
} macho_tables_t;

/* Name of symbol-table entry idx, without the leading underscore. */
static const char *symbol_name(const fathom_binary_t *b,
                               const macho_tables_t *t, uint32_t idx)
{
    if (!t->have_symtab || idx >= t->symtab.nsyms)
        return NULL;
    macho_nlist_t nl;
    if (!bin_read(b, t->symtab.symoff + (uint64_t)idx * sizeof(nl), &nl, sizeof(nl)))
        return NULL;
    const char *name = bin_cstr(b, (uint64_t)t->symtab.stroff + nl.n_strx,
                                (uint64_t)t->symtab.stroff + t->symtab.strsize);
    if (name && name[0] == '_')
        name++;
    return name;
}

static int add_indirect_imports(fathom_binary_t *b, const macho_tables_t *t,
                                const macho_section_t *s)
{
    uint32_t type = s->flags & SECTION_TYPE;
    uint64_t stride;

    if (type == S_SYMBOL_STUBS)
        stride = s->reserved2;
    else if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS)
        stride = 8;
    else
        return 0;
    if (stride == 0 || !t->have_dysymtab)
        return 0;

    uint64_t count = s->size / stride;
    for (uint64_t i = 0; i < count; i++) {
        uint32_t idx;
        uint64_t slot = (uint64_t)s->reserved1 + i;
        if (slot >= t->dysymtab.nindirectsyms ||
            !bin_read(b, t->dysymtab.indirectsymoff + slot * 4, &idx, 4))
            break;
        if (idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))
            continue;
        const char *name = symbol_name(b, t, idx);
        if (name && bin_add_import(b, s->addr + i * stride, name, strlen(name)) < 0)
            return -1;
    }
    return 0;
}

static int add_symbols(fathom_binary_t *b, const macho_tables_t *t)
{
    size_t defined = 0;

    for (uint32_t i = 0; t->have_symtab && i < t->symtab.nsyms; i++) {
        macho_nlist_t nl;
        if (!bin_read(b, t->symtab.symoff + (uint64_t)i * sizeof(nl), &nl, sizeof(nl)))
            return -1;
        if ((nl.n_type & N_STAB) || (nl.n_type & N_TYPE) != N_SECT || nl.n_value == 0)
            continue;

        const char *name = symbol_name(b, t, i);
        if (!name || strcmp(name, "_mh_execute_header") == 0)
            continue;

        uint8_t type = FATHOM_SYM_OBJECT;
        for (size_t s = 0; s < b->section_count; s++) {
            const fathom_section_t *sec = &b->sections[s];
            if ((sec->flags & FATHOM_SEC_CODE) &&
                nl.n_value >= sec->addr && nl.n_value < sec->addr + sec->size)
                type = FATHOM_SYM_FUNC;
        }
        if (bin_add_symbol(b, nl.n_value, name, strlen(name), type, 0) < 0)
            return -1;
        defined++;
    }

    b->stripped = defined == 0;
    return 0;
}

int fathom_macho_parse(fathom_binary_t *b)
{
    if (b->data[0] == 0xca && select_slice(b) < 0)
        return -1;

    macho_header_t mh;
    if (!bin_read(b, 0, &mh, sizeof(mh)) || mh.magic != MH_MAGIC_64) {
        fprintf(stderr, "fathom: only 64-bit Mach-O is supported\n");
        return -1;
    }

    b->arch = arch_of(mh.cputype);
    b->relocatable = (mh.flags & MH_PIE) != 0;

    macho_tables_t tables = {0};
    uint64_t text_vmaddr = 0, entryoff = 0, lo = UINT64_MAX, hi = 0;
    bool have_main = false;

    /* Pass 1: segments, sections and symbol table locations. */
    uint64_t off = sizeof(mh);
    for (uint32_t c = 0; c < mh.ncmds; c++) {
        macho_lc_t lc;
        if (!bin_read(b, off, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc))
            return -1;

        if (lc.cmd == LC_SEGMENT_64) {
            macho_segment_t seg;
            if (!bin_read(b, off, &seg, sizeof(seg)))
                return -1;
            if (strncmp(seg.segname, "__TEXT", 16) == 0)
                text_vmaddr = seg.vmaddr;
            if (seg.initprot != 0) {   /* skip __PAGEZERO */
                if (seg.vmaddr < lo)
                    lo = seg.vmaddr;
                if (seg.vmaddr + seg.vmsize > hi)
                    hi = seg.vmaddr + seg.vmsize;
            }

            for (uint32_t s = 0; s < seg.nsects; s++) {
                macho_section_t sec;
                if (!bin_read(b, off + sizeof(seg) + (uint64_t)s * sizeof(sec),
                              &sec, sizeof(sec)))
                    return -1;

                char name[40];
                section_name(&sec, name, sizeof(name));
                uint32_t flags = 0;
                if (sec.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
                    flags = FATHOM_SEC_CODE;
                else if (strcmp(name, "__TEXT,__cstring") == 0 ||
                         strcmp(name, "__TEXT,__const") == 0)
                    flags = FATHOM_SEC_RODATA;
                if (flags && sec.offset != 0 &&
                    bin_add_section(b, sec.addr, sec.size, sec.offset, flags,
                                    name, strlen(name)) < 0)
                    return -1;
            }
        } else if (lc.cmd == LC_SYMTAB) {
            tables.have_symtab = bin_read(b, off, &tables.symtab, sizeof(tables.symtab));
        } else if (lc.cmd == LC_DYSYMTAB) {
            tables.have_dysymtab = bin_read(b, off, &tables.dysymtab,
                                            sizeof(tables.dysymtab));
        } else if (lc.cmd == LC_MAIN) {
            have_main = bin_read(b, off + 8, &entryoff, sizeof(entryoff));
        } else if (lc.cmd == LC_UNIXTHREAD && !have_main) {
            /* flavor, count, then the register state; pc is at a fixed slot. */
            uint64_t pc = 0;
            uint64_t pc_off = b->arch == FATHOM_ARCH_ARM64 ? 16 + 32 * 8
                                                           : 16 + 16 * 8;
            if (bin_read(b, off + pc_off, &pc, sizeof(pc)))
                b->entry = pc;
        }
        off += lc.cmdsize;
    }

    if (have_main)
        b->entry = text_vmaddr + entryoff;
    b->image_base = text_vmaddr;
    b->image_size = hi > lo ? hi - text_vmaddr : 0;

    /* Pass 2: imports from stub / pointer sections, now that tables are known. */
    off = sizeof(mh);
    for (uint32_t c = 0; c < mh.ncmds; c++) {
        macho_lc_t lc;
        if (!bin_read(b, off, &lc, sizeof(lc)))
            return -1;
        if (lc.cmd == LC_SEGMENT_64) {
            macho_segment_t seg;
            if (!bin_read(b, off, &seg, sizeof(seg)))
                return -1;
            for (uint32_t s = 0; s < seg.nsects; s++) {
                macho_section_t sec;
                if (!bin_read(b, off + sizeof(seg) + (uint64_t)s * sizeof(sec),
                              &sec, sizeof(sec)))
                    return -1;
                if (add_indirect_imports(b, &tables, &sec) < 0)
                    return -1;
            }
        }
        off += lc.cmdsize;
    }

    return add_symbols(b, &tables);
}
