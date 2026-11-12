/*
 * fmt_pe.c — PE32+ loader (x64 and ARM64 Windows executables)
 *
 * Imports come from the import directory: each entry's address is its
 * IAT slot, which MSVC code calls through directly (`call [rip+slot]`)
 * and MinGW code reaches via a `jmp [rip+slot]` thunk.  Function
 * symbols come from the COFF symbol table when the linker kept one
 * (MinGW does unless stripped).
 */

#include "binary_internal.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_coff_t;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_t;

typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} pe_import_desc_t;

#define PE_MACHINE_AMD64        0x8664
#define PE_MACHINE_ARM64        0xaa64
#define PE_OPT_MAGIC_PE32PLUS   0x20b
#define PE_DLL_DYNAMIC_BASE     0x0040
#define PE_SCN_CNT_CODE         0x00000020u
#define PE_SCN_MEM_EXECUTE      0x20000000u
#define PE_SCN_MEM_WRITE        0x80000000u
#define PE_ORDINAL_FLAG         0x8000000000000000ull
#define PE_SYM_SIZE             18
#define PE_DTYPE_FUNCTION       0x20

typedef struct {
    pe_section_t *secs;
    uint16_t      count;
    uint64_t      image_base;
} pe_layout_t;

/* Translate an RVA to an image offset, or UINT64_MAX if it is not file-backed. */
static uint64_t rva_to_off(const pe_layout_t *l, uint32_t rva)
{
    for (uint16_t i = 0; i < l->count; i++) {
        const pe_section_t *s = &l->secs[i];
        uint32_t span = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva - s->VirtualAddress < span &&
            rva - s->VirtualAddress < s->SizeOfRawData)
            return (uint64_t)s->PointerToRawData + (rva - s->VirtualAddress);
    }
    return UINT64_MAX;
}

static int parse_imports(fathom_binary_t *b, const pe_layout_t *l,
                         uint32_t dir_rva)
{
    if (dir_rva == 0)
        return 0;
    uint64_t off = rva_to_off(l, dir_rva);

    for (;; off += sizeof(pe_import_desc_t)) {
        pe_import_desc_t d;
        if (off == UINT64_MAX || !bin_read(b, off, &d, sizeof(d)))
            return 0;
        if (d.FirstThunk == 0 && d.Name == 0)
            return 0;

        uint32_t names_rva = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        uint64_t thunk_off = rva_to_off(l, names_rva);
        if (thunk_off == UINT64_MAX)
            continue;

        for (uint64_t i = 0;; i++) {
            uint64_t thunk;
            if (!bin_read(b, thunk_off + i * 8, &thunk, 8) || thunk == 0)
                break;
            if (thunk & PE_ORDINAL_FLAG)
                continue;
            uint64_t name_off = rva_to_off(l, (uint32_t)thunk);
            if (name_off == UINT64_MAX)
                continue;
            const char *name = bin_cstr(b, name_off + 2, b->image_len);   /* skip Hint */
            uint64_t slot = l->image_base + d.FirstThunk + i * 8;
            if (name && bin_add_import(b, slot, name, strlen(name)) < 0)
                return -1;
        }
    }
}

static int parse_coff_symbols(fathom_binary_t *b, const pe_coff_t *coff,
                              const pe_layout_t *l)
{
    if (coff->PointerToSymbolTable == 0 || coff->NumberOfSymbols == 0)
        return 0;

    uint64_t strtab = coff->PointerToSymbolTable +
                      (uint64_t)coff->NumberOfSymbols * PE_SYM_SIZE;
    uint32_t strtab_size = 0;
    bin_read(b, strtab, &strtab_size, 4);

    for (uint32_t i = 0; i < coff->NumberOfSymbols; i++) {
        uint8_t raw[PE_SYM_SIZE];
        if (!bin_read(b, coff->PointerToSymbolTable + (uint64_t)i * PE_SYM_SIZE,
                      raw, sizeof(raw)))
            return 0;

        uint32_t value, zeroes, stroff;
        int16_t section;
        uint16_t type;
        memcpy(&value, raw + 8, 4);
        memcpy(&section, raw + 12, 2);
        memcpy(&type, raw + 14, 2);
        uint8_t aux = raw[17];

        if (section > 0 && section <= l->count && (type & 0xf0) == PE_DTYPE_FUNCTION) {
            const char *name;
            size_t len;
            memcpy(&zeroes, raw, 4);
            if (zeroes == 0) {
                memcpy(&stroff, raw + 4, 4);
                name = bin_cstr(b, strtab + stroff, strtab + strtab_size);
                len = name ? strlen(name) : 0;
            } else {
                name = (const char *)raw;
                len = 8;
            }
            uint64_t addr = l->image_base + l->secs[section - 1].VirtualAddress + value;
            if (name && bin_add_symbol(b, addr, name, len, FATHOM_SYM_FUNC, 0) < 0)
                return -1;
        }
        i += aux;
    }
    return 0;
}

int fathom_pe_parse(fathom_binary_t *b)
{
    uint32_t pe_off = 0;
    char sig[4];
    if (!bin_read(b, 0x3c, &pe_off, 4) || !bin_read(b, pe_off, sig, 4) ||
        memcmp(sig, "PE\0\0", 4) != 0) {
        fprintf(stderr, "fathom: not a PE executable\n");
        return -1;
    }

    pe_coff_t coff;
    uint64_t opt = pe_off + 4 + sizeof(coff);
    uint16_t magic = 0;
    if (!bin_read(b, pe_off + 4, &coff, sizeof(coff)) ||
        !bin_read(b, opt, &magic, 2) || magic != PE_OPT_MAGIC_PE32PLUS) {
        fprintf(stderr, "fathom: only 64-bit (PE32+) executables are supported\n");
        return -1;
    }

    b->arch = coff.Machine == PE_MACHINE_AMD64 ? FATHOM_ARCH_X86_64
            : coff.Machine == PE_MACHINE_ARM64 ? FATHOM_ARCH_ARM64
            : FATHOM_ARCH_UNKNOWN;

    uint32_t entry_rva = 0, size_of_image = 0, n_dirs = 0;
    uint32_t import_rva = 0;
    uint16_t dll_chars = 0;
    uint64_t image_base = 0;
    bin_read(b, opt + 16, &entry_rva, 4);
    bin_read(b, opt + 24, &image_base, 8);
    bin_read(b, opt + 56, &size_of_image, 4);
    bin_read(b, opt + 70, &dll_chars, 2);
    bin_read(b, opt + 108, &n_dirs, 4);
    if (n_dirs > 1)
        bin_read(b, opt + 112 + 8, &import_rva, 4);

    b->image_base  = image_base;
    b->image_size  = size_of_image;
    b->entry       = image_base + entry_rva;
    b->relocatable = (dll_chars & PE_DLL_DYNAMIC_BASE) != 0;

    pe_layout_t l = { .count = coff.NumberOfSections, .image_base = image_base };
    l.secs = calloc(l.count ? l.count : 1, sizeof(*l.secs));
    if (!l.secs)
        return -1;

    int rc = 0;
    uint64_t sec_off = opt + coff.SizeOfOptionalHeader;
    for (uint16_t i = 0; i < l.count && rc == 0; i++) {
        pe_section_t *s = &l.secs[i];
        if (!bin_read(b, sec_off + (uint64_t)i * sizeof(*s), s, sizeof(*s))) {
            rc = -1;
            break;
        }

        uint32_t flags = 0;
        if (s->Characteristics & (PE_SCN_CNT_CODE | PE_SCN_MEM_EXECUTE))
            flags = FATHOM_SEC_CODE;
        else if (!(s->Characteristics & PE_SCN_MEM_WRITE) &&
                 strncmp(s->Name, ".rdata", 8) == 0)
            flags = FATHOM_SEC_RODATA;

        uint32_t size = s->SizeOfRawData;
        if (s->VirtualSize && s->VirtualSize < size)
            size = s->VirtualSize;
        if (flags)
            rc = bin_add_section(b, image_base + s->VirtualAddress, size,
                                 s->PointerToRawData, flags, s->Name, 8);
    }

    if (rc == 0)
        rc = parse_imports(b, &l, import_rva);
    if (rc == 0)
        rc = parse_coff_symbols(b, &coff, &l);
    b->stripped = b->symbol_count == 0;

    free(l.secs);
    return rc;
}
