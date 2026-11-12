/*
 * fmt_elf.c — ELF64 loader
 *
 * Defines its own copies of the few ELF structures it needs so it builds
 * on hosts without <elf.h> (macOS, Windows).
 *
 * Imports come from dynamic relocations against undefined symbols: the
 * relocation offset is the GOT slot a PLT stub (or a -fno-plt call)
 * loads its target from.
 */

#include "binary_internal.h"

#include <stdio.h>

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf_phdr_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} elf_shdr_t;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf_sym_t;

#define ELFCLASS64      2
#define ELFDATA2LSB     1
#define ET_EXEC         2
#define ET_DYN          3
#define EM_X86_64       62
#define EM_AARCH64      183
#define PT_LOAD         1
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_RELA        4
#define SHT_REL         9
#define SHT_DYNSYM      11
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4
#define STT_OBJECT      1
#define STT_FUNC        2
#define STT_GNU_IFUNC   10

static bool read_shdr(const fathom_binary_t *b, const elf_ehdr_t *eh,
                      uint32_t idx, elf_shdr_t *out)
{
    if (idx >= eh->e_shnum)
        return false;
    return bin_read(b, eh->e_shoff + (uint64_t)idx * eh->e_shentsize,
                    out, sizeof(*out));
}

static int parse_layout(fathom_binary_t *b, const elf_ehdr_t *eh)
{
    uint64_t lo = UINT64_MAX, hi = 0;

    for (uint32_t i = 0; i < eh->e_phnum; i++) {
        elf_phdr_t ph;
        if (!bin_read(b, eh->e_phoff + (uint64_t)i * eh->e_phentsize,
                      &ph, sizeof(ph)))
            return -1;
        if (ph.p_type != PT_LOAD)
            continue;
        if (ph.p_vaddr < lo)
            lo = ph.p_vaddr;
        if (ph.p_vaddr + ph.p_memsz > hi)
            hi = ph.p_vaddr + ph.p_memsz;
    }

    if (lo == UINT64_MAX)
        lo = hi = 0;
    b->image_base = lo & ~(uint64_t)0xfff;
    b->image_size = hi - b->image_base;
    return 0;
}

static int parse_sections(fathom_binary_t *b, const elf_ehdr_t *eh)
{
    elf_shdr_t strsh;
    if (!read_shdr(b, eh, eh->e_shstrndx, &strsh))
        return -1;
    uint64_t names_end = strsh.sh_offset + strsh.sh_size;

    for (uint32_t i = 0; i < eh->e_shnum; i++) {
        elf_shdr_t sh;
        if (!read_shdr(b, eh, i, &sh))
            return -1;
        if (sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_ALLOC))
            continue;

        const char *name = bin_cstr(b, strsh.sh_offset + sh.sh_name, names_end);
        if (!name)
            name = "";

        uint32_t flags = 0;
        if (sh.sh_flags & SHF_EXECINSTR)
            flags = FATHOM_SEC_CODE;
        else if (!(sh.sh_flags & SHF_WRITE) && strncmp(name, ".rodata", 7) == 0)
            flags = FATHOM_SEC_RODATA;
        if (!flags)
            continue;

        if (bin_add_section(b, sh.sh_addr, sh.sh_size, sh.sh_offset, flags,
                            name, strlen(name)) < 0)
            return -1;
    }
    return 0;
}

static int parse_symtab(fathom_binary_t *b, const elf_ehdr_t *eh,
                        const elf_shdr_t *symsh)
{
    elf_shdr_t strsh;
    if (!read_shdr(b, eh, symsh->sh_link, &strsh))
        return 0;
    uint64_t str_end = strsh.sh_offset + strsh.sh_size;
    uint64_t ent = symsh->sh_entsize ? symsh->sh_entsize : sizeof(elf_sym_t);
    uint64_t n = symsh->sh_size / ent;

    for (uint64_t i = 1; i < n; i++) {
        elf_sym_t s;
        if (!bin_read(b, symsh->sh_offset + i * ent, &s, sizeof(s)))
            return -1;
        if (s.st_shndx == 0 || s.st_value == 0 || s.st_name == 0)
            continue;

        uint8_t t = s.st_info & 0xf;
        uint8_t type = (t == STT_FUNC || t == STT_GNU_IFUNC) ? FATHOM_SYM_FUNC
                     : t == STT_OBJECT ? FATHOM_SYM_OBJECT : FATHOM_SYM_OTHER;
        const char *name = bin_cstr(b, strsh.sh_offset + s.st_name, str_end);
        if (name && bin_add_symbol(b, s.st_value, name, strlen(name),
                                   type, s.st_size) < 0)
            return -1;
    }
    return 0;
}

/* Record every dynamic relocation against an undefined symbol as an import. */
static int parse_relocs(fathom_binary_t *b, const elf_ehdr_t *eh,
                        const elf_shdr_t *rsh)
{
    elf_shdr_t symsh, strsh;
    if (!read_shdr(b, eh, rsh->sh_link, &symsh) || symsh.sh_type != SHT_DYNSYM)
        return 0;
    if (!read_shdr(b, eh, symsh.sh_link, &strsh))
        return 0;

    uint64_t str_end = strsh.sh_offset + strsh.sh_size;
    uint64_t sym_ent = symsh.sh_entsize ? symsh.sh_entsize : sizeof(elf_sym_t);
    uint64_t ent = rsh->sh_entsize ? rsh->sh_entsize
                 : rsh->sh_type == SHT_RELA ? 24 : 16;
    uint64_t n = rsh->sh_size / ent;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t r[2];
        if (!bin_read(b, rsh->sh_offset + i * ent, r, sizeof(r)))
            return -1;
        uint64_t symidx = r[1] >> 32;
        if (symidx == 0)
            continue;

        elf_sym_t s;
        if (!bin_read(b, symsh.sh_offset + symidx * sym_ent, &s, sizeof(s)))
            continue;
        if (s.st_shndx != 0 || s.st_name == 0)
            continue;

        const char *name = bin_cstr(b, strsh.sh_offset + s.st_name, str_end);
        if (name && bin_add_import(b, r[0], name, strlen(name)) < 0)
            return -1;
    }
    return 0;
}

int fathom_elf_parse(fathom_binary_t *b)
{
    elf_ehdr_t eh;
    if (!bin_read(b, 0, &eh, sizeof(eh))) {
        fprintf(stderr, "fathom: truncated ELF header\n");
        return -1;
    }
    if (eh.e_ident[4] != ELFCLASS64 || eh.e_ident[5] != ELFDATA2LSB) {
        fprintf(stderr, "fathom: only 64-bit little-endian ELF is supported\n");
        return -1;
    }
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
        fprintf(stderr, "fathom: unsupported ELF type %u\n", eh.e_type);
        return -1;
    }

    b->arch = eh.e_machine == EM_X86_64  ? FATHOM_ARCH_X86_64
            : eh.e_machine == EM_AARCH64 ? FATHOM_ARCH_ARM64
            : FATHOM_ARCH_UNKNOWN;
    b->entry = eh.e_entry;
    b->relocatable = eh.e_type == ET_DYN;

    if (eh.e_shentsize != sizeof(elf_shdr_t) && eh.e_shnum != 0)
        return -1;
    if (parse_layout(b, &eh) < 0 || parse_sections(b, &eh) < 0)
        return -1;

    /* Prefer the full .symtab; fall back to .dynsym for stripped binaries. */
    elf_shdr_t symtab = {0}, dynsym = {0};
    for (uint32_t i = 0; i < eh.e_shnum; i++) {
        elf_shdr_t sh;
        if (!read_shdr(b, &eh, i, &sh))
            return -1;
        if (sh.sh_type == SHT_SYMTAB && symtab.sh_size == 0)
            symtab = sh;
        else if (sh.sh_type == SHT_DYNSYM && dynsym.sh_size == 0)
            dynsym = sh;
        else if ((sh.sh_type == SHT_RELA || sh.sh_type == SHT_REL) &&
                 parse_relocs(b, &eh, &sh) < 0)
            return -1;
    }

    b->stripped = symtab.sh_size == 0;
    const elf_shdr_t *syms = symtab.sh_size ? &symtab : &dynsym;
    if (syms->sh_size && parse_symtab(b, &eh, syms) < 0)
        return -1;

    return 0;
}
