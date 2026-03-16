/*
 * elf.c — ELF binary parser for libfathom
 *
 * Opens an ELF binary, maps it into memory, and extracts key sections
 * (.text, .plt, .rodata) and symbols.
 */

#include "elf_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Helpers ──────────────────────────────────────────────────────────── */

static int parse_sections(fathom_elf_t *elf)
{
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf->mapped;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        return 0; /* no section headers — not fatal */

    if (ehdr->e_shoff + (uint64_t)ehdr->e_shnum * ehdr->e_shentsize > elf->mapped_len)
        return -1;

    const Elf64_Shdr *shdrs =
        (const Elf64_Shdr *)(elf->mapped + ehdr->e_shoff);

    /* section name string table */
    if (ehdr->e_shstrndx >= ehdr->e_shnum)
        return -1;
    const Elf64_Shdr *strtab_sh = &shdrs[ehdr->e_shstrndx];
    if (strtab_sh->sh_offset + strtab_sh->sh_size > elf->mapped_len)
        return -1;
    const char *shstrtab = (const char *)(elf->mapped + strtab_sh->sh_offset);

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (sh->sh_name >= strtab_sh->sh_size)
            continue;
        const char *name = shstrtab + sh->sh_name;

        if (strcmp(name, ".text") == 0) {
            elf->text = (fathom_section_t){
                .addr   = sh->sh_addr,
                .size   = sh->sh_size,
                .offset = sh->sh_offset,
                .name   = ".text",
            };
        } else if (strcmp(name, ".plt") == 0) {
            elf->plt = (fathom_section_t){
                .addr   = sh->sh_addr,
                .size   = sh->sh_size,
                .offset = sh->sh_offset,
                .name   = ".plt",
            };
        } else if (strcmp(name, ".rodata") == 0) {
            elf->rodata = (fathom_section_t){
                .addr   = sh->sh_addr,
                .size   = sh->sh_size,
                .offset = sh->sh_offset,
                .name   = ".rodata",
            };
        }
    }

    return 0;
}

const Elf64_Shdr *fathom_elf_find_section(const fathom_elf_t *elf,
                                           const char *name)
{
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf->mapped;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        return NULL;

    const Elf64_Shdr *shdrs =
        (const Elf64_Shdr *)(elf->mapped + ehdr->e_shoff);

    if (ehdr->e_shstrndx >= ehdr->e_shnum)
        return NULL;
    const Elf64_Shdr *strtab_sh = &shdrs[ehdr->e_shstrndx];
    const char *shstrtab = (const char *)(elf->mapped + strtab_sh->sh_offset);

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_name >= strtab_sh->sh_size)
            continue;
        if (strcmp(shstrtab + shdrs[i].sh_name, name) == 0)
            return &shdrs[i];
    }
    return NULL;
}

static int parse_symbols(fathom_elf_t *elf)
{
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf->mapped;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        return 0;

    const Elf64_Shdr *shdrs =
        (const Elf64_Shdr *)(elf->mapped + ehdr->e_shoff);

    /* Find .symtab; fall back to .dynsym */
    const Elf64_Shdr *sym_sh = NULL;
    const Elf64_Shdr *str_sh = NULL;
    bool have_symtab = false;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            sym_sh = &shdrs[i];
            have_symtab = true;
            if (sym_sh->sh_link < ehdr->e_shnum)
                str_sh = &shdrs[sym_sh->sh_link];
            break;
        }
    }

    if (!sym_sh) {
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_DYNSYM) {
                sym_sh = &shdrs[i];
                if (sym_sh->sh_link < ehdr->e_shnum)
                    str_sh = &shdrs[sym_sh->sh_link];
                break;
            }
        }
    }

    elf->stripped = !have_symtab;

    if (!sym_sh || !str_sh)
        return 0;

    if (sym_sh->sh_offset + sym_sh->sh_size > elf->mapped_len)
        return -1;
    if (str_sh->sh_offset + str_sh->sh_size > elf->mapped_len)
        return -1;

    size_t entry_size = sym_sh->sh_entsize ? sym_sh->sh_entsize : sizeof(Elf64_Sym);
    size_t nsyms = sym_sh->sh_size / entry_size;

    const Elf64_Sym *syms = (const Elf64_Sym *)(elf->mapped + sym_sh->sh_offset);
    const char *strtab = (const char *)(elf->mapped + str_sh->sh_offset);

    elf->symbols = calloc(nsyms, sizeof(fathom_symbol_t));
    if (!elf->symbols)
        return -1;

    size_t count = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const Elf64_Sym *s = &syms[i];
        if (s->st_name == 0)
            continue;
        if (s->st_name >= str_sh->sh_size)
            continue;

        fathom_symbol_t *fs = &elf->symbols[count++];
        fs->addr = s->st_value;
        fs->name = strtab + s->st_name;
        fs->type = ELF64_ST_TYPE(s->st_info);
        fs->bind = ELF64_ST_BIND(s->st_info);
        fs->size = s->st_size;
    }
    elf->symbol_count = count;

    return 0;
}

/* ── Public API ───────────────────────────────────────────────────────── */

int fathom_elf_open(fathom_elf_t *elf, const char *path)
{
    memset(elf, 0, sizeof(*elf));

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "fathom: open(%s): %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    elf->mapped_len = (size_t)st.st_size;
    elf->mapped = mmap(NULL, elf->mapped_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (elf->mapped == MAP_FAILED) {
        elf->mapped = NULL;
        return -1;
    }

    /* Validate ELF magic */
    if (elf->mapped_len < sizeof(Elf64_Ehdr)) {
        fathom_elf_close(elf);
        return -1;
    }
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf->mapped;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "fathom: %s: not an ELF file\n", path);
        fathom_elf_close(elf);
        return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "fathom: %s: not a 64-bit ELF\n", path);
        fathom_elf_close(elf);
        return -1;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        fprintf(stderr, "fathom: %s: unsupported ELF type %u\n", path,
                ehdr->e_type);
        fathom_elf_close(elf);
        return -1;
    }

    elf->entry = ehdr->e_entry;

    if (parse_sections(elf) < 0) {
        fathom_elf_close(elf);
        return -1;
    }
    if (parse_symbols(elf) < 0) {
        fathom_elf_close(elf);
        return -1;
    }

    if (elf->text.size == 0) {
        fprintf(stderr, "fathom: %s: no .text section found\n", path);
        fathom_elf_close(elf);
        return -1;
    }

    return 0;
}

void fathom_elf_close(fathom_elf_t *elf)
{
    if (elf->mapped) {
        munmap(elf->mapped, elf->mapped_len);
        elf->mapped = NULL;
    }
    free(elf->symbols);
    elf->symbols = NULL;
    elf->symbol_count = 0;
}
