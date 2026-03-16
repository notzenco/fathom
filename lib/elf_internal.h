/*
 * elf_internal.h — Internal ELF parsing declarations
 */

#ifndef FATHOM_ELF_INTERNAL_H
#define FATHOM_ELF_INTERNAL_H

#include "fathom.h"
#include <elf.h>

/*
 * Locate a section header by name.
 * Returns NULL if not found.
 */
const Elf64_Shdr *fathom_elf_find_section(const fathom_elf_t *elf,
                                           const char *name);

#endif /* FATHOM_ELF_INTERNAL_H */
