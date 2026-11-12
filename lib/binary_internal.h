/*
 * binary_internal.h — Shared helpers for the ELF, Mach-O and PE loaders
 *
 * Every format parser reads through these bounds-checked helpers and
 * copies structures out with memcpy, so malformed or truncated files
 * fail cleanly and unaligned fields are safe on every host.  All
 * supported targets are little-endian; only the Mach-O fat header is
 * big-endian.
 */

#ifndef FATHOM_BINARY_INTERNAL_H
#define FATHOM_BINARY_INTERNAL_H

#include "fathom.h"

#include <string.h>

static inline bool bin_read(const fathom_binary_t *b, uint64_t off,
                            void *dst, size_t n)
{
    if (off > b->image_len || n > b->image_len - off)
        return false;
    memcpy(dst, b->image + off, n);
    return true;
}

/*
 * Return the NUL-terminated string at image offset off, or NULL if it
 * would run past limit (an image offset) or the end of the image.
 */
static inline const char *bin_cstr(const fathom_binary_t *b, uint64_t off,
                                   uint64_t limit)
{
    if (limit > b->image_len)
        limit = b->image_len;
    if (off >= limit)
        return NULL;
    const char *s = (const char *)b->image + off;
    if (!memchr(s, '\0', (size_t)(limit - off)))
        return NULL;
    return s;
}

int bin_add_section(fathom_binary_t *b, uint64_t addr, uint64_t size,
                    uint64_t offset, uint32_t flags, const char *name,
                    size_t name_len);
int bin_add_symbol(fathom_binary_t *b, uint64_t addr, const char *name,
                   size_t name_len, uint8_t type, uint64_t size);
int bin_add_import(fathom_binary_t *b, uint64_t addr, const char *name,
                   size_t name_len);

int fathom_elf_parse(fathom_binary_t *b);
int fathom_macho_parse(fathom_binary_t *b);
int fathom_pe_parse(fathom_binary_t *b);

#endif /* FATHOM_BINARY_INTERNAL_H */
