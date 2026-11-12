/*
 * osdep.h — Small OS abstractions shared by the library and CLI
 */

#ifndef FATHOM_OSDEP_H
#define FATHOM_OSDEP_H

#include <stdint.h>

/* Create one directory; succeeds if it already exists. */
int fathom_mkdir(const char *path);

/* Monotonic clock in microseconds. */
uint64_t fathom_now_us(void);

/* 64 bits from the OS random source (falls back to time and pid). */
uint64_t fathom_entropy(void);

/* Directory for temporary files, without a trailing separator. */
const char *fathom_tmpdir(void);

#ifdef _WIN32
/* Join argv into a command line that the CRT splits back identically. */
char *fathom_win_cmdline(char *const *argv);
#endif

#endif /* FATHOM_OSDEP_H */
