/*
 * libmaze.c — Shared library for the library coverage tests: the maze,
 * but in a library.  Crashes on input starting with "LIB!", each byte
 * checked in its own branch, so only coverage of the library's own code
 * can lead a fuzzer there.
 */
#include <stddef.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int libmaze_check(const unsigned char *b, size_t n)
{
    if (n >= 4) {
        if (b[0] == 'L') {
            if (b[1] == 'I') {
                if (b[2] == 'B') {
                    if (b[3] == '!') {
                        volatile int *p = NULL;
                        *p = 1;
                    }
                }
            }
        }
    }
    return 0;
}
