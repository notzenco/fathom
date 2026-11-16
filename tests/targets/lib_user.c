/*
 * lib_user.c — Test target that passes its input to libmaze_check in a
 * shared library (tests/targets/lib/libmaze.c) and does nothing else.
 */
#include <stddef.h>
#include <stdio.h>

int libmaze_check(const unsigned char *b, size_t n);

int main(void)
{
    unsigned char b[16] = {0};
    size_t n = fread(b, 1, sizeof(b), stdin);
    return libmaze_check(b, n);
}
