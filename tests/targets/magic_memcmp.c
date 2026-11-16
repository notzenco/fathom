/*
 * magic_memcmp.c — Benchmark target: a magic string checked with
 * memcmp, which only the read-only-data dictionary can supply.
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char b[32] = {0};
    size_t n = fread(b, 1, sizeof(b), stdin);
    if (n >= 10 && b[0] == 'M' && memcmp(b + 4, "SESAME", 6) == 0) {
        volatile int *p = NULL;
        *p = 1;
    }
    return 0;
}
