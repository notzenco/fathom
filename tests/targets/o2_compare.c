/*
 * o2_compare.c — Benchmark target built with -O2: a 32-bit magic value
 * that arm64 compilers load into a register before comparing, so it is
 * not an immediate operand of the comparison.
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char b[8] = {0};
    if (fread(b, 1, sizeof(b), stdin) >= 4) {
        unsigned v;
        memcpy(&v, b, 4);
        if (v == 0xdeadbeefu) {
            volatile int *p = NULL;
            *p = 1;
        }
    }
    return 0;
}
