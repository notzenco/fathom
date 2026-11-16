/*
 * o2_compare.c — Benchmark target built with -O2: a 32-bit magic value
 * kept in data, so the comparison reads it from memory or a register
 * rather than encoding it as an immediate operand.
 */
#include <stdio.h>
#include <string.h>

static volatile unsigned magic = 0xdeadbeefu;

int main(void)
{
    unsigned char b[8] = {0};
    if (fread(b, 1, sizeof(b), stdin) >= 4) {
        unsigned v;
        memcpy(&v, b, 4);
        if (v == magic) {
            volatile int *p = NULL;
            *p = 1;
        }
    }
    return 0;
}
