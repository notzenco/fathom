/*
 * be_length.c — Benchmark target: a big-endian 16-bit length field, as in
 * file formats and network protocols, must equal a constant.
 */
#include <stdio.h>

int main(void)
{
    unsigned char b[16] = {0};
    size_t n = fread(b, 1, sizeof(b), stdin);
    if (n >= 4) {
        unsigned len = (unsigned)b[0] << 8 | b[1];
        if (len == 0x1f40 && b[2] == 'X') {
            volatile int *p = NULL;
            *p = 1;
        }
    }
    return 0;
}
