/*
 * maze.c — Test target that only coverage feedback can solve.
 *
 * The crash needs the input to start with "FUZZ".  Each byte is checked
 * in its own branch, so a coverage-guided fuzzer can solve it one byte at
 * a time, while blind random mutation almost never does.  None of the
 * magic bytes appear in .rodata, so dictionary extraction cannot help.
 */
#include <stdio.h>
#include <stdlib.h>

static void crash(void)
{
    volatile int *p = NULL;
    *p = 1;
}

int main(void)
{
    unsigned char b[16] = {0};
    size_t n = fread(b, 1, sizeof(b), stdin);

    if (n >= 4) {
        if (b[0] == 'F') {
            if (b[1] == 'U') {
                if (b[2] == 'Z') {
                    if (b[3] == 'Z')
                        crash();
                }
            }
        }
    }
    return 0;
}
