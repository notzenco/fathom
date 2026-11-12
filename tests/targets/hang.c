/*
 * hang.c — Test target that never exits when the input starts with 'H'.
 */
#include <stdio.h>

int main(void)
{
    int c = getchar();
    if (c == 'H') {
        for (volatile unsigned long i = 0;; i++)
            ;
    }
    return 0;
}
