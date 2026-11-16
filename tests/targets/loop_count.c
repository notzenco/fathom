/*
 * loop_count.c — Test target whose only input-dependent behaviour is
 * how many times a loop runs: the first byte's digit value.
 */
#include <stdio.h>

int main(void)
{
    int c = getchar();
    int n = c >= '0' && c <= '9' ? c - '0' : 0;
    volatile int sum = 0;
    for (int i = 0; i < n; i++)
        sum += i;
    return 0;
}
