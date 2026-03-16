/*
 * stack_smash.c — Test target: stack buffer overflow via gets-like pattern.
 * Reads stdin into a stack buffer with no bounds checking.
 */
#include <stdio.h>
#include <string.h>

static void vulnerable(void)
{
    char buf[64];
    int c, i = 0;

    /* Bug: reads unlimited input into 64-byte stack buffer */
    while ((c = getchar()) != EOF && c != '\n') {
        buf[i++] = (char)c;
    }
    buf[i] = '\0';

    /* Deep path: only reachable with specific prefix */
    if (i > 4 && buf[0] == 'S' && buf[1] == 'M' &&
        buf[2] == 'S' && buf[3] == 'H') {
        char tmp[32];
        strcpy(tmp, buf + 4);   /* Second overflow */
        printf("matched: %s\n", tmp);
    }
}

int main(void)
{
    vulnerable();
    return 0;
}
