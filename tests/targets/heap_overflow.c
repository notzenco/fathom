/*
 * heap_overflow.c — Test target: heap buffer overflow via unchecked memcpy.
 * Reads stdin into a fixed heap buffer without length validation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

static void process(const char *data, size_t len)
{
    char *buf = malloc(BUF_SIZE);
    if (!buf) return;

    /* Bug: copies len bytes into a 64-byte buffer */
    memcpy(buf, data, len);

    /* Touch the buffer so optimizer doesn't elide the copy */
    if (buf[0] == 'F' && buf[1] == 'U' && buf[2] == 'Z' && buf[3] == 'Z') {
        /* Trigger deeper path only with magic header */
        char *buf2 = malloc(32);
        if (!buf2) { free(buf); return; }
        memcpy(buf2, buf + 4, len - 4);  /* Double overflow */
        free(buf2);
    }

    free(buf);
}

int main(void)
{
    char input[4096];
    size_t n = fread(input, 1, sizeof(input), stdin);
    if (n > 0)
        process(input, n);
    return 0;
}
