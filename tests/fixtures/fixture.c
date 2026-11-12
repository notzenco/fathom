/*
 * fixture.c — Source of the prebuilt binaries in this directory.
 *
 * The binary-format tests load these on every platform, so ELF, Mach-O
 * and PE parsing are all exercised whatever the host is.  Rebuild them
 * with build.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checksum(const char *s, size_t n)
{
    int c = 0;
    for (size_t i = 0; i < n; i++)
        c += s[i];
    return c;
}

/* Reached only through a function pointer. */
static int by_pointer(int x)
{
    return x * 3;
}

int main(int argc, char **argv)
{
    int (*fp)(int) = by_pointer;
    char buf[64];
    char *heap = malloc(32);

    if (!heap)
        return 1;
    if (argc > 1) {
        strcpy(buf, argv[1]);
        memcpy(heap, buf, strlen(buf) % 32);
        if (argv[1][0] == 0x37)
            heap[0] = 1;
    }
    printf("FIXTURE-MAGIC %d %d\n", checksum(heap, 16), fp(argc));
    free(heap);
    return 0;
}
