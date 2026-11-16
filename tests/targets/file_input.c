/*
 * file_input.c — Test target that reads its input from the file named by
 * its last argument (run as `file_input --in=@@`), not from stdin.
 * Crashes when the file starts with 'C'.
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2 || strncmp(argv[argc - 1], "--in=", 5) != 0)
        return 2;
    FILE *f = fopen(argv[argc - 1] + 5, "rb");
    if (!f)
        return 3;
    int c = fgetc(f);
    fclose(f);
    if (getchar() != EOF)
        return 4;   /* stdin must be empty when input comes from a file */
    if (c == 'C') {
        volatile int *p = NULL;
        *p = 1;
    }
    return 0;
}
