/*
 * reexec.c — Test target that re-executes itself before reading input.
 *
 * Input 'C' then crashes, so coverage and crash detection must survive
 * the exec.
 */
#ifdef _WIN32
int main(void)
{
    return 0;
}
#else
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        char *args[] = { argv[0], "again", NULL };
        execv(argv[0], args);
        return 1;
    }
    if (getchar() == 'C') {
        volatile int *p = NULL;
        *p = 1;
    }
    return 0;
}
#endif
