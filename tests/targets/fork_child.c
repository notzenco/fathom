/*
 * fork_child.c — Test target whose child process runs instrumented code.
 *
 * The parent aborts if the child dies from a signal, which is what an
 * inherited breakpoint does to an untraced child.  With input 'S' the
 * child sleeps and the parent exits, leaving the child behind.
 */
#ifdef _WIN32
int main(void)
{
    return 0;
}
#else
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int work(int c)
{
    int n = 0;
    for (int i = 0; i < c % 7; i++) {
        if (i & 1)
            n += i;
        else
            n -= 1;
    }
    return n;
}

int main(void)
{
    int c = getchar();
    pid_t pid = fork();
    if (pid == 0) {
        if (c == 'S')
            sleep(30);
        _exit(work(c) == 12345);
    }
    if (c == 'S')
        return 0;

    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        abort();
    return 0;
}
#endif
