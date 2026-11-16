/*
 * setsid_child.c — Test target whose child leaves the target's process
 * group and session (as daemons do) and then outlives it.
 */
#ifdef _WIN32
int main(void)
{
    return 0;
}
#else
#include <unistd.h>

int main(void)
{
    if (fork() == 0) {
        setsid();
        sleep(30);
        _exit(0);
    }
    usleep(200 * 1000);   /* the child is asleep, past every breakpoint, when we exit */
    return 0;
}
#endif
