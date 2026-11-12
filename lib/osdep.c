/*
 * osdep.c — Small OS abstractions shared by the library and CLI
 */

#include "osdep.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <process.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

int fathom_mkdir(const char *path)
{
#ifdef _WIN32
    int rc = _mkdir(path);
#else
    int rc = mkdir(path, 0755);
#endif
    if (rc == 0 || errno == EEXIST)
        return 0;
    return -1;
}

uint64_t fathom_now_us(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (uint64_t)(now.QuadPart / freq.QuadPart) * 1000000u +
           (uint64_t)(now.QuadPart % freq.QuadPart) * 1000000u / (uint64_t)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

uint64_t fathom_entropy(void)
{
    uint64_t seed = 0;
#ifdef _WIN32
    HCRYPTPROV prov;
    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(prov, sizeof(seed), (BYTE *)&seed);
        CryptReleaseContext(prov, 0);
    }
    if (seed == 0)
        seed = (uint64_t)time(NULL) ^ ((uint64_t)_getpid() << 32) ^ fathom_now_us();
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) != (ssize_t)sizeof(seed))
            seed = 0;
        close(fd);
    }
    if (seed == 0)
        seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^ fathom_now_us();
#endif
    return seed;
}

const char *fathom_tmpdir(void)
{
    static char buf[1024];
    if (buf[0])
        return buf;
#ifdef _WIN32
    DWORD n = GetTempPathA(sizeof(buf), buf);
    if (n == 0 || n >= sizeof(buf))
        strcpy(buf, ".");
    else if (buf[n - 1] == '\\' || buf[n - 1] == '/')
        buf[n - 1] = '\0';
#else
    const char *t = getenv("TMPDIR");
    size_t len = t ? strlen(t) : 0;
    if (!t || len == 0 || len >= sizeof(buf))
        t = "/tmp", len = 4;
    memcpy(buf, t, len);
    while (len > 1 && buf[len - 1] == '/')
        len--;
    buf[len] = '\0';
#endif
    return buf;
}

#ifdef _WIN32

/* ── Command line ────────────────────────────────────────────────────── */

/* Quote one argument the way CommandLineToArgvW / the CRT parse it back. */
static size_t quote_arg(const char *arg, char *out)
{
    size_t n = 0;
    bool needs = arg[0] == '\0' || strpbrk(arg, " \t\n\v\"") != NULL;

    if (!needs) {
        size_t len = strlen(arg);
        if (out)
            memcpy(out, arg, len);
        return len;
    }

    if (out) out[n] = '"';
    n++;
    for (const char *p = arg;; p++) {
        size_t slashes = 0;
        while (*p == '\\') {
            slashes++;
            p++;
        }
        /* Backslashes are literal unless they precede a quote or the end. */
        size_t reps = *p == '\0' ? slashes * 2 : *p == '"' ? slashes * 2 + 1 : slashes;
        for (size_t i = 0; i < reps; i++) {
            if (out) out[n] = '\\';
            n++;
        }
        if (*p == '\0')
            break;
        if (out) out[n] = *p;
        n++;
    }
    if (out) out[n] = '"';
    n++;
    return n;
}

char *fathom_win_cmdline(char *const *argv)
{
    size_t len = 1;
    for (size_t i = 0; argv[i]; i++)
        len += quote_arg(argv[i], NULL) + 1;

    char *cmd = malloc(len);
    if (!cmd)
        return NULL;
    size_t n = 0;
    for (size_t i = 0; argv[i]; i++) {
        if (i)
            cmd[n++] = ' ';
        n += quote_arg(argv[i], cmd + n);
    }
    cmd[n] = '\0';
    return cmd;
}

#endif /* _WIN32 */
