/*
 * exec.c — Target execution engine
 *
 * Runs the target binary with a mutated input and collects results:
 *   - Fork+exec model: each fathom_exec_run() forks a new child,
 *     writes the input to a temp file, and exec's the target.
 *   - Coverage is collected via the shared-memory bitmap (see coverage.c).
 *   - Crashes are detected by examining wait status for fatal signals
 *     (SIGSEGV, SIGABRT, SIGFPE, SIGBUS, SIGILL).
 *   - Hangs are detected via SIGALRM-based timeout.
 *   - On crash: ptrace GETREGS reads RIP/RSP/RBP and a few stack
 *     frame return addresses to produce a crash-deduplication hash.
 *   - Breakpoint addresses are recorded for future dynamic rotation;
 *     insertion into the child via ptrace POKETEXT is supported when
 *     the executor has an active ptraced child.
 */

#include "exec.h"
#include "coverage.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

/* ── Volatile flag for SIGALRM timeout ──────────────────────────────── */

static volatile sig_atomic_t g_child_timed_out;

static void sigalrm_handler(int sig)
{
    (void)sig;
    g_child_timed_out = 1;
}

/* ── Internal helpers (forward declarations) ────────────────────────── */

static int  write_input_file(const uint8_t *data, size_t len);
static void setup_timeout(uint32_t timeout_ms);
static void cancel_timeout(void);
static uint64_t compute_crash_hash(pid_t pid);
static uint64_t elapsed_us(const struct timeval *start,
                           const struct timeval *end);

/* ── Init / Destroy ─────────────────────────────────────────────────── */

int fathom_exec_init(fathom_exec_t *ex, const fathom_config_t *cfg)
{
    memset(ex, 0, sizeof(*ex));

    ex->target_path     = cfg->target_path;
    ex->target_argv     = cfg->target_argv;
    ex->timeout_ms      = cfg->timeout_ms ? cfg->timeout_ms
                                           : FATHOM_DEFAULT_TIMEOUT_MS;
    ex->fork_server_pid = -1;
    ex->fork_server_up  = false;
    ex->ctl_pipe[0]     = -1;
    ex->ctl_pipe[1]     = -1;
    ex->st_pipe[0]      = -1;
    ex->st_pipe[1]      = -1;

    /* Pre-allocate breakpoint table. */
    ex->bp_capacity = FATHOM_BP_INIT_CAP;
    ex->bp_count    = 0;
    ex->breakpoints = calloc(ex->bp_capacity, sizeof(*ex->breakpoints));
    if (!ex->breakpoints)
        return -1;

    ex->bp_orig_bytes = calloc(ex->bp_capacity, sizeof(*ex->bp_orig_bytes));
    if (!ex->bp_orig_bytes) {
        free(ex->breakpoints);
        ex->breakpoints = NULL;
        return -1;
    }

    /* Install SIGALRM handler (SA_RESTART so reads aren't interrupted
     * unexpectedly, but waitpid will return EINTR). */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* no SA_RESTART: we want waitpid to EINTR */
    sigaction(SIGALRM, &sa, NULL);

    return 0;
}

void fathom_exec_destroy(fathom_exec_t *ex)
{
    /* Tear down fork server if it was ever started. */
    if (ex->fork_server_up && ex->fork_server_pid > 0) {
        kill(ex->fork_server_pid, SIGKILL);
        waitpid(ex->fork_server_pid, NULL, 0);
    }

    if (ex->ctl_pipe[0] >= 0) close(ex->ctl_pipe[0]);
    if (ex->ctl_pipe[1] >= 0) close(ex->ctl_pipe[1]);
    if (ex->st_pipe[0]  >= 0) close(ex->st_pipe[0]);
    if (ex->st_pipe[1]  >= 0) close(ex->st_pipe[1]);

    free(ex->breakpoints);
    free(ex->bp_orig_bytes);

    ex->breakpoints   = NULL;
    ex->bp_orig_bytes = NULL;
    ex->bp_count      = 0;
    ex->bp_capacity   = 0;

    /* Clean up temp input file. */
    unlink(FATHOM_INPUT_FILE);
}

/* ── Execution ──────────────────────────────────────────────────────── */

int fathom_exec_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                    const uint8_t *input, size_t input_len,
                    fathom_exec_result_t *result)
{
    struct timeval tv_start, tv_end;

    memset(result, 0, sizeof(*result));

    /* 1. Write the input to the temp file. */
    if (write_input_file(input, input_len) < 0) {
        result->status = FATHOM_EXIT_ERROR;
        return -1;
    }

    /* 2. Reset the per-exec coverage bitmap. */
    fathom_coverage_reset_local(cov);

    /* 3. Fork and exec the target. */
    gettimeofday(&tv_start, NULL);
    g_child_timed_out = 0;

    pid_t child = fork();
    if (child < 0) {
        perror("fathom: fork");
        result->status = FATHOM_EXIT_ERROR;
        return -1;
    }

    if (child == 0) {
        /* ── Child process ─────────────────────────────────────────── */

        /* Redirect stdin from the input file. */
        int fd = open(FATHOM_INPUT_FILE, O_RDONLY);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }

        /* Suppress stdout/stderr from the target. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* Constrain resource usage. */
        struct rlimit rl;

        /* Cap virtual memory to 512 MB. */
        rl.rlim_cur = rl.rlim_max = (rlim_t)512 << 20;
        setrlimit(RLIMIT_AS, &rl);

        /* Cap file size to 16 MB. */
        rl.rlim_cur = rl.rlim_max = (rlim_t)16 << 20;
        setrlimit(RLIMIT_FSIZE, &rl);

        /* No core dumps. */
        rl.rlim_cur = rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);

        /* Request ptrace (so parent can read regs on crash). */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        /*
         * The shared memory ID is already in the environment
         * (set by fathom_coverage_init), so the target's
         * instrumentation can attach to it.
         */

        /* Exec the target. */
        execv(ex->target_path, ex->target_argv);

        /* If execv returns, it failed. */
        _exit(127);
    }

    /* ── Parent process ────────────────────────────────────────────── */

    /* 4. Wait for the child to stop from PTRACE_TRACEME exec. */
    int wstatus = 0;
    pid_t wp;

    wp = waitpid(child, &wstatus, 0);
    if (wp < 0) {
        perror("fathom: waitpid (traceme stop)");
        result->status = FATHOM_EXIT_ERROR;
        return -1;
    }

    /*
     * After exec with PTRACE_TRACEME the child receives SIGTRAP.
     * If we have breakpoints, insert them now before letting it run.
     */
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
        /* Insert INT3 breakpoints into the child address space. */
        for (size_t i = 0; i < ex->bp_count; i++) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKTEXT, child,
                               (void *)ex->breakpoints[i], NULL);
            if (errno) continue;

            /* Save the original byte. */
            ex->bp_orig_bytes[i] = (uint64_t)word;

            /* Replace the low byte with INT3 (0xCC). */
            long patched = (word & ~0xffL) | 0xcc;
            ptrace(PTRACE_POKETEXT, child,
                   (void *)ex->breakpoints[i], (void *)patched);
        }

        /* Resume the child. */
        ptrace(PTRACE_CONT, child, NULL, NULL);
    } else {
        /* Unexpected: child may have already exited. Handle below. */
        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
            goto child_done;
    }

    /* 5. Arm the timeout alarm. */
    setup_timeout(ex->timeout_ms);

    /* 6. Wait for child completion. */
    for (;;) {
        wp = waitpid(child, &wstatus, 0);
        if (wp < 0) {
            if (errno == EINTR) {
                /* SIGALRM fired — child timed out. */
                if (g_child_timed_out) {
                    kill(child, SIGKILL);
                    waitpid(child, &wstatus, 0);
                    result->status = FATHOM_EXIT_HANG;
                    goto done;
                }
                continue;
            }
            perror("fathom: waitpid");
            result->status = FATHOM_EXIT_ERROR;
            cancel_timeout();
            return -1;
        }

        if (WIFSTOPPED(wstatus)) {
            int sig = WSTOPSIG(wstatus);

            if (sig == SIGTRAP) {
                /*
                 * Breakpoint hit. The child's RIP is one past the
                 * INT3 byte. Find which breakpoint, restore the
                 * original byte, single-step, then re-insert.
                 */
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0) {
                    uint64_t bp_addr = regs.rip - 1;

                    for (size_t i = 0; i < ex->bp_count; i++) {
                        if (ex->breakpoints[i] != bp_addr)
                            continue;

                        /* Restore original byte. */
                        ptrace(PTRACE_POKETEXT, child,
                               (void *)bp_addr,
                               (void *)ex->bp_orig_bytes[i]);

                        /* Rewind RIP to the original instruction. */
                        regs.rip = bp_addr;
                        ptrace(PTRACE_SETREGS, child, NULL, &regs);

                        /* Single-step over the restored instruction. */
                        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                        waitpid(child, &wstatus, 0);

                        /* Re-insert the breakpoint. */
                        errno = 0;
                        long word = ptrace(PTRACE_PEEKTEXT, child,
                                           (void *)bp_addr, NULL);
                        if (!errno) {
                            long patched = (word & ~0xffL) | 0xcc;
                            ptrace(PTRACE_POKETEXT, child,
                                   (void *)bp_addr, (void *)patched);
                        }
                        break;
                    }
                }
                /* Resume after breakpoint handling. */
                ptrace(PTRACE_CONT, child, NULL, NULL);
                continue;
            }

            /*
             * Child stopped by a fatal signal (delivered but caught
             * by ptrace). Read registers for crash hash before
             * letting it die.
             */
            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGFPE ||
                sig == SIGBUS || sig == SIGILL) {
                result->status     = FATHOM_EXIT_CRASH;
                result->signal     = sig;
                result->crash_hash = compute_crash_hash(child);

                /* Let the signal actually kill the child. */
                ptrace(PTRACE_CONT, child, NULL, (void *)(long)sig);
                waitpid(child, &wstatus, 0);
                goto done;
            }

            /* Some other signal — re-deliver and keep going. */
            ptrace(PTRACE_CONT, child, NULL, (void *)(long)sig);
            continue;
        }

        /* Child exited or was signaled (non-stop path). */
        break;
    }

child_done:
    if (WIFSIGNALED(wstatus)) {
        int sig = WTERMSIG(wstatus);
        result->status = FATHOM_EXIT_CRASH;
        result->signal = sig;
        /* Cannot ptrace — child is gone. Hash from signal only. */
        result->crash_hash = FATHOM_FNV_OFFSET;
        result->crash_hash = fathom_fnv_mix(result->crash_hash,
                                            (uint64_t)sig);
    } else if (WIFEXITED(wstatus)) {
        result->status = FATHOM_EXIT_OK;
    } else {
        result->status = FATHOM_EXIT_ERROR;
    }

done:
    cancel_timeout();

    gettimeofday(&tv_end, NULL);
    result->exec_us = elapsed_us(&tv_start, &tv_end);

    return 0;
}

/* ── Breakpoints ────────────────────────────────────────────────────── */

int fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr)
{
    /* Deduplicate. */
    for (size_t i = 0; i < ex->bp_count; i++) {
        if (ex->breakpoints[i] == addr)
            return 0;
    }

    /* Grow table if necessary. */
    if (ex->bp_count >= ex->bp_capacity) {
        size_t new_cap = ex->bp_capacity ? ex->bp_capacity * 2
                                          : FATHOM_BP_INIT_CAP;
        uint64_t *new_bp = realloc(ex->breakpoints,
                                   new_cap * sizeof(*new_bp));
        if (!new_bp) return -1;
        ex->breakpoints = new_bp;

        uint64_t *new_orig = realloc(ex->bp_orig_bytes,
                                     new_cap * sizeof(*new_orig));
        if (!new_orig) return -1;
        ex->bp_orig_bytes = new_orig;

        ex->bp_capacity = new_cap;
    }

    ex->breakpoints[ex->bp_count]   = addr;
    ex->bp_orig_bytes[ex->bp_count] = 0;
    ex->bp_count++;

    return 0;
}

/* ── Internal helpers ───────────────────────────────────────────────── */

/*
 * Write input data to the temp file used as stdin for the target.
 */
static int write_input_file(const uint8_t *data, size_t len)
{
    int fd = open(FATHOM_INPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("fathom: open input file");
        return -1;
    }

    const uint8_t *p   = data;
    size_t         rem = len;

    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("fathom: write input file");
            close(fd);
            return -1;
        }
        p   += (size_t)n;
        rem -= (size_t)n;
    }

    close(fd);
    return 0;
}

/*
 * Arm a real-time alarm for the given timeout.
 */
static void setup_timeout(uint32_t timeout_ms)
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec  = timeout_ms / 1000;
    it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);
}

/*
 * Cancel any pending alarm.
 */
static void cancel_timeout(void)
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    setitimer(ITIMER_REAL, &it, NULL);
}

/*
 * Compute a crash de-duplication hash from the child's register state
 * and a short stack walk.  The child must be stopped (ptraced).
 */
static uint64_t compute_crash_hash(pid_t pid)
{
    uint64_t hash = FATHOM_FNV_OFFSET;

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0)
        return hash;

    /* Mix the crash PC. */
    hash = fathom_fnv_mix(hash, regs.rip);

    /*
     * Walk the frame-pointer chain (RBP-based) to collect return
     * addresses.  This only works for binaries compiled with frame
     * pointers.  We read cautiously and bail on any ptrace error.
     */
    uint64_t fp = regs.rbp;

    for (int depth = 0; depth < FATHOM_STACK_HASH_DEPTH; depth++) {
        if (fp == 0 || (fp & 7) != 0)
            break;

        /* The return address sits at fp+8 in the x86-64 ABI. */
        errno = 0;
        long ret_addr = ptrace(PTRACE_PEEKDATA, pid,
                               (void *)(fp + 8), NULL);
        if (errno)
            break;

        hash = fathom_fnv_mix(hash, (uint64_t)ret_addr);

        /* Follow the saved frame pointer at *fp. */
        errno = 0;
        long next_fp = ptrace(PTRACE_PEEKDATA, pid,
                              (void *)fp, NULL);
        if (errno)
            break;

        /* Detect cycle or backward walk. */
        if ((uint64_t)next_fp <= fp)
            break;

        fp = (uint64_t)next_fp;
    }

    return hash;
}

/*
 * Compute elapsed microseconds between two timevals.
 */
static uint64_t elapsed_us(const struct timeval *start,
                           const struct timeval *end)
{
    int64_t sec  = (int64_t)end->tv_sec  - (int64_t)start->tv_sec;
    int64_t usec = (int64_t)end->tv_usec - (int64_t)start->tv_usec;
    return (uint64_t)(sec * 1000000 + usec);
}
