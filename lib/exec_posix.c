/*
 * exec_posix.c — Debugger backend for Linux and macOS
 *
 * Both platforms fork, call ptrace(TRACEME) and exec the target, which
 * then stops with SIGTRAP before its first instruction.  Signals
 * (breakpoint traps, faults) arrive as ptrace stops through waitpid().
 * The platforms differ in how the debugger touches the stopped target:
 *
 *   Linux  /proc/<pid>/mem for memory, PTRACE_GETREGSET for registers,
 *          AT_ENTRY from /proc/<pid>/auxv for the ASLR slide.  Threads
 *          the target creates are traced too (PTRACE_O_TRACECLONE).
 *   macOS  a Mach task port (task_for_pid) for memory and thread state;
 *          the slide comes from finding the executable's Mach-O header
 *          in the task's address space.  task_for_pid needs the
 *          com.apple.security.cs.debugger entitlement (the Makefile
 *          signs fathom with it) or root.
 *
 * Timeouts: a SIGALRM handler SIGKILLs the target directly, so a hang
 * ends the blocking waitpid() without racing it.
 */

#if !defined(_WIN32)

#include "exec.h"
#include "osdep.h"

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
#include <sys/wait.h>

#if defined(__linux__)
#include <elf.h>
#include <sys/uio.h>
#include <sys/user.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#endif

/* ── Timeout ─────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_timed_out;
static volatile pid_t        g_target_pid;

/*
 * Linux: the handler SIGKILLs the target itself, which ends the blocking
 * waitpid() with no race.  macOS: a SIGKILL that lands while the target
 * is in a ptrace stop leaves it unkillable and unreapable, so the
 * handler only interrupts waitpid() and the loop kills with PT_KILL.
 * The timer repeats so a tick that lands outside waitpid() is not lost.
 */
static void on_alarm(int sig)
{
    (void)sig;
    if (g_target_pid > 0) {
        g_timed_out = 1;
#if defined(__linux__)
        kill(g_target_pid, SIGKILL);
#endif
    }
}

static void arm_timer(pid_t pid, uint32_t ms)
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec  = ms / 1000;
    it.it_value.tv_usec = (ms % 1000) * 1000;
#if defined(__APPLE__)
    it.it_interval.tv_usec = 50 * 1000;
#endif
    g_timed_out = 0;
    g_target_pid = pid;
    setitimer(ITIMER_REAL, &it, NULL);
}

static void disarm_timer(void)
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    setitimer(ITIMER_REAL, &it, NULL);
    g_target_pid = 0;
}

static bool is_crash_signal(int sig)
{
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL ||
           sig == SIGFPE  || sig == SIGABRT || sig == SIGSYS || sig == SIGTRAP;
}

/* ── Platform layer: memory and registers of a stopped target ────────── */

typedef struct {
    pid_t pid;
#if defined(__linux__)
    int   mem_fd;
#elif defined(__APPLE__)
    task_t task;
    size_t page;
#endif
} target_t;

#if defined(__linux__)

typedef struct user_regs_struct regs_t;

static int tgt_attach(target_t *t, pid_t pid)
{
    char path[64];
    t->pid = pid;
    ptrace(PTRACE_SETOPTIONS, pid, NULL,
           (void *)(long)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEEXEC));
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    t->mem_fd = open(path, O_RDWR | O_CLOEXEC);
    if (t->mem_fd < 0) {
        perror("fathom: open /proc/<pid>/mem");
        return -1;
    }
    return 0;
}

static void tgt_detach(target_t *t)
{
    if (t->mem_fd >= 0)
        close(t->mem_fd);
    t->mem_fd = -1;
}

static bool tgt_read(target_t *t, uint64_t addr, void *buf, size_t len)
{
    return pread(t->mem_fd, buf, len, (off_t)addr) == (ssize_t)len;
}

/* /proc/<pid>/mem writes through read-only text mappings for a tracer. */
static bool tgt_write(target_t *t, uint64_t addr, const void *buf, size_t len)
{
    return pwrite(t->mem_fd, buf, len, (off_t)addr) == (ssize_t)len;
}

static bool tgt_get_regs(target_t *t, pid_t tid, regs_t *r)
{
    (void)t;
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

static bool tgt_set_regs(target_t *t, pid_t tid, regs_t *r)
{
    (void)t;
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

#if defined(__x86_64__)
#define REG_PC(r) ((r).rip)
#define REG_FP(r) ((r).rbp)
#else
#define REG_PC(r) ((r).pc)
#define REG_FP(r) ((r).regs[29])
#endif

/* Runtime entry point from the aux vector, giving the ASLR slide. */
static bool tgt_slide(target_t *t, const fathom_exec_t *ex, uint64_t *slide)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/auxv", (int)t->pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    uint64_t pair[2];
    bool found = false;
    while (read(fd, pair, sizeof(pair)) == (ssize_t)sizeof(pair)) {
        if (pair[0] == AT_ENTRY) {
            *slide = pair[1] - ex->entry;
            found = true;
            break;
        }
        if (pair[0] == AT_NULL)
            break;
    }
    close(fd);
    return found;
}

static void tgt_continue(pid_t tid, int sig)
{
    ptrace(PTRACE_CONT, tid, NULL, (void *)(long)sig);
}

static void tgt_kill(pid_t pid)
{
    kill(pid, SIGKILL);
}

#elif defined(__APPLE__)

typedef struct {
    thread_act_t thread;
    uint64_t     pc, fp;
#if defined(__x86_64__)
    x86_thread_state64_t st;
#else
    arm_thread_state64_t st;
#endif
} regs_t;

static int tgt_attach(target_t *t, pid_t pid)
{
    t->pid = pid;
    t->page = (size_t)getpagesize();
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &t->task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr,
                "fathom: task_for_pid failed (%s).  fathom must be signed with "
                "the com.apple.security.cs.debugger entitlement (`make` does "
                "this) or run as root, and the target must not use the "
                "hardened runtime.\n", mach_error_string(kr));
        return -1;
    }
    return 0;
}

static void tgt_detach(target_t *t)
{
    if (t->task != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), t->task);
    t->task = MACH_PORT_NULL;
}

static bool tgt_read(target_t *t, uint64_t addr, void *buf, size_t len)
{
    mach_vm_size_t got = 0;
    return mach_vm_read_overwrite(t->task, addr, len, (mach_vm_address_t)buf,
                                  &got) == KERN_SUCCESS && got == len;
}

/* Code pages are read-only: make a private writable copy, write, restore. */
static bool tgt_write(target_t *t, uint64_t addr, const void *buf, size_t len)
{
    mach_vm_address_t start = addr & ~(uint64_t)(t->page - 1);
    mach_vm_size_t span = ((addr + len + t->page - 1) & ~(uint64_t)(t->page - 1)) - start;

    if (mach_vm_protect(t->task, start, span, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return false;
    kern_return_t kr = mach_vm_write(t->task, addr, (vm_offset_t)buf,
                                     (mach_msg_type_number_t)len);
    mach_vm_protect(t->task, start, span, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    /* The target's instruction cache does not see the write by itself (as debugserver does). */
    vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
    mach_vm_machine_attribute(t->task, addr, len, MATTR_CACHE, &flush);
    return kr == KERN_SUCCESS;
}

static bool thread_regs(thread_act_t th, regs_t *r)
{
    r->thread = th;
#if defined(__x86_64__)
    mach_msg_type_number_t n = x86_THREAD_STATE64_COUNT;
    if (thread_get_state(th, x86_THREAD_STATE64, (thread_state_t)&r->st, &n))
        return false;
    r->pc = r->st.__rip;
    r->fp = r->st.__rbp;
#else
    mach_msg_type_number_t n = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&r->st, &n))
        return false;
    r->pc = arm_thread_state64_get_pc(r->st);
    r->fp = arm_thread_state64_get_fp(r->st);
#endif
    return true;
}

static bool set_pc(regs_t *r, uint64_t pc)
{
#if defined(__x86_64__)
    r->st.__rip = pc;
    return thread_set_state(r->thread, x86_THREAD_STATE64,
                            (thread_state_t)&r->st, x86_THREAD_STATE64_COUNT) == 0;
#else
    arm_thread_state64_set_pc_fptr(r->st, (void *)(uintptr_t)pc);
    return thread_set_state(r->thread, ARM_THREAD_STATE64,
                            (thread_state_t)&r->st, ARM_THREAD_STATE64_COUNT) == 0;
#endif
}

/*
 * The whole task is stopped while we handle a signal; find the thread
 * the trap belongs to.  With want_bp, that is a thread sitting on one of
 * our breakpoints; otherwise the first thread.
 */
static bool find_thread(target_t *t, fathom_exec_t *ex, bool want_bp, regs_t *out)
{
    thread_act_array_t threads;
    mach_msg_type_number_t n = 0;
    bool found = false;

    if (task_threads(t->task, &threads, &n) != KERN_SUCCESS)
        return false;
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        regs_t r;
        if (!found && thread_regs(threads[i], &r) &&
            (!want_bp ||
             exec_bp_lookup(ex, r.pc - ex->os->pc_adjust - ex->os->slide) >= 0)) {
            *out = r;
            found = true;
            continue;   /* keep this thread's port */
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, n * sizeof(*threads));
    return found;
}

static void release_regs(regs_t *r)
{
    mach_port_deallocate(mach_task_self(), r->thread);
}

/* Find the main executable's Mach-O header in the task, giving the slide. */
static bool tgt_slide(target_t *t, const fathom_exec_t *ex, uint64_t *slide)
{
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj;
        if (mach_vm_region(t->task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &count, &obj) != KERN_SUCCESS)
            return false;

        struct mach_header_64 mh;
        if (tgt_read(t, addr, &mh, sizeof(mh)) && mh.magic == MH_MAGIC_64 &&
            mh.filetype == MH_EXECUTE) {
            *slide = addr - ex->image_base;
            return true;
        }
        addr += size;
    }
}

static void tgt_continue(pid_t pid, int sig)
{
    ptrace(PT_CONTINUE, pid, (caddr_t)1, sig);
}

/* A plain SIGKILL leaves a ptrace-stopped process unreapable on macOS. */
static void tgt_kill(pid_t pid)
{
    if (ptrace(PT_KILL, pid, NULL, 0) < 0)
        kill(pid, SIGKILL);
}

#endif

static bool read_word(void *ctx, uint64_t addr, uint64_t *out)
{
    return tgt_read(ctx, addr, out, sizeof(*out));
}

/* ── Backend hooks ───────────────────────────────────────────────────── */

int exec_os_init(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    char path[1100];

    snprintf(path, sizeof(path), "%s/fathom-input-XXXXXX", fathom_tmpdir());
    os->input_fd = mkstemp(path);
    if (os->input_fd < 0) {
        perror("fathom: mkstemp");
        return -1;
    }
    unlink(path);
    fcntl(os->input_fd, F_SETFD, FD_CLOEXEC);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    return 0;
}

void exec_os_destroy(fathom_exec_t *ex)
{
    if (ex->os->input_fd > 0)
        close(ex->os->input_fd);
    ex->os->input_fd = -1;
}

int exec_os_write_input(fathom_exec_t *ex, const uint8_t *data, size_t len)
{
    int fd = ex->os->input_fd;
    if (ftruncate(fd, 0) < 0)
        return -1;
    for (size_t done = 0; done < len;) {
        ssize_t n = pwrite(fd, data + done, len - done, (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static void child_exec(fathom_exec_t *ex)
{
    /* Own process group: Ctrl-C and group signals aimed at fathom miss the target. */
    setpgid(0, 0);

    int fd = ex->os->input_fd;
    if (dup2(fd, STDIN_FILENO) < 0 || lseek(STDIN_FILENO, 0, SEEK_SET) < 0)
        _exit(127);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__)
    rl.rlim_cur = rl.rlim_max = (rlim_t)512 << 20;
    setrlimit(RLIMIT_AS, &rl);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
#else
    ptrace(PT_TRACE_ME, 0, NULL, 0);
#endif
    execv(ex->target_path, ex->target_argv);
    _exit(127);
}

/* Read the launch-time bytes under every breakpoint and write breakpoints in. */
static int insert_breakpoints(fathom_exec_t *ex, target_t *t)
{
    struct fathom_exec_os *os = ex->os;
    if (ex->bp_count == 0)
        return 0;

    uint64_t at = os->lo + os->slide;
    size_t span = (size_t)(os->hi - os->lo);
    if (!tgt_read(t, at, os->orig, span)) {
        fprintf(stderr, "fathom: cannot read target code at 0x%llx\n",
                (unsigned long long)at);
        return -1;
    }
    exec_build_patch(ex);
    if (!tgt_write(t, at, os->patched, span)) {
        fprintf(stderr, "fathom: cannot write breakpoints into the target\n");
        return -1;
    }
    return 0;
}

/* Wait for any stop or exit of the target's threads. */
static pid_t wait_target(pid_t pid, int *status)
{
#if defined(__linux__)
    (void)pid;
    return waitpid(-1, status, __WALL);
#else
    return waitpid(pid, status, 0);
#endif
}

int exec_os_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                fathom_exec_result_t *res)
{
    struct fathom_exec_os *os = ex->os;
    target_t t;
    memset(&t, 0, sizeof(t));
#if defined(__linux__)
    t.mem_fd = -1;
#endif

    pid_t pid = fork();
    if (pid < 0) {
        perror("fathom: fork");
        return -1;
    }
    if (pid == 0)
        child_exec(ex);

    int st = 0;
    pid_t got;
    while ((got = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    if (got < 0) {
        perror("fathom: waitpid (exec stop)");
        return -1;
    }
    if (!WIFSTOPPED(st)) {
        fprintf(stderr, "fathom: target failed to start: %s (status 0x%x)\n",
                ex->target_path, st);
        return -1;
    }

    bool ok = tgt_attach(&t, pid) == 0;
    if (ok && !tgt_slide(&t, ex, &os->slide)) {
        fprintf(stderr, "fathom: cannot find the target image in memory\n");
        ok = false;
    }
    if (!ok || insert_breakpoints(ex, &t) < 0) {
        tgt_kill(pid);
        waitpid(pid, NULL, 0);
        tgt_detach(&t);
        return -1;
    }

    res->status = FATHOM_EXIT_OK;
    bool killed = false;
    arm_timer(pid, ex->timeout_ms);
    tgt_continue(pid, 0);

    for (;;) {
        pid_t tid = wait_target(pid, &st);
        if (tid < 0) {
            if (errno == EINTR) {
#if defined(__APPLE__)
                if (g_timed_out && !killed) {
                    tgt_kill(pid);
                    killed = true;
                }
#endif
                continue;
            }
            perror("fathom: waitpid");
            break;
        }

        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (tid != pid)
                continue;   /* a thread exited */
            if (WIFSIGNALED(st) && res->status == FATHOM_EXIT_OK &&
                is_crash_signal(WTERMSIG(st))) {
                res->status = FATHOM_EXIT_CRASH;
                res->crash_code = (uint32_t)WTERMSIG(st);
                res->crash_hash = fathom_fnv_mix(FATHOM_FNV_OFFSET, res->crash_code);
            }
            break;
        }
        if (!WIFSTOPPED(st))
            continue;

        int sig = WSTOPSIG(st);
#if defined(__linux__)
        if (st >> 16) {               /* clone / exec event stop */
            tgt_continue(tid, 0);
            continue;
        }
        if (sig == SIGSTOP && tid != pid) {   /* new thread's first stop */
            tgt_continue(tid, 0);
            continue;
        }
#endif
        if (res->status == FATHOM_EXIT_CRASH) {
            tgt_continue(tid, 0);     /* already dying from SIGKILL */
            continue;
        }

        if (sig == SIGTRAP) {
            regs_t r;
            const uint8_t *orig;
            size_t len;
#if defined(__linux__)
            bool have = tgt_get_regs(&t, tid, &r);
            uint64_t pc = have ? REG_PC(r) : 0;
#else
            bool have = find_thread(&t, ex, true, &r);
            uint64_t pc = have ? r.pc : 0;
#endif
            uint64_t bp = pc - os->pc_adjust;
            if (have && exec_bp_hit(ex, cov, bp, &orig, &len)) {
                tgt_write(&t, bp, orig, len);
#if defined(__linux__)
                REG_PC(r) = bp;
                tgt_set_regs(&t, tid, &r);
#else
                set_pc(&r, bp);
                release_regs(&r);
#endif
                tgt_continue(tid, 0);
                continue;
            }
#if defined(__APPLE__)
            if (have)
                release_regs(&r);
#endif
        }

        if (is_crash_signal(sig)) {
            regs_t r;
#if defined(__linux__)
            bool have = tgt_get_regs(&t, tid, &r);
            uint64_t pc = have ? REG_PC(r) : 0, fp = have ? REG_FP(r) : 0;
#else
            bool have = find_thread(&t, ex, false, &r);
            uint64_t pc = have ? r.pc : 0, fp = have ? r.fp : 0;
            if (have)
                release_regs(&r);
#endif
            res->status = FATHOM_EXIT_CRASH;
            res->crash_code = (uint32_t)sig;
            res->crash_pc = exec_link_addr(ex, pc);
            res->crash_hash = fathom_fnv_mix(exec_crash_hash(ex, pc, fp, read_word, &t),
                                             (uint64_t)sig);
            /* Kill rather than deliver the signal: no core dump or crash report. */
            tgt_kill(pid);
            killed = true;
            continue;
        }

        tgt_continue(tid, sig);       /* the target's own signal */
    }

    (void)killed;   /* only consulted on macOS */
    disarm_timer();
    if (g_timed_out && res->status != FATHOM_EXIT_CRASH)
        res->status = FATHOM_EXIT_HANG;
    tgt_detach(&t);
    return 0;
}

#endif /* !_WIN32 */
