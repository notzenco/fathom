/*
 * exec_posix.c — Debugger backend for Linux and macOS
 *
 * Both platforms fork, call ptrace(TRACEME) and exec the target, which
 * then stops with SIGTRAP before its first instruction.  Signals
 * (breakpoint traps, faults) arrive as ptrace stops through waitpid().
 * The platforms differ in how the debugger touches the stopped target:
 *
 *   Linux  /proc/<pid>/mem for memory, PTRACE_GETREGSET for registers,
 *          AT_ENTRY from /proc/<pid>/auxv for the ASLR slide.  Threads,
 *          forks and vforks of the target are traced too.  A forked
 *          child gets its original code back and is released, since it
 *          has its own copy of memory that our bookkeeping does not
 *          track; a vfork child shares memory and is handled like a
 *          thread until it execs.
 *   macOS  a Mach task port (task_for_pid) for memory and thread state;
 *          the slide comes from finding the executable's Mach-O header
 *          in the task's address space.  task_for_pid needs the
 *          com.apple.security.cs.debugger entitlement (the Makefile
 *          signs fathom with it) or root.  Breakpoints and faults are
 *          also caught on a Mach exception port (see the exception
 *          server below), which names the faulting thread and, because
 *          forked children inherit exception ports, covers them too.
 *
 * Faults: when the target catches the signal, it is delivered so the
 * handler can recover; the fault still counts as a crash if the target
 * then dies from it, faults again at the same place, or exits non-zero.
 * Otherwise the target is killed at the fault, before any core dump or
 * crash report.
 *
 * Every run ends by killing the target's process group (the target is
 * its own group leader), so no descendant outlives the run.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(__linux__)
#include <elf.h>
#include <sys/uio.h>
#include <sys/user.h>
#elif defined(__APPLE__)
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <sys/event.h>
#include <sys/sysctl.h>
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

/* Same file as the target, as opposed to another program it exec'd. */
static bool same_file(const char *a, const char *b)
{
    struct stat sa, sb;
    return stat(a, &sa) == 0 && stat(b, &sb) == 0 &&
           sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
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

static bool open_mem(pid_t pid, int *fd)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    *fd = open(path, O_RDWR | O_CLOEXEC);
    return *fd >= 0;
}

static int tgt_attach(target_t *t, pid_t pid)
{
    t->pid = pid;
    ptrace(PTRACE_SETOPTIONS, pid, NULL,
           (void *)(long)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                           PTRACE_O_TRACEEXEC));
    if (!open_mem(pid, &t->mem_fd)) {
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

static void to_exec_regs(const regs_t *r, exec_regs_t *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__x86_64__)
    const unsigned long long v[16] = {
        r->rax, r->rcx, r->rdx, r->rbx, r->rsp, r->rbp, r->rsi, r->rdi,
        r->r8, r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15,
    };
    for (int i = 0; i < 16; i++)
        out->r[i] = v[i];
#else
    for (int i = 0; i < 31; i++)
        out->r[i] = r->regs[i];
    out->r[31] = r->sp;
#endif
}

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

static bool tgt_runs_target(target_t *t, const fathom_exec_t *ex)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)t->pid);
    return same_file(path, ex->target_path);
}

static void tgt_continue(pid_t tid, int sig)
{
    ptrace(PTRACE_CONT, tid, NULL, (void *)(long)sig);
}

static void tgt_kill(pid_t pid)
{
    kill(pid, SIGKILL);
}

static bool tgt_catches(target_t *t, int sig)
{
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)t->pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return false;
    unsigned long long mask = 0;
    bool found = false;
    while (!found && fgets(line, sizeof(line), f))
        found = sscanf(line, "SigCgt: %llx", &mask) == 1;
    fclose(f);
    return found && (mask >> (sig - 1)) & 1;
}

/* Stable key for an address inside a file-backed mapping. */
static bool module_key(void *ctx, uint64_t addr, uint64_t *key)
{
    target_t *t = ctx;
    char path[64], line[4200];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)t->pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return false;
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long lo, hi, off;
        int name_at = 0;
        if (sscanf(line, "%llx-%llx %*s %llx %*s %*s %n", &lo, &hi, &off, &name_at) < 3 ||
            addr < lo || addr >= hi)
            continue;
        char *name = line + name_at;
        name[strcspn(name, "\n")] = '\0';
        if (name_at > 0 && name[0] == '/') {
            *key = exec_module_key(name, addr - lo + off);
            found = true;
        }
        break;
    }
    fclose(f);
    return found;
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

#if defined(__x86_64__)
#define STATE_FLAVOR  x86_THREAD_STATE64
#define STATE_COUNT   x86_THREAD_STATE64_COUNT
typedef x86_thread_state64_t state_t;
#define STATE_PC(s)   ((s).__rip)
#define STATE_FP(s)   ((s).__rbp)
#define STATE_SET_PC(s, v) ((s).__rip = (v))
#else
#define STATE_FLAVOR  ARM_THREAD_STATE64
#define STATE_COUNT   ARM_THREAD_STATE64_COUNT
typedef arm_thread_state64_t state_t;
#define STATE_PC(s)   ((uint64_t)arm_thread_state64_get_pc(s))
#define STATE_FP(s)   ((uint64_t)arm_thread_state64_get_fp(s))
#define STATE_SET_PC(s, v) arm_thread_state64_set_pc_fptr((s), (void *)(uintptr_t)(v))
#endif

static void state_regs(const state_t *st, exec_regs_t *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__x86_64__)
    const uint64_t v[16] = {
        st->__rax, st->__rcx, st->__rdx, st->__rbx, st->__rsp, st->__rbp, st->__rsi,
        st->__rdi, st->__r8, st->__r9, st->__r10, st->__r11, st->__r12, st->__r13,
        st->__r14, st->__r15,
    };
    for (int i = 0; i < 16; i++)
        out->r[i] = v[i];
#else
    for (int i = 0; i < 29; i++)
        out->r[i] = st->__x[i];
    out->r[29] = (uint64_t)arm_thread_state64_get_fp(*st);
    out->r[30] = (uint64_t)arm_thread_state64_get_lr(*st);
    out->r[31] = (uint64_t)arm_thread_state64_get_sp(*st);
#endif
}

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

static bool task_read(task_t task, uint64_t addr, void *buf, size_t len)
{
    mach_vm_size_t got = 0;
    return mach_vm_read_overwrite(task, addr, len, (mach_vm_address_t)buf,
                                  &got) == KERN_SUCCESS && got == len;
}

static bool tgt_read(target_t *t, uint64_t addr, void *buf, size_t len)
{
    return task_read(t->task, addr, buf, len);
}

/* Code pages are read-only: make a private writable copy, write, restore. */
static bool task_write(task_t task, uint64_t addr, const void *buf, size_t len)
{
    uint64_t page = (uint64_t)getpagesize();
    mach_vm_address_t start = addr & ~(page - 1);
    mach_vm_size_t span = ((addr + len + page - 1) & ~(page - 1)) - start;

    if (mach_vm_protect(task, start, span, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return false;
    kern_return_t kr = mach_vm_write(task, addr, (vm_offset_t)buf,
                                     (mach_msg_type_number_t)len);
    kern_return_t kp = mach_vm_protect(task, start, span, FALSE,
                                       VM_PROT_READ | VM_PROT_EXECUTE);

    /* The target's instruction cache does not see the write by itself (as debugserver does). */
    vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
    mach_vm_machine_attribute(task, addr, len, MATTR_CACHE, &flush);
    return kr == KERN_SUCCESS && kp == KERN_SUCCESS;
}

static bool tgt_write(target_t *t, uint64_t addr, const void *buf, size_t len)
{
    return task_write(t->task, addr, buf, len);
}

static bool task_rd(void *ctx, uint64_t addr, void *buf, size_t len)
{
    return task_read(*(task_t *)ctx, addr, buf, len);
}

static bool thread_regs(thread_act_t th, regs_t *r)
{
    r->thread = th;
    mach_msg_type_number_t n = STATE_COUNT;
    if (thread_get_state(th, STATE_FLAVOR, (thread_state_t)&r->st, &n))
        return false;
    r->pc = STATE_PC(r->st);
    r->fp = STATE_FP(r->st);
    return true;
}

static bool set_pc(regs_t *r, uint64_t pc)
{
    STATE_SET_PC(r->st, pc);
    return thread_set_state(r->thread, STATE_FLAVOR, (thread_state_t)&r->st,
                            STATE_COUNT) == 0;
}

/*
 * The whole task is stopped while we handle a signal; find the thread
 * the trap belongs to.  With want_bp, that is a thread sitting on one of
 * our breakpoints; otherwise the first thread.  Only a fallback: the
 * exception server normally names the thread.
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
             exec_is_ours(ex, r.pc - ex->os->pc_adjust - ex->os->slide))) {
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

static bool tgt_runs_target(target_t *t, const fathom_exec_t *ex)
{
    char path[PROC_PIDPATHINFO_MAXSIZE];
    return proc_pidpath(t->pid, path, sizeof(path)) > 0 &&
           same_file(path, ex->target_path);
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

static bool tgt_catches(target_t *t, int sig)
{
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, t->pid };
    if (sysctl(mib, 4, &kp, &len, NULL, 0) < 0 || len == 0)
        return false;
    return (kp.kp_proc.p_sigcatch & sigmask(sig)) != 0;
}

/* Stable key for an address inside a file-backed region. */
static bool module_key(void *ctx, uint64_t addr, uint64_t *key)
{
    target_t *t = ctx;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_regionfilename(t->pid, addr, path, sizeof(path)) <= 0)
        return false;

    mach_vm_address_t start = addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj;
    if (mach_vm_region(t->task, &start, &size, VM_REGION_BASIC_INFO_64,
                       (vm_region_info_t)&info, &count, &obj) != KERN_SUCCESS ||
        start > addr)
        return false;
    *key = exec_module_key(path, addr - start);
    return true;
}

/* ── macOS exception server ──────────────────────────────────────────── */

/*
 * A task exception port receives breakpoint and fault exceptions before
 * they turn into signals.  Breakpoints are handled right here, in
 * whichever task raised them: the target, or a forked child that
 * inherited both its code and its exception ports.  Faults in the
 * target are only recorded, with the thread that raised them, and then
 * passed on so the usual signal stop follows.
 *
 * The messages are mach_exception_raise_state_identity (mach_exc.defs),
 * laid out by hand instead of through MIG-generated code.
 */
#define EXC_RAISE_STATE_IDENTITY  2407   /* mach_exc subsystem base 2405 + 2 */
#define EXC_MASK_FATHOM  (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | \
                          EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC)

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t          head;
    mach_msg_body_t            body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t               ndr;
    exception_type_t           exception;
    mach_msg_type_number_t     code_count;
    int64_t                    code[2];
    int                        flavor;
    mach_msg_type_number_t     state_count;
    natural_t                  state[THREAD_STATE_MAX];
    mach_msg_trailer_t         trailer;
} exc_request_t;

typedef struct {
    mach_msg_header_t          head;
    NDR_record_t               ndr;
    kern_return_t              ret;
    int                        flavor;
    mach_msg_type_number_t     state_count;
    natural_t                  state[THREAD_STATE_MAX];
} exc_reply_t;
#pragma pack(pop)

static struct {
    pthread_once_t     once;
    bool               ready;
    mach_port_t        port;
    pthread_mutex_t    lock;
    /* The run in progress; ex is NULL between runs. */
    fathom_exec_t     *ex;
    fathom_coverage_t *cov;
    task_t             root;
    bool               failed;      /* a breakpoint could not be restored */
    /* Last fault in the target, consumed by the next crash signal stop. */
    bool               fault_set;
    exception_type_t   fault_exc;
    uint64_t           fault_pc, fault_fp;
} g_exc = { .once = PTHREAD_ONCE_INIT, .lock = PTHREAD_MUTEX_INITIALIZER };

static kern_return_t exc_handle(const exc_request_t *rq, exc_reply_t *rp)
{
    if (rq->flavor != STATE_FLAVOR || rq->state_count < STATE_COUNT)
        return KERN_FAILURE;
    state_t st;
    memcpy(&st, rq->state, sizeof(st));
    task_t task = rq->task.name;
    kern_return_t ret = KERN_FAILURE;

    pthread_mutex_lock(&g_exc.lock);
    fathom_exec_t *ex = g_exc.ex;
    if (ex) {
        exec_write_t w[2];
        uint32_t probe;
        uint64_t bp = STATE_PC(st) - ex->os->pc_adjust;
        size_t nw = rq->exception == EXC_BREAKPOINT
                  ? exec_bp_hit(ex, g_exc.cov, bp, w, &probe) : 0;
        if (nw && probe != UINT32_MAX) {
            exec_regs_t regs;
            state_regs(&st, &regs);
            exec_probe_log(ex, probe, &regs, task_rd, &task);
        }
        if (nw) {
            bool ok = true;
            for (size_t i = 0; i < nw; i++)
                ok = ok && task_write(task, w[i].addr, w[i].bytes, w[i].len);
            if (ok) {
                STATE_SET_PC(st, bp);
                ret = KERN_SUCCESS;
            } else {
                g_exc.failed = true;
            }
        } else if (task == g_exc.root) {
            g_exc.fault_set = true;
            g_exc.fault_exc = rq->exception;
            g_exc.fault_pc = STATE_PC(st);
            g_exc.fault_fp = STATE_FP(st);
        }
    }
    pthread_mutex_unlock(&g_exc.lock);

    memcpy(rp->state, &st, sizeof(st));
    rp->state_count = STATE_COUNT;
    rp->flavor = STATE_FLAVOR;
    return ret;
}

static void *exc_server(void *arg)
{
    (void)arg;
    /* SIGALRM must interrupt the main thread's waitpid(), not this mach_msg(). */
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    exc_request_t *rq = malloc(sizeof(*rq));
    exc_reply_t *rp = malloc(sizeof(*rp));
    if (!rq || !rp)
        return NULL;

    for (;;) {
        memset(rq, 0, sizeof(*rq));
        rq->head.msgh_size = sizeof(*rq);
        rq->head.msgh_local_port = g_exc.port;
        if (mach_msg(&rq->head, MACH_RCV_MSG, 0, sizeof(*rq),
                     g_exc.port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
            continue;

        memset(rp, 0, sizeof(*rp));
        kern_return_t ret = KERN_FAILURE;
        if (rq->head.msgh_id == EXC_RAISE_STATE_IDENTITY &&
            (rq->head.msgh_bits & MACH_MSGH_BITS_COMPLEX) && rq->body.msgh_descriptor_count == 2)
            ret = exc_handle(rq, rp);

        rp->head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(rq->head.msgh_bits), 0);
        rp->head.msgh_remote_port = rq->head.msgh_remote_port;
        rp->head.msgh_local_port = MACH_PORT_NULL;
        rp->head.msgh_id = rq->head.msgh_id + 100;
        rp->ndr = NDR_record;
        rp->ret = ret;
        rp->head.msgh_size = (mach_msg_size_t)(offsetof(exc_reply_t, state) +
                                               rp->state_count * sizeof(natural_t));
        /* The faulting task may already be dead; a failed reply is harmless. */
        mach_msg(&rp->head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, rp->head.msgh_size, 0,
                 MACH_PORT_NULL, 100, MACH_PORT_NULL);

        if (rq->head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            mach_port_deallocate(mach_task_self(), rq->thread.name);
            mach_port_deallocate(mach_task_self(), rq->task.name);
        }
    }
    return NULL;
}

static void exc_start(void)
{
    mach_port_t port;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
        return;
    if (mach_port_insert_right(mach_task_self(), port, port,
                               MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS)
        return;
    g_exc.port = port;

    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    g_exc.ready = pthread_create(&th, &attr, exc_server, NULL) == 0;
    pthread_attr_destroy(&attr);
}

/* Route the stopped target's exceptions to the server for this run. */
static void exc_begin(target_t *t, fathom_exec_t *ex, fathom_coverage_t *cov)
{
    pthread_once(&g_exc.once, exc_start);
    if (!g_exc.ready)
        return;
    pthread_mutex_lock(&g_exc.lock);
    g_exc.ex = ex;
    g_exc.cov = cov;
    g_exc.root = t->task;
    g_exc.failed = false;
    g_exc.fault_set = false;
    pthread_mutex_unlock(&g_exc.lock);
    task_set_exception_ports(t->task, EXC_MASK_FATHOM, g_exc.port,
                             (exception_behavior_t)(EXCEPTION_STATE_IDENTITY |
                                                    MACH_EXCEPTION_CODES),
                             STATE_FLAVOR);
}

static bool exc_end(void)
{
    pthread_mutex_lock(&g_exc.lock);
    bool failed = g_exc.failed;
    g_exc.ex = NULL;
    g_exc.cov = NULL;
    g_exc.root = MACH_PORT_NULL;
    pthread_mutex_unlock(&g_exc.lock);
    return failed;
}

static bool exc_failed(void)
{
    pthread_mutex_lock(&g_exc.lock);
    bool failed = g_exc.failed;
    pthread_mutex_unlock(&g_exc.lock);
    return failed;
}

/* The fault behind signal sig, recorded by the server, if there is one. */
static bool exc_take_fault(int sig, uint64_t *pc, uint64_t *fp)
{
    pthread_mutex_lock(&g_exc.lock);
    exception_type_t e = g_exc.fault_exc;
    bool match = g_exc.fault_set &&
                 ((e == EXC_BAD_ACCESS && (sig == SIGSEGV || sig == SIGBUS)) ||
                  (e == EXC_BAD_INSTRUCTION && sig == SIGILL) ||
                  (e == EXC_ARITHMETIC && sig == SIGFPE) ||
                  (e == EXC_BREAKPOINT && sig == SIGTRAP));
    if (match) {
        *pc = g_exc.fault_pc;
        *fp = g_exc.fault_fp;
    }
    g_exc.fault_set = false;
    pthread_mutex_unlock(&g_exc.lock);
    return match;
}

#endif

static bool read_word(void *ctx, uint64_t addr, uint64_t *out)
{
    return tgt_read(ctx, addr, out, sizeof(*out));
}

static bool rd_mem(void *ctx, uint64_t addr, void *buf, size_t len)
{
    return tgt_read(ctx, addr, buf, len);
}

static bool wr_mem(void *ctx, uint64_t addr, const void *buf, size_t len)
{
    return tgt_write(ctx, addr, buf, len);
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
    if (os->input_by_path)
        snprintf(os->input_path, sizeof(os->input_path), "%s", path);
    else
        unlink(path);
    fcntl(os->input_fd, F_SETFD, FD_CLOEXEC);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    return 0;
}

#if defined(__linux__)
static void fs_stop(struct fathom_exec_os *os);
#endif

void exec_os_destroy(fathom_exec_t *ex)
{
#if defined(__linux__)
    fs_stop(ex->os);
#endif
    if (ex->os->input_fd > 0)
        close(ex->os->input_fd);
    ex->os->input_fd = -1;
    if (ex->os->input_path[0])
        unlink(ex->os->input_path);
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

    int fd = ex->os->input_by_path ? open("/dev/null", O_RDONLY) : ex->os->input_fd;
    if (fd < 0 || dup2(fd, STDIN_FILENO) < 0 || lseek(STDIN_FILENO, 0, SEEK_SET) < 0)
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

/* ── Fault bookkeeping ───────────────────────────────────────────────── */

typedef struct {
    bool     set;
    int      sig;
    uint64_t pc;           /* runtime PC of the fault */
    uint64_t link_pc;
    uint64_t hash;
} fault_t;

static void record_fault(fathom_exec_t *ex, target_t *t, int sig, uint64_t pc,
                         uint64_t fp, fault_t *f)
{
    f->set = true;
    f->sig = sig;
    f->pc = pc;
    f->link_pc = exec_link_addr(ex, pc);
    f->hash = fathom_fnv_mix(exec_crash_hash(ex, pc, fp, read_word, module_key, t),
                             (uint64_t)sig);
}

static void report_crash(fathom_exec_result_t *res, const fault_t *f)
{
    res->status = FATHOM_EXIT_CRASH;
    res->crash_code = (uint32_t)f->sig;
    res->crash_pc = f->link_pc;
    res->crash_hash = f->hash;
}

/* ── Descendants (Linux) ─────────────────────────────────────────────── */

#if defined(__linux__)

enum { KID_UNKNOWN, KID_THREAD, KID_FORK, KID_VFORK };

#define MAX_KIDS 256

typedef struct {
    pid_t pid;
    int   kind;
    bool  stopped;     /* first stop seen, waiting to learn the kind */
    bool  started;
} kid_t;

typedef struct {
    kid_t  k[MAX_KIDS];
    size_t n;
} kids_t;

static kid_t *kid_get(kids_t *ks, pid_t pid, bool add)
{
    for (size_t i = 0; i < ks->n; i++) {
        if (ks->k[i].pid == pid)
            return &ks->k[i];
    }
    if (!add || ks->n == MAX_KIDS)
        return NULL;
    kid_t *k = &ks->k[ks->n++];
    memset(k, 0, sizeof(*k));
    k->pid = pid;
    return k;
}

static void kid_drop(kids_t *ks, pid_t pid)
{
    for (size_t i = 0; i < ks->n; i++) {
        if (ks->k[i].pid == pid) {
            ks->k[i] = ks->k[--ks->n];
            return;
        }
    }
}

/*
 * Let a new task run once both its first stop and its kind are known.
 * A fork has its own copy of the patched code, which nothing here would
 * restore, so it gets the original bytes back and is released.
 */
static void kid_start(fathom_exec_t *ex, kids_t *ks, kid_t *k)
{
    if (k->kind != KID_FORK) {
        k->started = true;
        tgt_continue(k->pid, 0);
        return;
    }
    const struct fathom_exec_os *os = ex->os;
    int fd;
    if (os->patch_ready && open_mem(k->pid, &fd)) {
        for (size_t i = 0; i < os->n_clusters; i++) {
            const struct exec_cluster *c = &os->clusters[i];
            if (pwrite(fd, os->orig + c->off, (size_t)(c->hi - c->lo),
                       (off_t)(c->lo + os->slide)) < 0)
                break;
        }
        close(fd);
    }
    ptrace(PTRACE_DETACH, k->pid, NULL, NULL);
    kid_drop(ks, k->pid);
}

static void kid_event(fathom_exec_t *ex, kids_t *ks, pid_t tid, int event)
{
    unsigned long msg = 0;
    ptrace(PTRACE_GETEVENTMSG, tid, NULL, &msg);
    kid_t *k = kid_get(ks, (pid_t)msg, true);
    if (!k)
        return;
    k->kind = event == PTRACE_EVENT_FORK  ? KID_FORK
            : event == PTRACE_EVENT_VFORK ? KID_VFORK : KID_THREAD;
    if (k->stopped && !k->started)
        kid_start(ex, ks, k);
}

/* Returns true if the stop was a new task's first stop and is handled. */
static bool kid_first_stop(fathom_exec_t *ex, kids_t *ks, pid_t tid, int sig)
{
    kid_t *k = kid_get(ks, tid, false);
    if (sig != SIGSTOP || (k && k->started))
        return false;
    if (!k && !(k = kid_get(ks, tid, true))) {
        tgt_continue(tid, 0);   /* table full: run it untracked */
        return true;
    }
    k->stopped = true;
    if (k->kind != KID_UNKNOWN)
        kid_start(ex, ks, k);
    return true;
}

/* Kill and reap every task still traced, so no stale stop reaches the next run. */
static void kids_reap(kids_t *ks)
{
    for (size_t i = 0; i < ks->n; i++) {
        if (ks->k[i].kind == KID_THREAD)
            continue;   /* died with the target */
        kill(ks->k[i].pid, SIGKILL);
        while (waitpid(ks->k[i].pid, NULL, __WALL) < 0 && errno == EINTR)
            ;
    }
    ks->n = 0;
}

#endif

/* ── Fork server (Linux) ─────────────────────────────────────────────── */

#if defined(__linux__)

/*
 * The template is the target stopped at its entry point, after the
 * dynamic loader ran.  Each run injects a fork into it: the child starts
 * from the entry point with the template's registers, memory (patched
 * with breakpoints) and file descriptors, so execve and dynamic linking
 * happen once.  The template's stdin shares its file offset with our
 * input descriptor, which is rewound before each fork.  A finished child
 * is reaped by an injected wait4, since the template is its parent.
 *
 * Code is injected at the entry point: a system call, then a trap.
 */
#if defined(__x86_64__)
static const uint8_t fs_stub[8] = { 0x0f, 0x05, 0xcc };   /* syscall; int3 */
#define FS_STUB_LEN  3
#define FS_NR_FORK   57
#define FS_NR_WAIT4  61
#else
static const uint8_t fs_stub[8] = { 0x01, 0x00, 0x00, 0xd4,    /* svc #0 */
                                    0x00, 0x00, 0x20, 0xd4 };  /* brk #0 */
#define FS_STUB_LEN  8
#define FS_NR_CLONE  220
#define FS_NR_WAIT4  260
#endif

static void fs_set_call(regs_t *r, uint64_t pc, long nr, const uint64_t a[4])
{
#if defined(__x86_64__)
    r->rip = pc;
    r->rax = (unsigned long long)nr;
    r->orig_rax = (unsigned long long)-1;   /* not inside a syscall: no restart */
    r->rdi = a[0];
    r->rsi = a[1];
    r->rdx = a[2];
    r->r10 = a[3];
#else
    r->pc = pc;
    r->regs[8] = (unsigned long long)nr;
    for (int i = 0; i < 4; i++)
        r->regs[i] = a[i];
    r->regs[4] = 0;
#endif
}

static long fs_result(const regs_t *r)
{
#if defined(__x86_64__)
    return (long)r->rax;
#else
    return (long)r->regs[0];
#endif
}

/* Wait for the template's next stop, swallowing signals sent to it. */
static int fs_wait(pid_t pid, int *st)
{
    for (;;) {
        pid_t got = waitpid(pid, st, __WALL);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0 || !WIFSTOPPED(*st))
            return -1;
        int event = *st >> 16;
        if (event || WSTOPSIG(*st) == SIGTRAP)
            return 0;
        tgt_continue(pid, 0);   /* e.g. SIGCHLD from a finished child */
    }
}

/*
 * Run system call nr in the template and return its result.  For a fork,
 * *child gets the new process, stopped at its first instruction.
 */
static long fs_inject(struct fathom_exec_os *os, long nr, const uint64_t a[4], pid_t *child,
                      uint8_t saved[FS_STUB_LEN])
{
    pid_t pid = os->fs_pid;
    regs_t r, entry;
    memcpy(&entry, os->fs_regs, sizeof(entry));
    if (pread(os->fs_mem, saved, FS_STUB_LEN, (off_t)os->fs_entry) != FS_STUB_LEN ||
        pwrite(os->fs_mem, fs_stub, FS_STUB_LEN, (off_t)os->fs_entry) != FS_STUB_LEN)
        return -1;
    r = entry;
    fs_set_call(&r, os->fs_entry, nr, a);
    long rc = -1;
    int st;
    target_t t = { pid, os->fs_mem };
    if (!tgt_set_regs(&t, pid, &r))
        goto restore;
    tgt_continue(pid, 0);
    if (fs_wait(pid, &st) < 0)
        goto restore;
    if (child && (st >> 16) != 0) {
        unsigned long msg = 0;
        ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg);
        *child = (pid_t)msg;
        tgt_continue(pid, 0);
        if (fs_wait(pid, &st) < 0)
            goto restore;
    }
    if (tgt_get_regs(&t, pid, &r))
        rc = fs_result(&r);
restore:
    if (pwrite(os->fs_mem, saved, FS_STUB_LEN, (off_t)os->fs_entry) != FS_STUB_LEN ||
        !tgt_set_regs(&t, pid, &entry))
        rc = -1;
    return rc;
}

static void fs_stop(struct fathom_exec_os *os)
{
    if (os->fs_pid > 0) {
        kill(os->fs_pid, SIGKILL);
        while (waitpid(os->fs_pid, NULL, __WALL) < 0 && errno == EINTR)
            ;
    }
    if (os->fs_mem >= 0)
        close(os->fs_mem);
    os->fs_pid = 0;
    os->fs_mem = -1;
}

/* Start the target and stop it at its entry point as the template. */
static int fs_start(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
        child_exec(ex);
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    target_t t = { pid, -1 };
    os->fs_pid = pid;
    if (!WIFSTOPPED(st) || tgt_attach(&t, pid) < 0)
        return -1;
    os->fs_mem = t.mem_fd;
    if (!tgt_slide(&t, ex, &os->slide))
        return -1;

    /* Run the loader up to the entry point. */
    os->fs_entry = ex->entry + os->slide;
    uint8_t saved[4];
    if (!tgt_read(&t, os->fs_entry, saved, os->bp_len) ||
        !tgt_write(&t, os->fs_entry, os->bp_insn, os->bp_len))
        return -1;
    tgt_continue(pid, 0);
    if (fs_wait(pid, &st) < 0 || (st >> 16) != 0)
        return -1;
    regs_t r;
    if (!tgt_write(&t, os->fs_entry, saved, os->bp_len) || !tgt_get_regs(&t, pid, &r))
        return -1;
    REG_PC(r) = os->fs_entry;
    if (!tgt_set_regs(&t, pid, &r))
        return -1;
    memcpy(os->fs_regs, &r, sizeof(r));
    os->fs_patch_gen = 0;
    return 0;
}

/* Fork a child from the template, ready to run from the entry point. */
static pid_t fs_spawn(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    if (!os->fs_pid && fs_start(ex) < 0) {
        fs_stop(os);
        return -1;
    }
    target_t t = { os->fs_pid, os->fs_mem };
    if (exec_insert_breakpoints(ex, rd_mem, wr_mem, &t) < 0)
        return -1;
    if (!ex->os->input_by_path && lseek(os->input_fd, 0, SEEK_SET) < 0)
        return -1;

    pid_t child = 0;
#if defined(__x86_64__)
    const uint64_t args[4] = { 0, 0, 0, 0 };
    uint8_t saved[FS_STUB_LEN];
    long rc = fs_inject(os, FS_NR_FORK, args, &child, saved);
#else
    const uint64_t args[4] = { SIGCHLD, 0, 0, 0 };
    uint8_t saved[FS_STUB_LEN];
    long rc = fs_inject(os, FS_NR_CLONE, args, &child, saved);
#endif
    if (rc <= 0 || child <= 0)
        return -1;

    /* Its first stop, then the entry state: registers and the code under the stub. */
    int st;
    while (waitpid(child, &st, __WALL) < 0 && errno == EINTR)
        ;
    regs_t r;
    memcpy(&r, os->fs_regs, sizeof(r));
    target_t c = { child, -1 };
    /* It was forked with the stub at the entry point: put the code back. */
    bool ok = WIFSTOPPED(st) && open_mem(child, &c.mem_fd) &&
              tgt_write(&c, os->fs_entry, saved, FS_STUB_LEN) &&
              tgt_set_regs(&c, child, &r);
    if (c.mem_fd >= 0)
        close(c.mem_fd);
    if (!ok) {
        kill(child, SIGKILL);
        return -1;
    }
    return child;
}

/* Reap a finished child: its parent is the template. */
static void fs_reap(struct fathom_exec_os *os, pid_t child)
{
    const uint64_t args[4] = { (uint64_t)child, 0, __WALL, 0 };
    uint8_t saved[FS_STUB_LEN];
    fs_inject(os, FS_NR_WAIT4, args, NULL, saved);
}

#endif

/* ── Run ─────────────────────────────────────────────────────────────── */

/*
 * The target exec'd: instrument the new image if it is the target again,
 * otherwise run it uninstrumented.
 */
static int on_root_exec(fathom_exec_t *ex, target_t *t)
{
    struct fathom_exec_os *os = ex->os;
    pid_t pid = t->pid;
    tgt_detach(t);
    if (tgt_attach(t, pid) < 0)
        return -1;
    if (!tgt_runs_target(t, ex) || !tgt_slide(t, ex, &os->slide)) {
        os->foreign_image = true;
        return 0;
    }
    os->foreign_image = false;
    return exec_insert_breakpoints(ex, rd_mem, wr_mem, t);
}

int exec_os_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                fathom_exec_result_t *res)
{
    struct fathom_exec_os *os = ex->os;
    target_t t;
    memset(&t, 0, sizeof(t));
#if defined(__linux__)
    t.mem_fd = -1;
    kids_t kids;
    kids.n = 0;
#endif
    os->foreign_image = false;
    int st = 0;
    pid_t pid = 0;
    bool forked = false;   /* from the fork server: already patched, own process group */
    bool ok;

#if defined(__linux__)
    if (os->fs_wanted && !os->fs_failed) {
        pid = fs_spawn(ex);
        if (pid > 0) {
            forked = true;
        } else {
            fprintf(stderr, "fathom: fork server unavailable; starting the target "
                            "for every run\n");
            os->fs_failed = true;
            fs_stop(os);
        }
    }
#endif
    if (forked) {
        t.pid = pid;
#if defined(__linux__)
        ok = open_mem(pid, &t.mem_fd);
#else
        ok = false;
#endif
    } else {
        pid = fork();
        if (pid < 0) {
            perror("fathom: fork");
            return -1;
        }
        if (pid == 0)
            child_exec(ex);

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

        ok = tgt_attach(&t, pid) == 0;
        if (ok && !tgt_slide(&t, ex, &os->slide)) {
            fprintf(stderr, "fathom: cannot find the target image in memory\n");
            ok = false;
        }
    }
#if defined(__APPLE__)
    int kq = -1;
    if (ok) {
        exc_begin(&t, ex, cov);
        /* NOTE_EXEC tells a later exec's SIGTRAP apart from a trap. */
        kq = kqueue();
        struct kevent kev;
        EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXEC, 0, NULL);
        if (kq >= 0)
            kevent(kq, &kev, 1, NULL, 0, NULL);
    }
#endif
    if (!ok || (!forked && exec_insert_breakpoints(ex, rd_mem, wr_mem, &t) < 0)) {
        tgt_kill(pid);
        waitpid(pid, NULL, 0);
#if defined(__APPLE__)
        exc_end();
        if (kq >= 0)
            close(kq);
#endif
        tgt_detach(&t);
        return -1;
    }

    res->status = FATHOM_EXIT_OK;
    fault_t pending = { 0 };
    bool killed = false, escalated = false, abandoned = false, failed = false;
    uint64_t killed_at = 0;
    arm_timer(pid, ex->timeout_ms);
    tgt_continue(pid, 0);

    for (;;) {
        pid_t tid = wait_target(pid, &st);
        if (tid < 0) {
            if (errno == EINTR) {
#if defined(__APPLE__)
                uint64_t now = fathom_now_us();
                if (g_timed_out && !killed) {
                    tgt_kill(pid);
                    killed = true;
                }
                if (killed && killed_at == 0)
                    killed_at = now;
                /*
                 * A target can occasionally survive PT_KILL (seen only on CI
                 * runners).  Escalate, then give up on it rather than hang
                 * the whole fuzzer on one run.
                 */
                if (killed && !escalated && now - killed_at > 2000000) {
                    kill(pid, SIGKILL);
                    ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
                    escalated = true;
                }
                if (killed && now - killed_at > 5000000) {
                    fprintf(stderr, "fathom: target %d did not exit after being "
                                    "killed; abandoning it\n", (int)pid);
                    abandoned = true;
                    break;
                }
#endif
                continue;
            }
            perror("fathom: waitpid");
            break;
        }

        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (tid != pid) {
#if defined(__linux__)
                kid_drop(&kids, tid);
#endif
                continue;   /* a thread or traced child exited */
            }
            if (res->status == FATHOM_EXIT_OK && !g_timed_out) {
                if (WIFSIGNALED(st) && is_crash_signal(WTERMSIG(st))) {
                    int sig = WTERMSIG(st);
                    if (pending.set && pending.sig == sig) {
                        report_crash(res, &pending);
                    } else {
                        fault_t f = { true, sig, 0, 0,
                                      fathom_fnv_mix(FATHOM_FNV_OFFSET, (uint64_t)sig) };
                        report_crash(res, &f);
                    }
                } else if (WIFEXITED(st) && WEXITSTATUS(st) != 0 && pending.set) {
                    report_crash(res, &pending);   /* a fault handler bailed out */
                }
            }
            break;
        }
        if (!WIFSTOPPED(st))
            continue;

        int sig = WSTOPSIG(st);
#if defined(__linux__)
        int event = st >> 16;
        if (event) {
            if (event == PTRACE_EVENT_EXEC && tid == pid && !killed) {
                if (on_root_exec(ex, &t) < 0)
                    failed = true;
            } else if (event == PTRACE_EVENT_EXEC) {
                ptrace(PTRACE_DETACH, tid, NULL, NULL);   /* a vfork child's new program */
                kid_drop(&kids, tid);
                continue;
            } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                       event == PTRACE_EVENT_CLONE) {
                kid_event(ex, &kids, tid, event);
            }
            if (failed) {
                tgt_kill(pid);
                killed = true;
            }
            tgt_continue(tid, 0);
            continue;
        }
        if (tid != pid && kid_first_stop(ex, &kids, tid, sig))
            continue;
#endif
        if (res->status == FATHOM_EXIT_CRASH || failed) {
            tgt_continue(tid, 0);     /* already dying from SIGKILL */
            continue;
        }

#if defined(__APPLE__)
        if (exc_failed()) {
            fprintf(stderr, "fathom: cannot restore code under a breakpoint\n");
            failed = true;
            tgt_kill(pid);
            killed = true;
            continue;
        }
        if (sig == SIGTRAP && kq >= 0) {
            struct kevent kev;
            struct timespec zero = { 0, 0 };
            if (kevent(kq, NULL, 0, &kev, 1, &zero) == 1 && (kev.fflags & NOTE_EXEC)) {
                if (on_root_exec(ex, &t) < 0) {
                    failed = true;
                    tgt_kill(pid);
                    killed = true;
                    continue;
                }
                exc_begin(&t, ex, cov);
                tgt_continue(pid, 0);
                continue;
            }
        }
#endif

        if (sig == SIGTRAP) {
            regs_t r;
            exec_write_t w[2];
            size_t nw = 0;
#if defined(__linux__)
            bool have = tgt_get_regs(&t, tid, &r);
            uint64_t pc = have ? REG_PC(r) : 0;
#else
            bool have = find_thread(&t, ex, true, &r);
            uint64_t pc = have ? r.pc : 0;
#endif
            uint64_t bp = pc - os->pc_adjust;
            uint32_t probe = UINT32_MAX;
            if (have && (nw = exec_bp_hit(ex, cov, bp, w, &probe)) > 0) {
                if (probe != UINT32_MAX) {
                    exec_regs_t regs;
#if defined(__linux__)
                    to_exec_regs(&r, &regs);
#else
                    state_regs(&r.st, &regs);
#endif
                    exec_probe_log(ex, probe, &regs, rd_mem, &t);
                }
                bool restored = true;
                for (size_t i = 0; i < nw; i++)
                    restored = restored && tgt_write(&t, w[i].addr, w[i].bytes, w[i].len);
#if defined(__linux__)
                REG_PC(r) = bp;
                restored = restored && tgt_set_regs(&t, tid, &r);
#else
                restored = restored && set_pc(&r, bp);
                release_regs(&r);
#endif
                if (!restored) {
                    fprintf(stderr, "fathom: cannot restore code under the "
                                    "breakpoint at 0x%llx\n", (unsigned long long)bp);
                    failed = true;
                    tgt_kill(pid);
                    killed = true;
                    continue;
                }
                tgt_continue(tid, 0);
                continue;
            }
#if defined(__APPLE__)
            if (have)
                release_regs(&r);
#endif
        }

        if (is_crash_signal(sig)) {
            uint64_t pc = 0, fp = 0;
#if defined(__linux__)
            regs_t r;
            if (tgt_get_regs(&t, tid, &r)) {
                pc = REG_PC(r);
                fp = REG_FP(r);
            }
#else
            if (!exc_take_fault(sig, &pc, &fp)) {
                regs_t r;
                if (find_thread(&t, ex, false, &r)) {
                    pc = r.pc;
                    fp = r.fp;
                    release_regs(&r);
                }
            }
#endif
            /*
             * Let the target's own handler try to recover, unless the same
             * fault just came back, which means the handler did not fix it.
             */
            bool repeat = pending.set && pending.sig == sig && pending.pc == pc;
            fault_t f;
            record_fault(ex, &t, sig, pc, fp, &f);
            if (!repeat && tgt_catches(&t, sig)) {
                pending = f;
                tgt_continue(tid, sig);
                continue;
            }

            report_crash(res, &f);
            /* Kill rather than deliver the signal: no core dump or crash report. */
            tgt_kill(pid);
            killed = true;
            killed_at = fathom_now_us();
            continue;
        }

        tgt_continue(tid, sig);       /* the target's own signal */
    }

    /* Only consulted on macOS. */
    (void)escalated;
    (void)killed_at;
    disarm_timer();
#if defined(__APPLE__)
    failed |= exc_end();
    if (kq >= 0)
        close(kq);
    if (abandoned) {
        if (res->status != FATHOM_EXIT_CRASH)
            res->status = FATHOM_EXIT_HANG;
        kill(-pid, SIGKILL);
        tgt_detach(&t);
        return failed ? -1 : 0;
    }
    /*
     * When the debugger is also the parent, the first wait reports the
     * exit as the tracer and a second one reaps the zombie.  Skipping it
     * leaks a process per run until fork() fails with EAGAIN.
     */
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
#else
    (void)abandoned;
#endif
#if defined(__linux__)
    if (forked) {
        /* The group is the template's: end the child and its traced descendants only. */
        kids_reap(&kids);
        fs_reap(os, pid);
    } else {
        kill(-pid, SIGKILL);   /* the target leads its own group: ends every descendant */
        kids_reap(&kids);
    }
#else
    (void)forked;
    kill(-pid, SIGKILL);       /* the target leads its own group: ends every descendant */
#endif
    if (g_timed_out && res->status != FATHOM_EXIT_CRASH)
        res->status = FATHOM_EXIT_HANG;
    tgt_detach(&t);
    return failed ? -1 : 0;
}

#endif /* !_WIN32 */
