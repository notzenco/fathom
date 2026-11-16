/*
 * exec_windows.c — Debugger backend for Windows (x64 and ARM64)
 *
 * The target is started with DEBUG_ONLY_THIS_PROCESS, so the kernel
 * reports its process creation, breakpoints and faults to this process
 * as debug events.  Breakpoints are written when the process-creation
 * event arrives, before the target's first instruction; the image base
 * in that event gives the ASLR slide.
 *
 * Faults are passed back to the target on first chance, so its own
 * handlers (SEH, vectored handlers) can recover, and count as crashes on
 * second chance, when nothing handled them.  A fault also counts when it
 * repeats at the same place on first chance (a handler that did not fix
 * it) or the target then exits non-zero.  Fail-fast exceptions (heap
 * corruption, /GS stack checks) cannot be handled and count at once.
 *
 * Breakpoint exceptions that are not ours are the target's, except the
 * loader's single initial break, which is skipped.
 *
 * Each target runs in a job object that is terminated after the run, so
 * no process it starts outlives the run.
 */

#if defined(_WIN32)

#include "exec.h"
#include "osdep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PSAPI_VERSION 2   /* GetMappedFileName from kernel32 */
#include <psapi.h>

#ifndef STATUS_HEAP_CORRUPTION
#define STATUS_HEAP_CORRUPTION      ((DWORD)0xC0000374)
#endif
#ifndef STATUS_STACK_BUFFER_OVERRUN
#define STATUS_STACK_BUFFER_OVERRUN ((DWORD)0xC0000409)
#endif
#ifndef STATUS_FAIL_FAST_EXCEPTION
#define STATUS_FAIL_FAST_EXCEPTION  ((DWORD)0xC0000602)
#endif

static bool is_fail_fast(DWORD code)
{
    return code == STATUS_HEAP_CORRUPTION || code == STATUS_STACK_BUFFER_OVERRUN ||
           code == STATUS_FAIL_FAST_EXCEPTION;
}

static bool is_crash_code(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_IN_PAGE_ERROR:
    case STATUS_HEAP_CORRUPTION:
    case STATUS_STACK_BUFFER_OVERRUN:
    case STATUS_FAIL_FAST_EXCEPTION:
        return true;
    default:
        return false;
    }
}

/* ── Target memory and registers ─────────────────────────────────────── */

static bool read_mem(HANDLE proc, uint64_t addr, void *buf, size_t len)
{
    SIZE_T got = 0;
    return ReadProcessMemory(proc, (LPCVOID)(uintptr_t)addr, buf, len, &got) &&
           got == len;
}

static bool write_code(HANDLE proc, uint64_t addr, const void *buf, size_t len)
{
    SIZE_T put = 0;
    bool ok = WriteProcessMemory(proc, (LPVOID)(uintptr_t)addr, buf, len, &put) &&
              put == len;
    FlushInstructionCache(proc, (LPCVOID)(uintptr_t)addr, len);
    return ok;
}

static bool read_word(void *ctx, uint64_t addr, uint64_t *out)
{
    return read_mem((HANDLE)ctx, addr, out, sizeof(*out));
}

static bool rd_mem(void *ctx, uint64_t addr, void *buf, size_t len)
{
    return read_mem((HANDLE)ctx, addr, buf, len);
}

static bool wr_mem(void *ctx, uint64_t addr, const void *buf, size_t len)
{
    return write_code((HANDLE)ctx, addr, buf, len);
}

/* Stable key for an address inside a mapped image (a DLL). */
static bool module_key(void *ctx, uint64_t addr, uint64_t *key)
{
    HANDLE proc = (HANDLE)ctx;
    MEMORY_BASIC_INFORMATION mbi;
    char path[MAX_PATH];
    if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) ||
        mbi.Type != MEM_IMAGE ||
        !GetMappedFileNameA(proc, mbi.AllocationBase, path, sizeof(path)))
        return false;
    *key = exec_module_key(path, addr - (uint64_t)(uintptr_t)mbi.AllocationBase);
    return true;
}

#if defined(_M_ARM64) || defined(__aarch64__)
#define CTX_PC(c) ((c).Pc)
#define CTX_FP(c) ((c).Fp)
#else
#define CTX_PC(c) ((c).Rip)
#define CTX_FP(c) ((c).Rbp)
#endif

static void ctx_regs(const CONTEXT *c, exec_regs_t *out)
{
    memset(out, 0, sizeof(*out));
#if defined(_M_ARM64) || defined(__aarch64__)
    for (int i = 0; i < 31; i++)
        out->r[i] = c->X[i];
    out->r[31] = c->Sp;
#else
    const DWORD64 v[16] = {
        c->Rax, c->Rcx, c->Rdx, c->Rbx, c->Rsp, c->Rbp, c->Rsi, c->Rdi,
        c->R8, c->R9, c->R10, c->R11, c->R12, c->R13, c->R14, c->R15,
    };
    for (int i = 0; i < 16; i++)
        out->r[i] = v[i];
#endif
}

static HANDLE open_thread(DWORD tid, CONTEXT *ctx)
{
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(th, ctx)) {
        CloseHandle(th);
        return NULL;
    }
    return th;
}

/* ── Backend hooks ───────────────────────────────────────────────────── */

int exec_os_init(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    char path[MAX_PATH];

    /* No "program has stopped working" dialogs for crashing targets. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);

    if (!GetTempFileNameA(fathom_tmpdir(), "fth", 0, path)) {
        fprintf(stderr, "fathom: GetTempFileName failed (%lu)\n", GetLastError());
        return -1;
    }
    /*
     * A target opening the file by path (@@) would not pass
     * FILE_SHARE_DELETE, which delete-on-close requires; that file is
     * deleted in exec_os_destroy instead.
     */
    os->input = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            &sa, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY |
                            (os->input_by_path ? 0 : FILE_FLAG_DELETE_ON_CLOSE), NULL);
    if (os->input_by_path)
        snprintf(os->input_path, sizeof(os->input_path), "%s", path);
    os->devnull = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);
    os->cmdline = NULL;   /* built at the first run, once argv has its input path */
    os->job = CreateJobObjectA(NULL, NULL);
    if (os->job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim;
        memset(&lim, 0, sizeof(lim));
        lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(os->job, JobObjectExtendedLimitInformation,
                                &lim, sizeof(lim));
    }
    if (os->input == INVALID_HANDLE_VALUE || os->devnull == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "fathom: cannot set up target I/O (%lu)\n", GetLastError());
        return -1;
    }
    return 0;
}

void exec_os_destroy(fathom_exec_t *ex)
{
    struct fathom_exec_os *os = ex->os;
    if (os->input && os->input != INVALID_HANDLE_VALUE)
        CloseHandle(os->input);
    if (os->devnull && os->devnull != INVALID_HANDLE_VALUE)
        CloseHandle(os->devnull);
    if (os->job)
        CloseHandle(os->job);
    free(os->cmdline);
    if (os->input_path[0])
        DeleteFileA(os->input_path);
    os->job = NULL;
    os->input = os->devnull = NULL;
    os->cmdline = NULL;
}

int exec_os_write_input(fathom_exec_t *ex, const uint8_t *data, size_t len)
{
    HANDLE h = ex->os->input;
    DWORD put = 0;
    /* The target inherits this handle and shares its file position. */
    if (SetFilePointer(h, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
        (len && (!WriteFile(h, data, (DWORD)len, &put, NULL) || put != len)) ||
        !SetEndOfFile(h) ||
        SetFilePointer(h, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return -1;
    return 0;
}

typedef struct {
    bool     set;
    DWORD    code;
    uint64_t pc;
    uint64_t link_pc;
    uint64_t hash;
} fault_t;

typedef struct {
    fathom_exec_t        *ex;
    fathom_coverage_t    *cov;
    fathom_exec_result_t *res;
    HANDLE                proc;
    bool                  seen_loader_break;
    bool                  failed;
    fault_t               pending;
} run_t;

static void record_fault(run_t *r, DWORD code, uint64_t pc, uint64_t fp, fault_t *f)
{
    f->set = true;
    f->code = code;
    f->pc = pc;
    f->link_pc = exec_link_addr(r->ex, pc);
    f->hash = fathom_fnv_mix(exec_crash_hash(r->ex, pc, fp, read_word, module_key, r->proc),
                             code);
}

static void report_crash(fathom_exec_result_t *res, const fault_t *f)
{
    res->status = FATHOM_EXIT_CRASH;
    res->crash_code = f->code;
    res->crash_pc = f->link_pc;
    res->crash_hash = f->hash;
}

/* Returns the ContinueDebugEvent status for an exception event. */
static DWORD on_exception(run_t *r, const DEBUG_EVENT *ev, bool *kill_now)
{
    const EXCEPTION_RECORD *er = &ev->u.Exception.ExceptionRecord;
    DWORD code = er->ExceptionCode;
    bool first = ev->u.Exception.dwFirstChance != 0;
    uint64_t addr = (uint64_t)(uintptr_t)er->ExceptionAddress;
    CONTEXT ctx;

    if (code == EXCEPTION_BREAKPOINT && first) {
        exec_write_t w[2];
        size_t nw;
        HANDLE th = open_thread(ev->dwThreadId, &ctx);
        if (!th) {
            r->failed = *kill_now = true;
            return DBG_CONTINUE;
        }
        DWORD cont = DBG_CONTINUE;
        uint32_t probe;
        if ((nw = exec_bp_hit(r->ex, r->cov, addr, w, &probe)) > 0) {
            if (probe != UINT32_MAX) {
                exec_regs_t regs;
                ctx_regs(&ctx, &regs);
                exec_probe_log(r->ex, probe, &regs, rd_mem, r->proc);
            }
            bool ok = true;
            for (size_t i = 0; i < nw; i++)
                ok = ok && write_code(r->proc, w[i].addr, w[i].bytes, w[i].len);
            CTX_PC(ctx) = addr;
            if (!ok || !SetThreadContext(th, &ctx)) {
                fprintf(stderr, "fathom: cannot restore code under the breakpoint "
                                "at 0x%llx (%lu)\n", (unsigned long long)addr,
                        GetLastError());
                r->failed = *kill_now = true;
            }
        } else if (!r->seen_loader_break) {
            /* The loader's initial break: step past it on ARM64, where PC stays on the brk. */
            r->seen_loader_break = true;
            if (r->ex->arch == FATHOM_ARCH_ARM64 && CTX_PC(ctx) == addr) {
                CTX_PC(ctx) += 4;
                SetThreadContext(th, &ctx);
            }
        } else {
            record_fault(r, code, CTX_PC(ctx), CTX_FP(ctx), &r->pending);
            cont = DBG_EXCEPTION_NOT_HANDLED;   /* the target's own trap */
        }
        CloseHandle(th);
        return cont;
    }

    bool fatal = !first || is_fail_fast(code);
    if (!fatal && !is_crash_code(code))
        return DBG_EXCEPTION_NOT_HANDLED;   /* C++ throws, debug prints, ... */

    uint64_t pc = addr, fp = 0;
    HANDLE th = open_thread(ev->dwThreadId, &ctx);
    if (th) {
        pc = CTX_PC(ctx);
        fp = CTX_FP(ctx);
        CloseHandle(th);
    }

    fault_t f;
    record_fault(r, code, pc, fp, &f);
    bool repeat = r->pending.set && r->pending.code == code && r->pending.pc == pc;
    if (!fatal && !repeat) {
        r->pending = f;
        return DBG_EXCEPTION_NOT_HANDLED;   /* let the target's handlers try */
    }

    if (!first && r->pending.set && r->pending.code == code)
        f = r->pending;   /* the context where the fault first happened */
    report_crash(r->res, &f);
    *kill_now = true;
    return DBG_CONTINUE;
}

int exec_os_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                fathom_exec_result_t *res)
{
    struct fathom_exec_os *os = ex->os;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = os->input_by_path ? os->devnull : os->input;
    si.hStdOutput = os->devnull;
    si.hStdError = os->devnull;

    if (!os->cmdline && !(os->cmdline = fathom_win_cmdline(ex->target_argv)))
        return -1;
    /* CreateProcess may modify the command line buffer. */
    char *cmd = _strdup(os->cmdline);
    if (!cmd)
        return -1;
    BOOL ok = CreateProcessA(ex->target_path, cmd, NULL, NULL, TRUE,
                             DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_PROCESS_GROUP |
                             CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    free(cmd);
    if (!ok) {
        fprintf(stderr, "fathom: CreateProcess(%s) failed (%lu)\n",
                ex->target_path, GetLastError());
        return -1;
    }

    /* Children join the job, so terminating it ends them too. */
    if (os->job)
        AssignProcessToJobObject(os->job, pi.hProcess);

    run_t run;
    memset(&run, 0, sizeof(run));
    run.ex = ex;
    run.cov = cov;
    run.res = res;
    run.proc = pi.hProcess;

    res->status = FATHOM_EXIT_OK;
    uint64_t deadline = fathom_now_us() + (uint64_t)ex->timeout_ms * 1000u;
    bool killed = false, timed_out = false, failed = false;

    for (;;) {
        DEBUG_EVENT ev;
        DWORD wait_ms = 5000;
        if (!killed) {
            uint64_t now = fathom_now_us();
            if (now >= deadline) {
                TerminateProcess(pi.hProcess, 1);
                killed = timed_out = true;
            } else {
                wait_ms = (DWORD)((deadline - now + 999) / 1000);
            }
        }

        if (!WaitForDebugEvent(&ev, wait_ms)) {
            /* Before the kill, a timeout just re-checks the deadline. */
            if (GetLastError() == ERROR_SEM_TIMEOUT && !killed)
                continue;
            failed = true;
            break;
        }

        DWORD cont = DBG_CONTINUE;
        bool done = false, kill_now = false;

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hFile)
                CloseHandle(ev.u.CreateProcessInfo.hFile);
            os->slide = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage -
                        ex->image_base;
            if (exec_insert_breakpoints(ex, rd_mem, wr_mem, pi.hProcess) < 0)
                failed = kill_now = true;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (ev.u.LoadDll.hFile)
                CloseHandle(ev.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
            if (res->status == FATHOM_EXIT_CRASH)
                break;
            cont = on_exception(&run, &ev, &kill_now);
            failed |= run.failed;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            /* A fault handler that bailed out with an error still hit the fault. */
            if (res->status == FATHOM_EXIT_OK && !killed && run.pending.set &&
                ev.u.ExitProcess.dwExitCode != 0)
                report_crash(res, &run.pending);
            done = true;
            break;
        default:
            break;
        }

        if (kill_now && !killed) {
            TerminateProcess(pi.hProcess, 1);
            killed = true;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        if (done)
            break;
    }

    if (os->job)
        TerminateJobObject(os->job, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (failed)
        return -1;
    if (timed_out && res->status != FATHOM_EXIT_CRASH)
        res->status = FATHOM_EXIT_HANG;
    return 0;
}

#endif /* _WIN32 */
