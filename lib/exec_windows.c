/*
 * exec_windows.c — Debugger backend for Windows (x64 and ARM64)
 *
 * The target is started with DEBUG_ONLY_THIS_PROCESS, so the kernel
 * reports its process creation, breakpoints and faults to this process
 * as debug events.  Breakpoints are written when the process-creation
 * event arrives, before the target's first instruction; the image base
 * in that event gives the ASLR slide.
 *
 * Faults are counted as crashes on first chance: by then the target has
 * done something invalid, and waiting for the second chance would let a
 * handler mask it.  Other first-chance exceptions (C++ throws, debug
 * prints) are passed back to the target.
 */

#if defined(_WIN32)

#include "exec.h"
#include "osdep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef STATUS_HEAP_CORRUPTION
#define STATUS_HEAP_CORRUPTION      ((DWORD)0xC0000374)
#endif
#ifndef STATUS_STACK_BUFFER_OVERRUN
#define STATUS_STACK_BUFFER_OVERRUN ((DWORD)0xC0000409)
#endif
#ifndef STATUS_FAIL_FAST_EXCEPTION
#define STATUS_FAIL_FAST_EXCEPTION  ((DWORD)0xC0000602)
#endif

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

#if defined(_M_ARM64) || defined(__aarch64__)
#define CTX_PC(c) ((c).Pc)
#define CTX_FP(c) ((c).Fp)
#else
#define CTX_PC(c) ((c).Rip)
#define CTX_FP(c) ((c).Rbp)
#endif

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
    os->input = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            &sa, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    os->devnull = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);
    os->cmdline = fathom_win_cmdline(ex->target_argv);
    if (os->input == INVALID_HANDLE_VALUE || os->devnull == INVALID_HANDLE_VALUE ||
        !os->cmdline) {
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
    free(os->cmdline);
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

static int insert_breakpoints(fathom_exec_t *ex, HANDLE proc)
{
    struct fathom_exec_os *os = ex->os;
    if (ex->bp_count == 0)
        return 0;

    uint64_t at = os->lo + os->slide;
    size_t span = (size_t)(os->hi - os->lo);
    if (!read_mem(proc, at, os->orig, span)) {
        fprintf(stderr, "fathom: cannot read target code (%lu)\n", GetLastError());
        return -1;
    }
    exec_build_patch(ex);
    if (!write_code(proc, at, os->patched, span)) {
        fprintf(stderr, "fathom: cannot write breakpoints (%lu)\n", GetLastError());
        return -1;
    }
    return 0;
}

/* Returns the ContinueDebugEvent status for an exception event. */
static DWORD on_exception(fathom_exec_t *ex, fathom_coverage_t *cov,
                          fathom_exec_result_t *res, HANDLE proc,
                          const DEBUG_EVENT *ev, bool *kill_now)
{
    const EXCEPTION_RECORD *er = &ev->u.Exception.ExceptionRecord;
    uint64_t addr = (uint64_t)(uintptr_t)er->ExceptionAddress;
    CONTEXT ctx;

    if (er->ExceptionCode == EXCEPTION_BREAKPOINT) {
        const uint8_t *orig;
        size_t len;
        HANDLE th = open_thread(ev->dwThreadId, &ctx);
        if (!th)
            return DBG_CONTINUE;

        if (exec_bp_hit(ex, cov, addr, &orig, &len)) {
            write_code(proc, addr, orig, len);
            CTX_PC(ctx) = addr;
            SetThreadContext(th, &ctx);
        } else if (ex->arch == FATHOM_ARCH_ARM64 && CTX_PC(ctx) == addr) {
            /* Not ours (e.g. the loader's initial break): step past the brk. */
            CTX_PC(ctx) += 4;
            SetThreadContext(th, &ctx);
        }
        CloseHandle(th);
        return DBG_CONTINUE;
    }

    if (is_crash_code(er->ExceptionCode) || !ev->u.Exception.dwFirstChance) {
        uint64_t pc = addr, fp = 0;
        HANDLE th = open_thread(ev->dwThreadId, &ctx);
        if (th) {
            pc = CTX_PC(ctx);
            fp = CTX_FP(ctx);
            CloseHandle(th);
        }
        res->status = FATHOM_EXIT_CRASH;
        res->crash_code = er->ExceptionCode;
        res->crash_pc = exec_link_addr(ex, pc);
        res->crash_hash = fathom_fnv_mix(exec_crash_hash(ex, pc, fp, read_word, proc),
                                         er->ExceptionCode);
        *kill_now = true;
        return DBG_CONTINUE;
    }

    return DBG_EXCEPTION_NOT_HANDLED;
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
    si.hStdInput = os->input;
    si.hStdOutput = os->devnull;
    si.hStdError = os->devnull;

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
            if (insert_breakpoints(ex, pi.hProcess) < 0) {
                failed = kill_now = true;
            }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (ev.u.LoadDll.hFile)
                CloseHandle(ev.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
            if (res->status == FATHOM_EXIT_CRASH)
                break;
            cont = on_exception(ex, cov, res, pi.hProcess, &ev, &kill_now);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
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

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (failed)
        return -1;
    if (timed_out && res->status != FATHOM_EXIT_CRASH)
        res->status = FATHOM_EXIT_HANG;
    return 0;
}

#endif /* _WIN32 */
