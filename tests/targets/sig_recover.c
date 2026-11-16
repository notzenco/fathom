/*
 * sig_recover.c — Test target that faults on purpose and recovers.
 *
 * Every run probes an unmapped address and recovers in its fault
 * handler, which is not a crash.  Input 'C' then faults with no handler.
 */
#include <stdio.h>
#include <stdlib.h>

static int g_c;

static void fault(int v)
{
    volatile int *p = NULL;
    *p = v;
}

#ifdef _WIN32
#include <windows.h>

static void *g_veh;

static __attribute__((noreturn)) void resume(void)
{
    RemoveVectoredExceptionHandler(g_veh);
    if (g_c == 'C')
        fault(2);
    ExitProcess(0);
}

static LONG CALLBACK on_fault(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
#if defined(_M_ARM64) || defined(__aarch64__)
    ep->ContextRecord->Pc = (DWORD64)(uintptr_t)resume;
#else
    ep->ContextRecord->Rip = (DWORD64)(uintptr_t)resume;
    ep->ContextRecord->Rsp -= 8;   /* as if called: keep the ABI's stack alignment */
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void)
{
    g_c = getchar();
    g_veh = AddVectoredExceptionHandler(1, on_fault);
    fault(1);
    return 1;
}
#else
#include <setjmp.h>
#include <signal.h>

static sigjmp_buf g_env;

static void on_fault(int sig)
{
    (void)sig;
    siglongjmp(g_env, 1);
}

int main(void)
{
    g_c = getchar();
    signal(SIGSEGV, on_fault);
    signal(SIGBUS, on_fault);
    if (sigsetjmp(g_env, 1) == 0)
        fault(1);

    if (g_c == 'C') {
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
        fault(2);
    }
    return 0;
}
#endif
