/*
 * trap_block.c — Test target with a block whose first instruction is
 * the same trap fathom uses as a breakpoint.  Input 'T' executes it,
 * which kills an undebugged process.
 */
#include <stdio.h>

#if defined(__x86_64__) || defined(_M_X64)
#define TRAP "int3"
#elif defined(_WIN32)
#define TRAP "brk #0xf000"
#else
#define TRAP "brk #0"
#endif

#ifdef __APPLE__
#define SYM "_trap_fn"
#else
#define SYM "trap_fn"
#endif

__asm__(".text\n.globl " SYM "\n" SYM ":\n " TRAP "\n ret\n");
void trap_fn(void);

int main(void)
{
    if (getchar() == 'T')
        trap_fn();
    return 0;
}
