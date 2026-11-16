/*
 * switch_table.c — Test target with a dense switch that compiles to a
 * jump table (the Makefile builds it with -O2), so its cases are
 * reachable only through an indirect jump.
 */
#include <stdio.h>

static volatile int sink;

#define CASE_FN(n) __attribute__((noinline)) static void case_##n(void) { sink ^= n; }
CASE_FN(0) CASE_FN(1) CASE_FN(2) CASE_FN(3) CASE_FN(4) CASE_FN(5) CASE_FN(6) CASE_FN(7) CASE_FN(8) CASE_FN(9) CASE_FN(10) CASE_FN(11)

int main(void)
{
    switch (getchar()) {
    case 'a': case_0(); sink += 3; break;
    case 'b': case_1(); sink += 10; break;
    case 'c': case_2(); sink += 17; break;
    case 'd': case_3(); sink += 24; break;
    case 'e': case_4(); sink += 31; break;
    case 'f': case_5(); sink += 38; break;
    case 'g': case_6(); sink += 45; break;
    case 'h': case_7(); sink += 52; break;
    case 'i': case_8(); sink += 59; break;
    case 'j': case_9(); sink += 66; break;
    case 'k': case_10(); sink += 73; break;
    case 'l': case_11(); sink += 80; break;
    default:  sink = 0; break;
    }
    return 0;
}
