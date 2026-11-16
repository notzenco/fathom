/*
 * switch_table.c — Test target with a dense switch that compiles to a
 * jump table (the Makefile builds it with -O2), so its cases are
 * reachable only through an indirect jump.  It has enough cases that no
 * compiler turns it into a comparison tree instead.
 */
#include <stdio.h>

static volatile int sink;

#define CASE_FN(n) __attribute__((noinline)) static void case_##n(void) { sink ^= n; }
CASE_FN(0) CASE_FN(1) CASE_FN(2) CASE_FN(3) CASE_FN(4) CASE_FN(5) CASE_FN(6) CASE_FN(7)
CASE_FN(8) CASE_FN(9) CASE_FN(10) CASE_FN(11) CASE_FN(12) CASE_FN(13) CASE_FN(14) CASE_FN(15)
CASE_FN(16) CASE_FN(17) CASE_FN(18) CASE_FN(19) CASE_FN(20) CASE_FN(21) CASE_FN(22) CASE_FN(23)

int main(void)
{
    switch (getchar()) {
    case 'A': case_0(); sink += 3; break;
    case 'B': case_1(); sink += 10; break;
    case 'C': case_2(); sink += 17; break;
    case 'D': case_3(); sink += 24; break;
    case 'E': case_4(); sink += 31; break;
    case 'F': case_5(); sink += 38; break;
    case 'G': case_6(); sink += 45; break;
    case 'H': case_7(); sink += 52; break;
    case 'I': case_8(); sink += 59; break;
    case 'J': case_9(); sink += 66; break;
    case 'K': case_10(); sink += 73; break;
    case 'L': case_11(); sink += 80; break;
    case 'M': case_12(); sink += 87; break;
    case 'N': case_13(); sink += 94; break;
    case 'O': case_14(); sink += 101; break;
    case 'P': case_15(); sink += 108; break;
    case 'Q': case_16(); sink += 115; break;
    case 'R': case_17(); sink += 122; break;
    case 'S': case_18(); sink += 129; break;
    case 'T': case_19(); sink += 136; break;
    case 'U': case_20(); sink += 143; break;
    case 'V': case_21(); sink += 150; break;
    case 'W': case_22(); sink += 157; break;
    case 'X': case_23(); sink += 164; break;
    default:  sink = 0; break;
    }
    return 0;
}
