/*
 * test_disasm.c — Disassembler unit tests
 *
 * Opens /bin/ls, disassembles the .text section, and verifies
 * basic properties of the instruction stream.
 */

#include "fathom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_BINARY "/bin/ls"

static int failures = 0;

#define CHECK(cond, msg)                                         \
    do {                                                         \
        if (!(cond)) {                                           \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
            failures++;                                          \
        }                                                        \
    } while (0)

int main(void)
{
    fathom_elf_t elf;
    fathom_disasm_t dis;

    /* Open ELF */
    int rc = fathom_elf_open(&elf, TEST_BINARY);
    CHECK(rc == 0, "fathom_elf_open should succeed on " TEST_BINARY);
    if (rc != 0) {
        fprintf(stderr, "Cannot open %s — aborting\n", TEST_BINARY);
        return 1;
    }

    printf(".text: addr=0x%lx  size=%lu  offset=0x%lx\n",
           (unsigned long)elf.text.addr,
           (unsigned long)elf.text.size,
           (unsigned long)elf.text.offset);

    /* Disassemble */
    rc = fathom_disasm_open(&dis, &elf);
    CHECK(rc == 0, "fathom_disasm_open should succeed");
    if (rc != 0) {
        fathom_elf_close(&elf);
        return 1;
    }

    printf("Disassembled %zu instructions\n", dis.count);
    CHECK(dis.count > 0, "instruction count should be > 0");

    /* Count instruction kinds */
    size_t n_branch   = 0;
    size_t n_call     = 0;
    size_t n_ret      = 0;
    size_t n_syscall  = 0;
    size_t n_other    = 0;
    size_t n_cond     = 0;

    for (size_t i = 0; i < dis.count; i++) {
        const fathom_insn_t *insn = &dis.insns[i];
        switch (insn->kind) {
        case FATHOM_INSN_BRANCH:  n_branch++;  break;
        case FATHOM_INSN_CALL:    n_call++;    break;
        case FATHOM_INSN_RET:     n_ret++;     break;
        case FATHOM_INSN_SYSCALL: n_syscall++; break;
        default:                  n_other++;   break;
        }
        if (insn->is_conditional)
            n_cond++;
    }

    printf("  branches:  %zu (conditional: %zu)\n", n_branch, n_cond);
    printf("  calls:     %zu\n", n_call);
    printf("  rets:      %zu\n", n_ret);
    printf("  syscalls:  %zu\n", n_syscall);
    printf("  other:     %zu\n", n_other);

    CHECK(n_call > 0, "should find at least one CALL instruction");
    CHECK(n_ret > 0,  "should find at least one RET instruction");
    CHECK(n_branch > 0, "should find at least one BRANCH instruction");
    CHECK(n_cond > 0, "should find at least one conditional branch");

    /* Verify branch targets are non-zero for at least some branches */
    size_t targets_found = 0;
    for (size_t i = 0; i < dis.count; i++) {
        const fathom_insn_t *insn = &dis.insns[i];
        if ((insn->kind == FATHOM_INSN_BRANCH || insn->kind == FATHOM_INSN_CALL) &&
            insn->branch_target != 0)
            targets_found++;
    }
    printf("  branch/call targets resolved: %zu\n", targets_found);
    CHECK(targets_found > 0, "should resolve at least one branch target");

    /* Print first 10 instructions as a sanity check */
    printf("\nFirst 10 instructions:\n");
    for (size_t i = 0; i < dis.count && i < 10; i++) {
        const fathom_insn_t *insn = &dis.insns[i];
        printf("  0x%08lx [%2u] %-8s kind=%d target=0x%lx cond=%d\n",
               (unsigned long)insn->addr,
               insn->size,
               insn->mnemonic,
               insn->kind,
               (unsigned long)insn->branch_target,
               insn->is_conditional);
    }

    /* Cleanup */
    fathom_disasm_close(&dis);
    fathom_elf_close(&elf);

    if (failures > 0) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }

    printf("\nAll checks passed.\n");
    return 0;
}
