/*
 * disasm.c — x86-64 disassembly wrapper using Capstone
 *
 * Performs linear sweep disassembly of the .text section and classifies
 * each instruction by kind (branch, call, ret, syscall).
 */

#include "disasm.h"

#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ──────────────────────────────────────────────────────────── */

/*
 * Classify an instruction into a fathom_insn_kind_t by checking its
 * Capstone group membership.
 */
static fathom_insn_kind_t classify_insn(const cs_insn *insn, bool *is_cond)
{
    *is_cond = false;

    const cs_detail *d = insn->detail;
    if (!d)
        return FATHOM_INSN_OTHER;

    bool is_jump = false;
    bool is_call = false;
    bool is_ret  = false;
    bool is_int  = false;

    for (uint8_t i = 0; i < d->groups_count; i++) {
        switch (d->groups[i]) {
        case CS_GRP_JUMP:  is_jump = true; break;
        case CS_GRP_CALL:  is_call = true; break;
        case CS_GRP_RET:   is_ret  = true; break;
        case CS_GRP_INT:   is_int  = true; break;
        default: break;
        }
    }

    /* syscall / sysenter */
    if (insn->id == X86_INS_SYSCALL || insn->id == X86_INS_SYSENTER)
        return FATHOM_INSN_SYSCALL;

    /* int 0x80 is a legacy Linux syscall */
    if (is_int) {
        if (d->x86.op_count == 1 &&
            d->x86.operands[0].type == X86_OP_IMM &&
            d->x86.operands[0].imm == 0x80)
            return FATHOM_INSN_SYSCALL;
        return FATHOM_INSN_OTHER;
    }

    if (is_ret)
        return FATHOM_INSN_RET;

    if (is_call)
        return FATHOM_INSN_CALL;

    if (is_jump) {
        /*
         * Unconditional jumps: jmp, ljmp.
         * Everything else in CS_GRP_JUMP is conditional.
         */
        if (insn->id == X86_INS_JMP || insn->id == X86_INS_LJMP)
            *is_cond = false;
        else
            *is_cond = true;
        return FATHOM_INSN_BRANCH;
    }

    return FATHOM_INSN_OTHER;
}

/*
 * For branches and calls with an immediate operand, extract the
 * absolute target address.  Returns 0 for indirect operands.
 */
static uint64_t extract_branch_target(const cs_insn *insn)
{
    const cs_detail *d = insn->detail;
    if (!d)
        return 0;

    for (uint8_t i = 0; i < d->x86.op_count; i++) {
        if (d->x86.operands[i].type == X86_OP_IMM)
            return (uint64_t)d->x86.operands[i].imm;
    }

    return 0;
}

/* ── Public API ───────────────────────────────────────────────────────── */

int fathom_disasm_open(fathom_disasm_t *dis, const fathom_elf_t *elf)
{
    memset(dis, 0, sizeof(*dis));

    if (!elf || !elf->mapped || elf->text.size == 0) {
        fprintf(stderr, "fathom_disasm: invalid ELF (no .text)\n");
        return -1;
    }

    /* Bounds-check the .text section against the mapping */
    if (elf->text.offset + elf->text.size > elf->mapped_len) {
        fprintf(stderr, "fathom_disasm: .text section exceeds mapped file\n");
        return -1;
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "fathom_disasm: cs_open failed\n");
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const uint8_t *code = elf->mapped + elf->text.offset;
    size_t code_size    = elf->text.size;
    uint64_t base_addr  = elf->text.addr;

    cs_insn *cs_insns = NULL;
    size_t cs_count = cs_disasm(handle, code, code_size, base_addr, 0, &cs_insns);

    if (cs_count == 0) {
        fprintf(stderr, "fathom_disasm: no instructions decoded\n");
        cs_close(&handle);
        return -1;
    }

    dis->insns = calloc(cs_count, sizeof(fathom_insn_t));
    if (!dis->insns) {
        cs_free(cs_insns, cs_count);
        cs_close(&handle);
        return -1;
    }
    dis->count = cs_count;

    for (size_t i = 0; i < cs_count; i++) {
        const cs_insn *ci = &cs_insns[i];
        fathom_insn_t *fi = &dis->insns[i];

        fi->addr = ci->address;
        fi->size = ci->size;

        strncpy(fi->mnemonic, ci->mnemonic, sizeof(fi->mnemonic) - 1);
        fi->mnemonic[sizeof(fi->mnemonic) - 1] = '\0';

        bool cond = false;
        fi->kind = classify_insn(ci, &cond);
        fi->is_conditional = cond;

        if (fi->kind == FATHOM_INSN_BRANCH || fi->kind == FATHOM_INSN_CALL)
            fi->branch_target = extract_branch_target(ci);
        else
            fi->branch_target = 0;
    }

    cs_free(cs_insns, cs_count);
    cs_close(&handle);

    return 0;
}

void fathom_disasm_close(fathom_disasm_t *dis)
{
    free(dis->insns);
    dis->insns = NULL;
    dis->count = 0;
}
