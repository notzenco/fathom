/*
 * disasm.c — x86-64 / ARM64 disassembly using Capstone
 *
 * Linear sweep over every code section.  Bytes Capstone cannot decode
 * (padding, data in code) are skipped instead of ending the sweep.
 * Each instruction is classified (branch, call, ret, syscall) and gets
 * its direct target plus any PC-relative address it computes.
 */

#include "disasm.h"

/* Capstone 6 renamed ARM64 to AArch64; this keeps the old names working. */
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if CS_API_MAJOR >= 6
#define A64_ARCH        CS_ARCH_AARCH64
#define A64(detail)     (&(detail)->aarch64)
#else
#define A64_ARCH        CS_ARCH_ARM64
#define A64(detail)     (&(detail)->arm64)
#endif

/* ── x86-64 ──────────────────────────────────────────────────────────── */

static fathom_insn_kind_t classify_x86(const cs_insn *insn, bool *is_cond)
{
    const cs_detail *d = insn->detail;
    bool is_jump = false, is_call = false, is_ret = false, is_int = false;

    for (uint8_t i = 0; i < d->groups_count; i++) {
        switch (d->groups[i]) {
        case CS_GRP_JUMP: is_jump = true; break;
        case CS_GRP_CALL: is_call = true; break;
        case CS_GRP_RET:  is_ret  = true; break;
        case CS_GRP_INT:  is_int  = true; break;
        default: break;
        }
    }

    if (insn->id == X86_INS_SYSCALL || insn->id == X86_INS_SYSENTER)
        return FATHOM_INSN_SYSCALL;
    if (is_int) {
        if (d->x86.op_count == 1 && d->x86.operands[0].type == X86_OP_IMM &&
            d->x86.operands[0].imm == 0x80)
            return FATHOM_INSN_SYSCALL;
        return FATHOM_INSN_OTHER;
    }
    if (is_ret)
        return FATHOM_INSN_RET;
    if (is_call)
        return FATHOM_INSN_CALL;
    if (is_jump) {
        *is_cond = insn->id != X86_INS_JMP && insn->id != X86_INS_LJMP;
        return FATHOM_INSN_BRANCH;
    }
    return FATHOM_INSN_OTHER;
}

static void decode_x86(const cs_insn *ci, fathom_insn_t *fi)
{
    const cs_x86 *x = &ci->detail->x86;
    bool cond = false;

    fi->kind = classify_x86(ci, &cond);
    fi->is_conditional = cond;

    bool is_cmp = strcmp(ci->mnemonic, "cmp") == 0;

    for (uint8_t i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_IMM && is_cmp) {
            fi->cmp_imm = op->imm;
            fi->has_cmp_imm = true;
        } else if (op->type == X86_OP_IMM &&
            (fi->kind == FATHOM_INSN_BRANCH || fi->kind == FATHOM_INSN_CALL))
            fi->branch_target = (uint64_t)op->imm;
        else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP &&
                 op->mem.index == X86_REG_INVALID)
            fi->ref_target = ci->address + ci->size + (uint64_t)op->mem.disp;
    }
}

/* ── ARM64 ───────────────────────────────────────────────────────────── */

/*
 * Pages loaded by recent `adrp` instructions, so a following add/ldr
 * through the same register yields the full address.
 */
#define ADRP_SLOTS   4
#define ADRP_WINDOW  8   /* instructions an adrp result stays trusted */

typedef struct {
    unsigned reg;
    uint64_t page;
    size_t   at;
} adrp_slot_t;

typedef struct {
    adrp_slot_t slots[ADRP_SLOTS];
    size_t      next;
} adrp_state_t;

static adrp_slot_t *adrp_find(adrp_state_t *st, unsigned reg, size_t now)
{
    for (int i = 0; i < ADRP_SLOTS; i++) {
        adrp_slot_t *s = &st->slots[i];
        if (s->reg == reg && reg != 0 && now - s->at <= ADRP_WINDOW)
            return s;
    }
    return NULL;
}

static void adrp_forget(adrp_state_t *st, unsigned reg)
{
    for (int i = 0; i < ADRP_SLOTS; i++) {
        if (st->slots[i].reg == reg)
            st->slots[i].reg = 0;
    }
}

static bool has_prefix(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* Classified by mnemonic: instruction ids and groups differ across Capstone 4-6. */
static fathom_insn_kind_t classify_arm64(const char *m, bool *is_cond)
{
    if (strcmp(m, "bl") == 0 || has_prefix(m, "blr"))
        return FATHOM_INSN_CALL;
    if (strcmp(m, "b") == 0 || has_prefix(m, "br"))
        return FATHOM_INSN_BRANCH;
    if (has_prefix(m, "b.") || strcmp(m, "cbz") == 0 || strcmp(m, "cbnz") == 0 ||
        strcmp(m, "tbz") == 0 || strcmp(m, "tbnz") == 0) {
        *is_cond = true;
        return FATHOM_INSN_BRANCH;
    }
    if (has_prefix(m, "ret") || strcmp(m, "eret") == 0)
        return FATHOM_INSN_RET;
    if (strcmp(m, "svc") == 0)
        return FATHOM_INSN_SYSCALL;
    return FATHOM_INSN_OTHER;
}

static void decode_arm64(const cs_insn *ci, fathom_insn_t *fi,
                         adrp_state_t *st, size_t idx)
{
    const cs_arm64 *a = A64(ci->detail);
    bool cond = false;

    fi->kind = classify_arm64(ci->mnemonic, &cond);
    fi->is_conditional = cond;

    if (fi->kind == FATHOM_INSN_BRANCH || fi->kind == FATHOM_INSN_CALL) {
        /* The target is the last immediate (tbz/tbnz also carry a bit number). */
        for (uint8_t i = 0; i < a->op_count; i++) {
            if (a->operands[i].type == ARM64_OP_IMM)
                fi->branch_target = (uint64_t)a->operands[i].imm;
        }
    }

    if (fi->kind != FATHOM_INSN_OTHER) {
        memset(st, 0, sizeof(*st));
        return;
    }

    /* cmp/cmn are aliases of subs/adds; at -O0 clang often emits the latter. */
    const char *m = ci->mnemonic;
    bool is_sub = !strcmp(m, "cmp") || !strcmp(m, "subs") || !strcmp(m, "ccmp");
    bool is_add = !strcmp(m, "cmn") || !strcmp(m, "adds") || !strcmp(m, "ccmn");
    if ((is_sub || is_add) && a->op_count >= 2) {
        for (uint8_t i = 1; i < a->op_count; i++) {
            if (a->operands[i].type == ARM64_OP_IMM) {
                fi->cmp_imm = is_add ? -a->operands[i].imm : a->operands[i].imm;
                fi->has_cmp_imm = true;
                break;
            }
        }
    }
    if (a->op_count < 2 || a->operands[0].type != ARM64_OP_REG)
        return;

    unsigned dst = a->operands[0].reg;
    const cs_arm64_op *src = &a->operands[1];

    if (strcmp(ci->mnemonic, "adrp") == 0 && src->type == ARM64_OP_IMM) {
        adrp_forget(st, dst);
        st->slots[st->next] = (adrp_slot_t){ dst, (uint64_t)src->imm, idx };
        st->next = (st->next + 1) % ADRP_SLOTS;
        return;
    }

    adrp_slot_t *s = NULL;
    if (strcmp(ci->mnemonic, "add") == 0 && a->op_count == 3 &&
        src->type == ARM64_OP_REG && a->operands[2].type == ARM64_OP_IMM &&
        (s = adrp_find(st, src->reg, idx)))
        fi->ref_target = s->page + (uint64_t)a->operands[2].imm;
    else if (has_prefix(ci->mnemonic, "ldr") && src->type == ARM64_OP_MEM &&
             (s = adrp_find(st, src->mem.base, idx)))
        fi->ref_target = s->page + (uint64_t)(int64_t)src->mem.disp;

    adrp_forget(st, dst);
}

/* ── Public API ───────────────────────────────────────────────────────── */

static int append(fathom_disasm_t *dis, size_t *cap)
{
    if (dis->count < *cap)
        return 0;
    size_t ncap = *cap ? *cap * 2 : 4096;
    fathom_insn_t *p = realloc(dis->insns, ncap * sizeof(*p));
    if (!p)
        return -1;
    dis->insns = p;
    *cap = ncap;
    return 0;
}

static int sweep_section(fathom_disasm_t *dis, size_t *cap, csh handle,
                         cs_insn *ci, const fathom_binary_t *bin,
                         const fathom_section_t *sec)
{
    size_t step = bin->arch == FATHOM_ARCH_ARM64 ? 4 : 1;
    const uint8_t *code = bin->image + sec->offset;
    size_t   left = (size_t)sec->size;
    uint64_t addr = sec->addr;
    adrp_state_t adrp;
    memset(&adrp, 0, sizeof(adrp));

    while (left > 0) {
        if (!cs_disasm_iter(handle, &code, &left, &addr, ci)) {
            /* Undecodable bytes: skip one instruction slot and resume. */
            size_t skip = left < step ? left : step;
            code += skip;
            left -= skip;
            addr += skip;
            memset(&adrp, 0, sizeof(adrp));
            continue;
        }

        if (append(dis, cap) < 0)
            return -1;
        fathom_insn_t *fi = &dis->insns[dis->count];
        memset(fi, 0, sizeof(*fi));
        fi->addr = ci->address;
        fi->size = ci->size;
        size_t mlen = strnlen(ci->mnemonic, sizeof(fi->mnemonic) - 1);
        memcpy(fi->mnemonic, ci->mnemonic, mlen);   /* fi was zeroed: stays terminated */

        if (bin->arch == FATHOM_ARCH_ARM64)
            decode_arm64(ci, fi, &adrp, dis->count);
        else
            decode_x86(ci, fi);
        dis->count++;
    }
    return 0;
}

int fathom_disasm_open(fathom_disasm_t *dis, const fathom_binary_t *bin)
{
    memset(dis, 0, sizeof(*dis));
    if (!bin || !bin->image)
        return -1;

    dis->arch = bin->arch;
    cs_arch arch = bin->arch == FATHOM_ARCH_ARM64 ? A64_ARCH : CS_ARCH_X86;
    cs_mode mode = bin->arch == FATHOM_ARCH_ARM64 ? CS_MODE_LITTLE_ENDIAN : CS_MODE_64;

    csh handle;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "fathom_disasm: cs_open failed for %s\n",
                fathom_arch_name(bin->arch));
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *ci = cs_malloc(handle);
    size_t cap = 0;
    int rc = ci ? 0 : -1;

    for (size_t i = 0; i < bin->section_count && rc == 0; i++) {
        if (bin->sections[i].flags & FATHOM_SEC_CODE)
            rc = sweep_section(dis, &cap, handle, ci, bin, &bin->sections[i]);
    }

    if (ci)
        cs_free(ci, 1);
    cs_close(&handle);

    if (rc == 0 && dis->count == 0) {
        fprintf(stderr, "fathom_disasm: no instructions decoded\n");
        rc = -1;
    }
    if (rc < 0)
        fathom_disasm_close(dis);
    return rc;
}

void fathom_disasm_close(fathom_disasm_t *dis)
{
    free(dis->insns);
    dis->insns = NULL;
    dis->count = 0;
}

size_t fathom_disasm_find(const fathom_disasm_t *dis, uint64_t addr)
{
    size_t lo = 0, hi = dis->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (dis->insns[mid].addr < addr)
            lo = mid + 1;
        else if (dis->insns[mid].addr > addr)
            hi = mid;
        else
            return mid;
    }
    return (size_t)-1;
}
