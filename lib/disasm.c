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
    bool is_lea = strcmp(ci->mnemonic, "lea") == 0;

    for (uint8_t i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_IMM && is_cmp) {
            fi->cmp_imm = op->imm;
            fi->has_cmp_imm = true;
        } else if (op->type == X86_OP_IMM &&
            (fi->kind == FATHOM_INSN_BRANCH || fi->kind == FATHOM_INSN_CALL))
            fi->branch_target = (uint64_t)op->imm;
        else if (op->type == X86_OP_MEM && fi->kind == FATHOM_INSN_BRANCH &&
                 op->mem.base == X86_REG_INVALID && op->mem.index != X86_REG_INVALID &&
                 op->mem.scale == 8 && op->mem.disp > 0)
            fi->jt_table = (uint64_t)op->mem.disp;
        else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP &&
                 op->mem.index == X86_REG_INVALID) {
            fi->ref_target = ci->address + ci->size + (uint64_t)op->mem.disp;
            fi->ref_is_addr = is_lea;
        }
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
    if (a->op_count >= 3 && a->operands[a->op_count - 1].type == ARM64_OP_REG) {
        const cs_arm64_op *last = &a->operands[a->op_count - 1];
        fi->op_shift = (uint8_t)last->shift.value;
        fi->op_sext = last->ext == ARM64_EXT_SXTB || last->ext == ARM64_EXT_SXTH ||
                      last->ext == ARM64_EXT_SXTW;
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
    if (strcmp(ci->mnemonic, "adr") == 0 && src->type == ARM64_OP_IMM) {
        fi->ref_target = (uint64_t)src->imm;
        fi->ref_is_addr = true;
    } else if (strcmp(ci->mnemonic, "add") == 0 && a->op_count == 3 &&
        src->type == ARM64_OP_REG && a->operands[2].type == ARM64_OP_IMM &&
        (s = adrp_find(st, src->reg, idx))) {
        fi->ref_target = s->page + (uint64_t)a->operands[2].imm;
        fi->ref_is_addr = true;
    } else if (has_prefix(ci->mnemonic, "ldr") && src->type == ARM64_OP_MEM &&
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

/* ── Comparison sites ────────────────────────────────────────────────── */

/* x86-64 register to FATHOM_REG numbering; high-byte registers have none. */
static uint8_t x86_gpr(unsigned r)
{
    static const struct { unsigned r[4]; } map[16] = {
        {{ X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AL }},
        {{ X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CL }},
        {{ X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL }},
        {{ X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BL }},
        {{ X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL }},
        {{ X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL }},
        {{ X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL }},
        {{ X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL }},
        {{ X86_REG_R8,  X86_REG_R8D,  X86_REG_R8W,  X86_REG_R8B }},
        {{ X86_REG_R9,  X86_REG_R9D,  X86_REG_R9W,  X86_REG_R9B }},
        {{ X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B }},
        {{ X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B }},
        {{ X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B }},
        {{ X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B }},
        {{ X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B }},
        {{ X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B }},
    };
    for (uint8_t i = 0; i < 16; i++) {
        for (int k = 0; k < 4; k++) {
            if (map[i].r[k] == r)
                return i;
        }
    }
    return FATHOM_REG_NONE;
}

static uint8_t arm64_gpr(unsigned r, uint8_t *width)
{
    *width = 8;
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
        return (uint8_t)(r - ARM64_REG_X0);
    if (r == ARM64_REG_X29)
        return 29;
    if (r == ARM64_REG_X30)
        return 30;
    if (r == ARM64_REG_SP)
        return 31;
    if (r == ARM64_REG_XZR)
        return FATHOM_REG_ZERO;
    *width = 4;
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
        return (uint8_t)(r - ARM64_REG_W0);
    if (r == ARM64_REG_WSP)
        return 31;
    if (r == ARM64_REG_WZR)
        return FATHOM_REG_ZERO;
    return FATHOM_REG_NONE;
}

static bool x86_operand(const cs_insn *ci, const cs_x86_op *op, fathom_operand_t *out)
{
    memset(out, 0, sizeof(*out));
    out->index = FATHOM_REG_NONE;
    if (op->type == X86_OP_REG) {
        out->reg = x86_gpr(op->reg);
        return out->reg != FATHOM_REG_NONE;
    }
    if (op->type != X86_OP_MEM || op->mem.segment != X86_REG_INVALID)
        return false;
    out->mem = true;
    out->scale = (uint8_t)op->mem.scale;
    out->disp = op->mem.disp;
    if (op->mem.base == X86_REG_RIP) {
        out->pc_rel = true;
        out->reg = FATHOM_REG_NONE;
        out->disp = (int64_t)(ci->address + ci->size) + op->mem.disp;
    } else if (op->mem.base == X86_REG_INVALID) {
        out->reg = FATHOM_REG_NONE;
    } else if ((out->reg = x86_gpr(op->mem.base)) == FATHOM_REG_NONE) {
        return false;
    }
    if (op->mem.index != X86_REG_INVALID &&
        (out->index = x86_gpr(op->mem.index)) == FATHOM_REG_NONE)
        return false;
    return !out->pc_rel || out->index == FATHOM_REG_NONE;
}

/* Decode the two compared operands of a register/memory compare. */
static bool decode_compare(const cs_insn *ci, fathom_arch_t arch, fathom_cmp_site_t *site)
{
    if (arch == FATHOM_ARCH_X86_64) {
        const cs_x86 *x = &ci->detail->x86;
        if (strcmp(ci->mnemonic, "cmp") != 0 || x->op_count != 2 ||
            x->operands[0].type == X86_OP_IMM || x->operands[1].type == X86_OP_IMM)
            return false;
        site->width = x->operands[0].size;
        return site->width > 0 && site->width <= 8 &&
               x86_operand(ci, &x->operands[0], &site->a) &&
               x86_operand(ci, &x->operands[1], &site->b);
    }

    const cs_arm64 *a = A64(ci->detail);
    const char *m = ci->mnemonic;
    /* cmn/adds compare against a negation; only the plain forms are logged. */
    if (strcmp(m, "cmp") != 0 && strcmp(m, "subs") != 0 && strcmp(m, "ccmp") != 0)
        return false;
    uint8_t first = strcmp(m, "subs") == 0 ? 1 : 0;   /* subs has a destination */
    if (a->op_count < first + 2)
        return false;
    const cs_arm64_op *o1 = &a->operands[first], *o2 = &a->operands[first + 1];
    if (o1->type != ARM64_OP_REG || o2->type != ARM64_OP_REG ||
        o2->shift.type != ARM64_SFT_INVALID || o2->ext != ARM64_EXT_INVALID)
        return false;
    uint8_t w1, w2;
    memset(&site->a, 0, sizeof(site->a));
    memset(&site->b, 0, sizeof(site->b));
    site->a.index = site->b.index = FATHOM_REG_NONE;
    site->a.reg = arm64_gpr(o1->reg, &w1);
    site->b.reg = arm64_gpr(o2->reg, &w2);
    site->width = w1;
    return site->a.reg != FATHOM_REG_NONE && site->b.reg != FATHOM_REG_NONE && w1 == w2;
}

static const char *const bytes_funcs[][2] = {
    /* name, whether the third argument is the length */
    { "memcmp", "n" }, { "bcmp", "n" }, { "strncmp", "n" }, { "strncasecmp", "n" },
    { "strcmp", "" }, { "strcasecmp", "" }, { "__memcmp_chk", "n" },
};

static bool decode_bytes_call(const fathom_binary_t *bin, const fathom_disasm_t *dis,
                              const fathom_insn_t *insn, fathom_cmp_site_t *site)
{
    const char *name = fathom_resolve_call(bin, dis, insn);
    if (!name)
        return false;
    for (size_t i = 0; i < sizeof(bytes_funcs) / sizeof(bytes_funcs[0]); i++) {
        if (strcmp(name, bytes_funcs[i][0]) != 0)
            continue;
        /* First three integer arguments by calling convention. */
        uint8_t args[3] = { 0, 1, 2 };                       /* arm64: x0, x1, x2 */
        if (bin->arch == FATHOM_ARCH_X86_64 && bin->format == FATHOM_FMT_PE) {
            args[0] = 1; args[1] = 2; args[2] = 8;           /* Win64: rcx, rdx, r8 */
        } else if (bin->arch == FATHOM_ARCH_X86_64) {
            args[0] = 7; args[1] = 6; args[2] = 2;           /* SysV: rdi, rsi, rdx */
        }
        memset(site, 0, sizeof(*site));
        site->kind = FATHOM_CMP_BYTES;
        site->a.reg = args[0];
        site->b.reg = args[1];
        site->a.index = site->b.index = FATHOM_REG_NONE;
        site->len_reg = bytes_funcs[i][1][0] ? args[2] : FATHOM_REG_NONE;
        return true;
    }
    return false;
}

static const uint8_t *code_bytes(const fathom_binary_t *bin, uint64_t addr, size_t len)
{
    for (size_t i = 0; i < bin->section_count; i++) {
        const fathom_section_t *s = &bin->sections[i];
        if ((s->flags & FATHOM_SEC_CODE) && addr >= s->addr && addr - s->addr + len <= s->size)
            return bin->image + s->offset + (addr - s->addr);
    }
    return NULL;
}

long fathom_cmp_sites(const fathom_binary_t *bin, const fathom_disasm_t *dis,
                      const fathom_cfg_t *cfg, const uint32_t *blocks, size_t nblocks,
                      fathom_cmp_site_t **out)
{
    *out = NULL;
    csh handle;
    cs_arch arch = bin->arch == FATHOM_ARCH_ARM64 ? A64_ARCH : CS_ARCH_X86;
    cs_mode mode = bin->arch == FATHOM_ARCH_ARM64 ? CS_MODE_LITTLE_ENDIAN : CS_MODE_64;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *ci = cs_malloc(handle);
    fathom_cmp_site_t *sites = malloc(FATHOM_MAX_CMP_SITES * sizeof(*sites));
    long n = 0;
    if (!ci || !sites) {
        n = -1;
        goto done;
    }

    for (size_t bi = 0; bi < nblocks && n < FATHOM_MAX_CMP_SITES; bi++) {
        const fathom_block_t *b = &cfg->blocks[blocks[bi]];
        for (size_t k = 0; k < b->insn_count && n < FATHOM_MAX_CMP_SITES; k++) {
            const fathom_insn_t *insn = &dis->insns[b->insn_start + k];
            fathom_cmp_site_t site;
            memset(&site, 0, sizeof(site));
            if (insn->kind == FATHOM_INSN_CALL) {
                if (!decode_bytes_call(bin, dis, insn, &site))
                    continue;
            } else {
                /* decode_compare rejects immediates (already dictionary tokens). */
                if (strcmp(insn->mnemonic, "cmp") != 0 && strcmp(insn->mnemonic, "subs") != 0 &&
                    strcmp(insn->mnemonic, "ccmp") != 0)
                    continue;
                const uint8_t *code = code_bytes(bin, insn->addr, insn->size);
                size_t left = insn->size;
                uint64_t addr = insn->addr;
                if (!code || !cs_disasm_iter(handle, &code, &left, &addr, ci) ||
                    !decode_compare(ci, bin->arch, &site))
                    continue;
                site.kind = FATHOM_CMP_VALUES;
            }
            site.addr = insn->addr;
            sites[n++] = site;
        }
    }

done:
    if (ci)
        cs_free(ci, 1);
    cs_close(&handle);
    if (n <= 0) {
        free(sites);
        return n;
    }
    *out = sites;
    return n;
}
