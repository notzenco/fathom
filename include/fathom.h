/*
 * fathom.h — Public API for libfathom
 *
 * Coverage-guided fuzzer with static analysis for uninstrumented
 * x86-64 and ARM64 binaries (ELF, Mach-O and PE) on Linux, macOS and
 * Windows.
 */

#ifndef FATHOM_H
#define FATHOM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ── Version ─────────────────────────────────────────────────────────── */

#define FATHOM_VERSION_MAJOR 0
#define FATHOM_VERSION_MINOR 2
#define FATHOM_VERSION_PATCH 0

/* ── Coverage map ────────────────────────────────────────────────────── */

/* One byte per instrumented basic block; also caps the breakpoint count. */
#define FATHOM_MAP_SIZE   (1 << 16)

/* ── Binary image types ──────────────────────────────────────────────── */

typedef enum {
    FATHOM_FMT_UNKNOWN = 0,
    FATHOM_FMT_ELF,
    FATHOM_FMT_MACHO,
    FATHOM_FMT_PE,
} fathom_format_t;

typedef enum {
    FATHOM_ARCH_UNKNOWN = 0,
    FATHOM_ARCH_X86_64,
    FATHOM_ARCH_ARM64,
} fathom_arch_t;

#define FATHOM_SEC_CODE    0x1u   /* executable instructions */
#define FATHOM_SEC_RODATA  0x2u   /* read-only data (dictionary source) */

typedef struct {
    uint64_t addr;         /* link-time virtual address */
    uint64_t size;         /* bytes present in the file */
    uint64_t offset;       /* offset into fathom_binary_t.image */
    uint32_t flags;        /* FATHOM_SEC_* */
    char     name[40];     /* ".text", "__TEXT,__text", ... */
} fathom_section_t;

#define FATHOM_SYM_OTHER   0
#define FATHOM_SYM_FUNC    1
#define FATHOM_SYM_OBJECT  2

typedef struct {
    uint64_t addr;
    char    *name;
    uint8_t  type;         /* FATHOM_SYM_* */
    uint64_t size;
} fathom_symbol_t;

/*
 * An imported function, keyed by the address code uses to reach it:
 * a GOT/IAT/lazy-pointer slot, or a Mach-O stub.
 */
typedef struct {
    uint64_t addr;
    char    *name;
} fathom_import_t;

typedef struct {
    fathom_format_t format;
    fathom_arch_t   arch;

    uint8_t        *data;          /* whole file contents (owned) */
    size_t          data_len;
    const uint8_t  *image;         /* selected slice (fat Mach-O) or data */
    size_t          image_len;

    uint64_t        entry;         /* link-time entry point */
    uint64_t        image_base;    /* link-time load address */
    uint64_t        image_size;    /* bytes spanned once mapped */
    bool            relocatable;   /* PIE / ASLR-capable */

    fathom_section_t *sections;
    size_t            section_count;

    fathom_symbol_t  *symbols;
    size_t            symbol_count;
    bool              stripped;

    fathom_import_t  *imports;
    size_t            import_count;
} fathom_binary_t;

/* ── Disassembler types ──────────────────────────────────────────────── */

typedef enum {
    FATHOM_INSN_OTHER = 0,
    FATHOM_INSN_BRANCH,      /* jmp, jcc, b, b.cond, cbz, tbz, br */
    FATHOM_INSN_CALL,
    FATHOM_INSN_RET,
    FATHOM_INSN_SYSCALL,
} fathom_insn_kind_t;

typedef struct {
    uint64_t           addr;
    uint16_t           size;
    fathom_insn_kind_t kind;
    uint64_t           branch_target;  /* 0 if indirect/none */
    /*
     * Address computed PC-relatively by this instruction (x86 RIP-relative
     * operand, ARM64 adrp+add/ldr pair), or 0.  Used to resolve import
     * stubs and to find functions referenced only by address.
     */
    uint64_t           ref_target;
    int64_t            cmp_imm;        /* constant compared against, if has_cmp_imm */
    bool               has_cmp_imm;
    bool               is_conditional;
    char               mnemonic[16];
} fathom_insn_t;

typedef struct {
    fathom_arch_t  arch;
    fathom_insn_t *insns;      /* sorted by address */
    size_t         count;
} fathom_disasm_t;

/* ── CFG types ───────────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    uint64_t start_addr;
    uint64_t end_addr;      /* exclusive */
    size_t   insn_start;    /* index into disasm->insns */
    size_t   insn_count;

    uint32_t *succs;
    size_t    succ_count;
    uint32_t *preds;
    size_t    pred_count;

    bool     is_loop_header;
    int32_t  idom;          /* immediate dominator block id, -1 if none */
    double   score;         /* analysis score */
} fathom_block_t;

typedef struct {
    uint32_t from;
    uint32_t to;
    bool     is_back_edge;
} fathom_edge_t;

typedef struct {
    fathom_block_t *blocks;
    size_t          block_count;
    fathom_edge_t  *edges;
    size_t          edge_count;
} fathom_cfg_t;

/* ── Analysis types ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t  *data;
    size_t    len;
} fathom_dict_entry_t;

typedef struct {
    fathom_dict_entry_t *entries;
    size_t               count;
    size_t               capacity;
} fathom_dict_t;

typedef struct {
    fathom_cfg_t  *cfg;
    fathom_dict_t  dict;
    uint32_t      *ranked_blocks;   /* block ids sorted by score desc */
    size_t         ranked_count;
    /*
     * Blocks safe to instrument: reachable from the entry point, a
     * symbol, a call target or a code address the program takes.
     * Sorted by address, capped at FATHOM_MAP_SIZE.
     */
    uint32_t      *cov_blocks;
    size_t         cov_count;
} fathom_analysis_t;

/* ── Mutation types ──────────────────────────────────────────────────── */

typedef enum {
    FATHOM_MUT_BITFLIP = 0,
    FATHOM_MUT_BYTEFLIP,
    FATHOM_MUT_ARITH,
    FATHOM_MUT_INTERESTING,
    FATHOM_MUT_DICTIONARY,
    FATHOM_MUT_HAVOC,
    FATHOM_MUT_SPLICE,
    FATHOM_MUT_COUNT,
} fathom_mutation_t;

typedef struct {
    double weights[FATHOM_MUT_COUNT];
    uint64_t hits[FATHOM_MUT_COUNT];   /* new-coverage hits per strategy */
    uint64_t uses[FATHOM_MUT_COUNT];
    fathom_dict_t *dict;
    /*
     * Optional tokens from the coverage frontier: constants compared in
     * covered blocks whose branch still has an uncovered side.  Drawn
     * from half the time when non-empty.
     */
    fathom_dict_t *frontier;
    uint64_t rng;                      /* xorshift64* state, never 0 */
} fathom_mutator_t;

/* ── Coverage types ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t *local;        /* per-exec map: one byte per instrumented block */
    uint8_t *global;       /* cumulative map */
    size_t   total_blocks;
    size_t   new_blocks;
} fathom_coverage_t;

/* ── Corpus types ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    double   priority;
    bool     was_fuzzed;
    size_t   new_coverage;   /* blocks first reached by this input */
    uint64_t exec_us;        /* execution time in microseconds */
} fathom_input_t;

typedef struct {
    fathom_input_t *inputs;
    size_t          count;
    size_t          capacity;
    size_t          current;
    const char     *out_dir;
    size_t          crash_count;
    size_t          unique_crashes;
} fathom_corpus_t;

/* ── Executor types ──────────────────────────────────────────────────── */

typedef enum {
    FATHOM_EXIT_OK = 0,
    FATHOM_EXIT_CRASH,
    FATHOM_EXIT_HANG,
    FATHOM_EXIT_ERROR,
} fathom_exit_t;

typedef struct {
    fathom_exit_t status;
    /* POSIX signal number, or Windows exception code (NTSTATUS). */
    uint32_t      crash_code;
    uint64_t      crash_pc;      /* link-time address when inside the image */
    uint64_t      crash_hash;
    uint64_t      exec_us;
} fathom_exec_result_t;

struct fathom_exec_os;   /* per-platform debugger state */

typedef struct {
    const char  *target_path;
    char *const *target_argv;
    uint32_t     timeout_ms;

    fathom_arch_t arch;
    uint64_t     entry;          /* link-time entry, used to find the slide */
    uint64_t     image_base;
    uint64_t     image_size;

    /* Breakpoint i records coverage in map slot i. */
    uint64_t    *bp_addrs;       /* link-time addresses */
    size_t       bp_count;
    size_t       bp_capacity;

    struct fathom_exec_os *os;
} fathom_exec_t;

/* ── Top-level config ────────────────────────────────────────────────── */

typedef struct {
    const char  *target_path;
    char *const *target_argv;
    const char  *input_dir;
    const char  *output_dir;
    const char  *dict_file;
    uint32_t     timeout_ms;
    uint32_t     jobs;
    bool         analysis_only;
    bool         verbose;
} fathom_config_t;

/* ── Public API ──────────────────────────────────────────────────────── */

/* Binary images */
int  fathom_binary_open(fathom_binary_t *bin, const char *path);
void fathom_binary_close(fathom_binary_t *bin);
const fathom_section_t *fathom_binary_find_section(const fathom_binary_t *bin,
                                                   const char *name);
const char *fathom_import_at(const fathom_binary_t *bin, uint64_t addr);
const char *fathom_format_name(fathom_format_t fmt);
const char *fathom_arch_name(fathom_arch_t arch);
fathom_arch_t fathom_host_arch(void);

/* Disassembly */
int  fathom_disasm_open(fathom_disasm_t *dis, const fathom_binary_t *bin);
void fathom_disasm_close(fathom_disasm_t *dis);
size_t fathom_disasm_find(const fathom_disasm_t *dis, uint64_t addr);

/* CFG */
int  fathom_cfg_build(fathom_cfg_t *cfg, const fathom_disasm_t *dis);
void fathom_cfg_free(fathom_cfg_t *cfg);

/* Analysis */
int  fathom_analyze(fathom_analysis_t *ana, fathom_cfg_t *cfg,
                    const fathom_binary_t *bin, const fathom_disasm_t *dis);
void fathom_analysis_free(fathom_analysis_t *ana);
void fathom_analysis_print(const fathom_analysis_t *ana,
                           const fathom_binary_t *bin,
                           const fathom_disasm_t *dis);
const char *fathom_resolve_call(const fathom_binary_t *bin,
                                const fathom_disasm_t *dis,
                                const fathom_insn_t *call);

/* Coverage */
int  fathom_coverage_init(fathom_coverage_t *cov);
void fathom_coverage_destroy(fathom_coverage_t *cov);
void fathom_coverage_reset_local(fathom_coverage_t *cov);
bool fathom_coverage_has_new(fathom_coverage_t *cov);
void fathom_coverage_merge(fathom_coverage_t *cov);

/* Mutation */
void fathom_mutator_init(fathom_mutator_t *mut, fathom_dict_t *dict);
void fathom_mutator_seed(fathom_mutator_t *mut, uint64_t seed);
int  fathom_mutate(fathom_mutator_t *mut, uint8_t *buf, size_t *len,
                   size_t max_len, const uint8_t *splice, size_t splice_len);
void fathom_mutator_reward(fathom_mutator_t *mut, fathom_mutation_t which);
uint32_t fathom_rand_below(fathom_mutator_t *mut, uint32_t limit);

/* Executor */
int  fathom_exec_init(fathom_exec_t *ex, const fathom_config_t *cfg,
                      const fathom_binary_t *bin);
void fathom_exec_destroy(fathom_exec_t *ex);
int  fathom_exec_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                     const uint8_t *input, size_t input_len,
                     fathom_exec_result_t *result);
/* Returns the coverage map slot for addr, or -1 on failure / full map. */
int  fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr);

/* Corpus */
int  fathom_corpus_init(fathom_corpus_t *corpus, const char *input_dir,
                        const char *output_dir);
void fathom_corpus_destroy(fathom_corpus_t *corpus);
int  fathom_corpus_add(fathom_corpus_t *corpus, const uint8_t *data,
                       size_t len, size_t new_blocks, double score);
fathom_input_t *fathom_corpus_next(fathom_corpus_t *corpus);
int  fathom_corpus_save_crash(fathom_corpus_t *corpus, const uint8_t *data,
                              size_t len, uint64_t hash);

/* Dictionary */
void fathom_dict_init(fathom_dict_t *dict);
void fathom_dict_destroy(fathom_dict_t *dict);
int  fathom_dict_add(fathom_dict_t *dict, const uint8_t *data, size_t len);
int  fathom_dict_load(fathom_dict_t *dict, const char *path);
/* Add v as a 1/2/4/8-byte little-endian token unless already present.
 * Returns 1 if added, 0 if skipped (duplicate or trivial), -1 on error. */
int  fathom_dict_add_constant(fathom_dict_t *dict, int64_t v);

#endif /* FATHOM_H */
