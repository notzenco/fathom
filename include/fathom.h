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
    /*
     * The instruction computes ref_target as a value (lea, adr, adrp+add)
     * instead of loading from or storing to it, so it may be a code
     * pointer.  Loads from code sections read data and are not code roots.
     */
    bool               ref_is_addr;
    /* x86 `jmp [table + index*8]`: the table of absolute targets, else 0. */
    uint64_t           jt_table;
    /* arm64: shift and sign extension applied to the last register operand. */
    uint8_t            op_shift;
    bool               op_sext;
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

/* ── Comparison sites (run-time comparison logging) ──────────────────── */

/*
 * General-purpose registers are numbered across architectures as:
 *   x86-64  0 rax, 1 rcx, 2 rdx, 3 rbx, 4 rsp, 5 rbp, 6 rsi, 7 rdi, 8-15 r8-r15
 *   arm64   0-30 x0-x30, 31 sp
 * and FATHOM_REG_ZERO reads as 0 (xzr/wzr).
 */
#define FATHOM_REG_COUNT  33
#define FATHOM_REG_ZERO   32
#define FATHOM_REG_NONE   0xff

typedef struct {
    bool     mem;        /* memory operand: [base + index*scale + disp] */
    uint8_t  reg;        /* the register, or the base register */
    uint8_t  index;      /* index register, or FATHOM_REG_NONE */
    uint8_t  scale;
    int64_t  disp;       /* for a PC-relative operand, the link-time address */
    bool     pc_rel;
} fathom_operand_t;

typedef enum {
    FATHOM_CMP_VALUES = 0,   /* cmp/subs of two registers or memory */
    FATHOM_CMP_BYTES,        /* memcmp/strcmp-style call: a and b point to the data */
} fathom_cmp_kind_t;

typedef struct {
    uint64_t          addr;      /* link-time address of the compare or call */
    fathom_cmp_kind_t kind;
    uint8_t           width;     /* VALUES: operand size in bytes */
    fathom_operand_t  a, b;      /* BYTES: registers holding the two pointers */
    uint8_t           len_reg;   /* BYTES: register holding the length, or NONE (C strings) */
} fathom_cmp_site_t;

/* What one comparison saw at run time: the bytes of both sides. */
#define FATHOM_CMP_MAX_BYTES 32
typedef struct {
    uint32_t site;
    uint8_t  len;                /* bytes valid in a and b */
    bool     bytes;              /* a BYTES site, else little-endian values */
    uint8_t  a[FATHOM_CMP_MAX_BYTES];
    uint8_t  b[FATHOM_CMP_MAX_BYTES];
} fathom_cmp_entry_t;

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
     * Sorted by address.
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
    FATHOM_MUT_INSERT,       /* insert random bytes or a copy of a chunk */
    FATHOM_MUT_DELETE,       /* delete a chunk */
    FATHOM_MUT_CLONE,        /* overwrite a chunk with a copy of another */
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
    size_t   size;         /* slots in each map */
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
    char    *path;           /* queue file, NULL without an output dir */

    /* Set by fathom_corpus_record once the input has been run as-is. */
    uint32_t *slots;         /* coverage slots it reaches, ascending */
    size_t    slot_count;
    uint64_t  trace_hash;    /* fathom_coverage_hash of that run */
    bool      trimmed;

    uint32_t  fuzz_count;    /* times picked for fuzzing */
    double    steer;         /* best fathom_steer value among its blocks */
    /*
     * Smallest and fastest input for some slot no other favored input
     * reaches; the scheduler mostly fuzzes these.  Inputs not yet run
     * as-is count as favored.
     */
    bool      favored;
} fathom_input_t;

typedef struct {
    fathom_input_t *inputs;
    size_t          count;
    size_t          capacity;
    size_t          current;
    const char     *out_dir;
    size_t          crash_count;
    size_t          unique_crashes;
    size_t          next_id;      /* queue file numbering */
    size_t          map_size;     /* coverage slots, from fathom_corpus_record */
    bool            cull_dirty;   /* favored set needs recomputing */
    uint64_t        rng;          /* scheduling randomness, see fathom_corpus_seed */
    bool            resumed;      /* loaded an existing queue instead of the seeds */
    /*
     * Schedule without run times, which vary between runs, so a seeded
     * run is reproducible: inputs are ranked by size alone.
     */
    bool            deterministic;
    size_t          unique_hangs;
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
/* Function symbol at or before addr, with addr's offset into it, or NULL. */
const char *fathom_symbol_near(const fathom_binary_t *bin, uint64_t addr, uint64_t *off);
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

/*
 * Comparison sites in the given blocks: register and memory compares
 * (immediates are already dictionary tokens) and calls to memcmp,
 * strcmp and their relatives.  *out is malloc'd; returns the count, or
 * -1 on error.
 */
#define FATHOM_MAX_CMP_SITES 4096
long fathom_cmp_sites(const fathom_binary_t *bin, const fathom_disasm_t *dis,
                      const fathom_cfg_t *cfg, const uint32_t *blocks, size_t nblocks,
                      fathom_cmp_site_t **out);

/* CFG */
/* bin may be NULL; when given, its entry point and function symbols start blocks. */
int  fathom_cfg_build(fathom_cfg_t *cfg, const fathom_disasm_t *dis,
                      const fathom_binary_t *bin);
void fathom_cfg_free(fathom_cfg_t *cfg);

/* Analysis */
int  fathom_analyze(fathom_analysis_t *ana, fathom_cfg_t *cfg,
                    const fathom_binary_t *bin, const fathom_disasm_t *dis);
void fathom_analysis_free(fathom_analysis_t *ana);
/*
 * Directed fuzzing: val[b] for every block is the score of the best
 * uncovered scored block reachable from b, halved per CFG edge between
 * them (up to FATHOM_STEER_DEPTH edges), else 0.  covered[b] marks
 * blocks already reached.
 */
#define FATHOM_STEER_DEPTH 8
/*
 * Frontier tokens: constants compared in covered blocks whose
 * conditional branch still has an uncovered side, the values most likely
 * to unlock new code.  Statically linked runtimes (MinGW, musl) bury the
 * target's own comparisons among hundreds of library ones whose startup
 * branches stay open forever, so blocks first reached in the latest two
 * coverage gains (epoch[slot] vs now) come first, and the whole frontier
 * only when those offer nothing.  global is the cumulative coverage map;
 * slot_block and block_slot map slots to CFG blocks and back (-1: none).
 */
void fathom_frontier(fathom_dict_t *out, const fathom_cfg_t *cfg,
                     const fathom_disasm_t *dis, const uint8_t *global, size_t slots,
                     const uint32_t *slot_block, const int32_t *block_slot,
                     const uint32_t *epoch, uint32_t now);
void fathom_steer(const fathom_cfg_t *cfg, const bool *covered, double *val);
void fathom_analysis_print(const fathom_analysis_t *ana,
                           const fathom_binary_t *bin,
                           const fathom_disasm_t *dis);
const char *fathom_resolve_call(const fathom_binary_t *bin,
                                const fathom_disasm_t *dis,
                                const fathom_insn_t *call);

/* Coverage */
/* size is the number of slots, normally the breakpoint count. */
int  fathom_coverage_init(fathom_coverage_t *cov, size_t size);
void fathom_coverage_destroy(fathom_coverage_t *cov);
void fathom_coverage_reset_local(fathom_coverage_t *cov);
bool fathom_coverage_has_new(fathom_coverage_t *cov);
void fathom_coverage_merge(fathom_coverage_t *cov);
/* Hash of which slots the last run reached, to compare two runs' paths. */
uint64_t fathom_coverage_hash(const fathom_coverage_t *cov);

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
/* Returns the coverage map slot for addr, or -1 on failure. */
int  fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr);
/*
 * Count how often slot's block runs, up to FATHOM_HIT_LIMIT per run, by
 * re-arming its breakpoint each time.  next_insn is the address of the
 * block's second instruction, where a temporary breakpoint re-arms the
 * first; the first instruction must fall through to it.
 */
#define FATHOM_HIT_LIMIT 8
/*
 * Leave slot's breakpoint out of later runs, or put it back.  Disarming
 * blocks that are already covered saves their traps; such runs report
 * only blocks still armed.
 */
void fathom_exec_arm(fathom_exec_t *ex, int slot, bool armed);
/*
 * Comparison logging: probe the compare at site->addr (an instruction
 * start that is not a loop-count breakpoint).  While armed, each probe
 * records what its comparison sees the first time it runs; the log is
 * reset at the start of every run.  Returns -1 if the site cannot be used.
 */
#define FATHOM_CMP_LOG_MAX 1024
int  fathom_exec_add_cmp_site(fathom_exec_t *ex, const fathom_cmp_site_t *site);
void fathom_exec_arm_cmp(fathom_exec_t *ex, bool armed);
size_t fathom_exec_cmp_log(const fathom_exec_t *ex, const fathom_cmp_entry_t **log);
int  fathom_exec_count_hits(fathom_exec_t *ex, int slot, uint64_t next_insn);

/*
 * Shrink buf by deleting chunks while its run still exits normally with
 * path want_hash (see fathom_coverage_hash).  Stops after max_execs runs
 * in total, counted in *execs.  Returns -1 if the executor fails.
 */
int  fathom_trim(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf,
                 size_t *len, uint64_t want_hash, uint32_t max_execs,
                 uint64_t *execs);

/*
 * Shrink a crashing input while it still crashes with crash_hash, first
 * by deleting chunks and then bytes.  Same budget rules as fathom_trim.
 */
int  fathom_minimize(fathom_exec_t *ex, fathom_coverage_t *cov, uint8_t *buf,
                     size_t *len, uint64_t crash_hash, uint32_t max_execs,
                     uint64_t *execs);

/* Corpus */
int  fathom_corpus_init(fathom_corpus_t *corpus, const char *input_dir,
                        const char *output_dir);
void fathom_corpus_destroy(fathom_corpus_t *corpus);
int  fathom_corpus_add(fathom_corpus_t *corpus, const uint8_t *data,
                       size_t len, size_t new_blocks, double score);
/*
 * Pick the next input to fuzz: unfuzzed favored inputs by priority, then
 * a cycle through the queue that mostly skips inputs that are not
 * favored.
 */
fathom_input_t *fathom_corpus_next(fathom_corpus_t *corpus);
void fathom_corpus_seed(fathom_corpus_t *corpus, uint64_t seed);
/* Record what running input idx unmutated covered and how long it took. */
int  fathom_corpus_record(fathom_corpus_t *corpus, size_t idx,
                          const fathom_coverage_t *cov, uint64_t exec_us);
/* Replace input idx's bytes (after trimming), rewriting its queue file. */
int  fathom_corpus_update(fathom_corpus_t *corpus, size_t idx,
                          const uint8_t *data, size_t len);
/* Drop input idx (a seed that crashes or hangs) and its queue file. */
void fathom_corpus_remove(fathom_corpus_t *corpus, size_t idx);
/*
 * Mutated executions to spend on input idx this pick: more for inputs
 * that are fast, reach many blocks, scored high in static analysis, lie
 * close to uncovered high-scoring blocks (steer) or have not been fuzzed
 * yet.
 */
uint32_t fathom_corpus_energy(const fathom_corpus_t *corpus, size_t idx);
int  fathom_corpus_save_crash(fathom_corpus_t *corpus, const uint8_t *data,
                              size_t len, uint64_t hash);
/*
 * Remember hash as seen without saving anything (another fuzzer already
 * saved it).  Returns 1 if it was new to this corpus.
 */
int  fathom_corpus_mark_crash(fathom_corpus_t *corpus, uint64_t hash);
/* Write text as crashes/crash_<hash>.txt, next to the crash's input. */
int  fathom_corpus_describe_crash(fathom_corpus_t *corpus, uint64_t hash, const char *text);
/*
 * Save a timed-out input as hangs/hang_<hash> unless that hash was seen
 * (hash: the path it took, see fathom_coverage_hash).  At most
 * FATHOM_MAX_HANGS are kept.  Returns 1 if saved, 0 if not, -1 on error.
 */
#define FATHOM_MAX_HANGS 256
int  fathom_corpus_save_hang(fathom_corpus_t *corpus, const uint8_t *data,
                             size_t len, uint64_t hash);

/* Dictionary */
void fathom_dict_init(fathom_dict_t *dict);
void fathom_dict_destroy(fathom_dict_t *dict);
int  fathom_dict_add(fathom_dict_t *dict, const uint8_t *data, size_t len);
int  fathom_dict_load(fathom_dict_t *dict, const char *path);
/* Add v as a 1/2/4/8-byte token, little- and big-endian, unless present.
 * Returns 1 if added, 0 if skipped (duplicate or trivial), -1 on error. */
int  fathom_dict_add_constant(fathom_dict_t *dict, int64_t v);

#endif /* FATHOM_H */
