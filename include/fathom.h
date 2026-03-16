/*
 * fathom.h — Public API for libfathom
 *
 * Hybrid coverage-guided fuzzer + static analysis tool for ELF binaries.
 */

#ifndef FATHOM_H
#define FATHOM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* ── Version ─────────────────────────────────────────────────────────── */

#define FATHOM_VERSION_MAJOR 0
#define FATHOM_VERSION_MINOR 1
#define FATHOM_VERSION_PATCH 0

/* ── Coverage bitmap ─────────────────────────────────────────────────── */

#define FATHOM_MAP_SIZE   (1 << 16)   /* 64 KB */

/* ── ELF types ───────────────────────────────────────────────────────── */

typedef struct {
    uint64_t addr;
    uint64_t size;
    uint64_t offset;       /* file offset */
    const char *name;
} fathom_section_t;

typedef struct {
    uint64_t addr;
    const char *name;
    uint8_t  type;         /* STT_FUNC, STT_OBJECT, etc. */
    uint8_t  bind;         /* STB_LOCAL, STB_GLOBAL, etc. */
    uint64_t size;
} fathom_symbol_t;

typedef struct {
    uint64_t  entry;       /* ELF entry point */
    uint8_t  *mapped;      /* mmap'd file contents */
    size_t    mapped_len;

    fathom_section_t  text;
    fathom_section_t  plt;
    fathom_section_t  rodata;

    fathom_symbol_t  *symbols;
    size_t            symbol_count;

    bool              stripped;
} fathom_elf_t;

/* ── Disassembler types ──────────────────────────────────────────────── */

typedef enum {
    FATHOM_INSN_OTHER = 0,
    FATHOM_INSN_BRANCH,      /* jmp, jcc */
    FATHOM_INSN_CALL,
    FATHOM_INSN_RET,
    FATHOM_INSN_SYSCALL,
} fathom_insn_kind_t;

typedef struct {
    uint64_t           addr;
    uint16_t           size;
    fathom_insn_kind_t kind;
    uint64_t           branch_target;  /* 0 if indirect/none */
    bool               is_conditional;
    char               mnemonic[16];
} fathom_insn_t;

typedef struct {
    fathom_insn_t *insns;
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
} fathom_mutator_t;

/* ── Coverage types ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t *local;       /* per-exec bitmap */
    uint8_t *global;      /* cumulative bitmap */
    int      shm_id;
    size_t   total_edges;
    size_t   new_edges;
    uint64_t prev_loc;
} fathom_coverage_t;

/* ── Corpus types ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    double   priority;
    bool     was_fuzzed;
    size_t   new_coverage;   /* edges discovered by this input */
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
    int           signal;
    uint64_t      crash_hash;
    uint64_t      exec_us;
} fathom_exec_result_t;

typedef struct {
    const char  *target_path;
    char *const *target_argv;
    uint32_t     timeout_ms;
    pid_t        fork_server_pid;
    bool         fork_server_up;
    int          ctl_pipe[2];
    int          st_pipe[2];

    uint64_t    *breakpoints;
    uint64_t    *bp_orig_bytes;
    size_t       bp_count;
    size_t       bp_capacity;
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

/* ELF */
int  fathom_elf_open(fathom_elf_t *elf, const char *path);
void fathom_elf_close(fathom_elf_t *elf);

/* Disassembly */
int  fathom_disasm_open(fathom_disasm_t *dis, const fathom_elf_t *elf);
void fathom_disasm_close(fathom_disasm_t *dis);

/* CFG */
int  fathom_cfg_build(fathom_cfg_t *cfg, const fathom_disasm_t *dis);
void fathom_cfg_free(fathom_cfg_t *cfg);

/* Analysis */
int  fathom_analyze(fathom_analysis_t *ana, fathom_cfg_t *cfg,
                    const fathom_elf_t *elf, const fathom_disasm_t *dis);
void fathom_analysis_free(fathom_analysis_t *ana);
void fathom_analysis_print(const fathom_analysis_t *ana,
                           const fathom_disasm_t *dis);

/* Coverage */
int  fathom_coverage_init(fathom_coverage_t *cov);
void fathom_coverage_destroy(fathom_coverage_t *cov);
void fathom_coverage_reset_local(fathom_coverage_t *cov);
bool fathom_coverage_has_new(fathom_coverage_t *cov);
void fathom_coverage_merge(fathom_coverage_t *cov);

/* Mutation */
void fathom_mutator_init(fathom_mutator_t *mut, fathom_dict_t *dict);
int  fathom_mutate(fathom_mutator_t *mut, uint8_t *buf, size_t *len,
                   size_t max_len, const uint8_t *splice, size_t splice_len);
void fathom_mutator_reward(fathom_mutator_t *mut, fathom_mutation_t which);

/* Executor */
int  fathom_exec_init(fathom_exec_t *ex, const fathom_config_t *cfg);
void fathom_exec_destroy(fathom_exec_t *ex);
int  fathom_exec_run(fathom_exec_t *ex, fathom_coverage_t *cov,
                     const uint8_t *input, size_t input_len,
                     fathom_exec_result_t *result);
int  fathom_exec_add_breakpoint(fathom_exec_t *ex, uint64_t addr);

/* Corpus */
int  fathom_corpus_init(fathom_corpus_t *corpus, const char *input_dir,
                        const char *output_dir);
void fathom_corpus_destroy(fathom_corpus_t *corpus);
int  fathom_corpus_add(fathom_corpus_t *corpus, const uint8_t *data,
                       size_t len, size_t new_edges);
fathom_input_t *fathom_corpus_next(fathom_corpus_t *corpus);
int  fathom_corpus_save_crash(fathom_corpus_t *corpus, const uint8_t *data,
                              size_t len, uint64_t hash);

/* Dictionary */
void fathom_dict_init(fathom_dict_t *dict);
void fathom_dict_destroy(fathom_dict_t *dict);
int  fathom_dict_add(fathom_dict_t *dict, const uint8_t *data, size_t len);
int  fathom_dict_load(fathom_dict_t *dict, const char *path);

#endif /* FATHOM_H */
