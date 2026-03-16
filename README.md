# Fathom

A hybrid coverage-guided fuzzer with static analysis for x86-64 ELF binaries.

## What is Fathom

Fathom is a fuzzer that combines static binary analysis with coverage-guided
mutation testing. Before fuzzing begins, Fathom disassembles the target ELF
binary, builds a control flow graph, and scores basic blocks by
interestingness -- calls to dangerous libc functions, loop headers, error
handling paths, and complex branching. These scores drive breakpoint placement
and corpus prioritization during the fuzz loop.

Unlike AFL or honggfuzz, Fathom works directly on stripped, unmodified ELF
binaries. There is no need to recompile with instrumentation. Coverage is
tracked through an AFL-style shared memory bitmap, and crash deduplication uses
ptrace register reads and frame-pointer stack walks to produce stable hashes.

Fathom is implemented as a modular C library (`libfathom`) with a thin CLI
driver. The library exposes a clean API for ELF parsing, disassembly, CFG
construction, static analysis, mutation, execution, and coverage tracking, so
individual components can be embedded in other tools.

## Key Features

- **Static analysis-guided fuzzing** -- CFG analysis scores blocks and
  prioritizes exploration toward dangerous code paths
- **No recompilation required** -- works on stripped ELF binaries via ptrace
- **Dynamic breakpoint management** -- inserts and rotates INT3 breakpoints at
  high-value basic blocks using ptrace POKETEXT/PEEKTEXT
- **Adaptive mutation engine** -- 7 weighted strategies (bitflip, byteflip,
  arithmetic, interesting values, dictionary, havoc, splice) with automatic
  reward-based weight adjustment
- **Dictionary extraction** -- automatically harvests printable strings from
  `.rodata` for dictionary-based mutations
- **AFL-compatible coverage bitmap** -- 64 KB shared memory bitmap with
  hit-count bucketing
- **Crash deduplication** -- FNV-1a hashing of crash PC + frame-pointer stack
  walk
- **Modular library architecture** -- each subsystem (ELF, disasm, CFG,
  analysis, mutation, execution, coverage, corpus) is a separate compilation
  unit with a clean internal API

## Architecture

Fathom's pipeline has three phases:

```
ELF binary
    |
    v
[1] Static Analysis
    ELF parse --> disassemble (.text via Capstone) --> build CFG
    --> score blocks --> extract .rodata dictionary --> rank targets
    |
    v
[2] Fuzzer Setup
    init coverage bitmap (SysV shm) --> load seed corpus
    --> init mutator (with extracted dictionary)
    --> init executor --> set breakpoints at top-scored blocks
    |
    v
[3] Fuzz Loop
    pick seed --> mutate --> fork+exec target (ptrace)
    --> collect coverage --> check for new edges
    --> save interesting inputs / crashes --> repeat
```

The library (`libfathom.a`) contains all analysis and fuzzing logic. The CLI
driver (`src/main.c`) orchestrates the pipeline and handles argument parsing.

## Quick Start

```sh
# Build
make

# Analysis-only mode (print CFG scores, no fuzzing)
./fathom -a -- /path/to/binary

# Fuzz a target
mkdir seeds && echo "AAAA" > seeds/seed1
./fathom -i seeds/ -o output/ -- /path/to/target

# Run 4 sharded workers
./fathom -i seeds/ -o output/ -j 4 -- /path/to/target

# Build and fuzz the included test targets
make targets
./fathom -i tests/seeds/ -o output/ -- ./tests/targets/heap_overflow
```

## CLI Usage

```
Usage: fathom [options] -- /path/to/target [target_args...]

Options:
  -i <dir>    Input corpus (seeds)
  -o <dir>    Output directory (default: ./fathom-out)
  -t <ms>     Timeout per exec (default: 1000)
  -j <n>      Parallel instances (default: 1)
  -a          Analysis-only mode (print CFG + scores, no fuzzing)
  -v          Verbose output
  --dict <f>  Extra dictionary file
  -h          Show this help
```

The target binary and its arguments follow the `--` separator. Input is
delivered to the target via stdin from a temporary file.

For `-j > 1`, Fathom runs isolated worker processes and shards the output
directory by worker, for example `output/worker-000/queue/` and
`output/worker-000/crashes/`.

## Dependencies

- **[Capstone](https://www.capstone-engine.org/)** (>= 4.0) -- disassembly
  framework (MIT license). Install via your package manager:
  ```sh
  # Arch
  pacman -S capstone

  # Debian/Ubuntu
  apt install libcapstone-dev

  # Fedora
  dnf install capstone-devel
  ```
- **Linux** -- requires ptrace(2) for execution control and SysV shared memory
  (`shmget`/`shmat`) for the coverage bitmap
- **pkg-config** -- used by the Makefile to locate Capstone

## Building

```sh
# Standard build
make

# Debug build (no optimization, extra debug info)
DEBUG=1 make

# Build with AddressSanitizer + UBSan
ASAN=1 make

# Run unit tests
make test

# Build vulnerable test targets (compiled without protections)
make targets

# Install (default prefix: /usr/local)
make install

# Install to a custom prefix
PREFIX=/opt/fathom make install

# Clean
make clean
```

The build produces:
- `fathom` -- CLI binary
- `libfathom.a` -- static library
- `include/fathom.h` -- public API header

## Project Structure

```
fathom/
  include/
    fathom.h            Public API: types, constants, function declarations
  lib/
    elf.c / elf_internal.h      ELF64 parser (mmap, sections, symbols)
    disasm.c / disasm.h         x86-64 disassembler (Capstone wrapper)
    cfg.c / cfg.h               CFG builder (basic blocks, edges, dominators)
    analyze.c / analyze.h       Static analysis (block scoring, dictionary extraction)
    mutate.c / mutate.h         Mutation engine (7 strategies, adaptive weights)
    exec.c / exec.h             Target executor (fork+exec, ptrace, breakpoints)
    coverage.c / coverage.h     AFL-style shared memory coverage bitmap
    corpus.c / corpus.h         Seed queue, priority scheduling, crash dedup
  src/
    main.c              CLI driver (argument parsing, pipeline orchestration)
  tests/
    test_elf.c          Unit tests: ELF parser
    test_disasm.c       Unit tests: disassembler
    test_cfg.c          Unit tests: CFG builder
    test_corpus.c       Unit tests: corpus manager
    test_coverage.c     Unit tests: coverage bitmap
    test_mutate.c       Unit tests: mutation engine
    integration.sh      Integration test runner
    seeds/              Sample seed inputs for test targets
    targets/
      heap_overflow.c   Vulnerable test target: heap buffer overflow
      stack_smash.c     Vulnerable test target: stack buffer overflow
      format_string.c   Vulnerable test target: format string bug
  .gitignore
  Makefile
  LICENSE
  README.md
```

## Testing

```sh
# Unit tests (62 tests across 6 modules)
make test

# Integration tests (fuzzes vulnerable targets, verifies crash detection)
make targets
bash tests/integration.sh
```

The unit test suite covers: ELF parsing (9 tests), disassembly (1), CFG
construction (5), coverage bitmap (7), mutation engine (29), and corpus
management (11). Integration tests compile three intentionally vulnerable
binaries and verify Fathom can discover crashes within 30 seconds.

## How It Works

### Phase 1: Static Analysis

Fathom opens the target ELF binary and memory-maps it. It locates the `.text`,
`.plt`, and `.rodata` sections and extracts symbols (falling back to `.dynsym`
for stripped binaries). The `.text` section is disassembled into a linear
instruction stream using Capstone, then split into basic blocks by identifying
branch, call, and return boundaries.

The CFG builder connects blocks via fall-through and branch-target edges,
detects back-edges (loops), and computes immediate dominators. The analysis
pass then scores each block:

| Signal                          | Score  |
|---------------------------------|--------|
| Call to dangerous function      | +10.0  |
| Loop header (back-edge target)  | +5.0   |
| Error handling path             | +3.0   |
| High fan-out (per extra edge)   | +2.0   |

Dangerous functions include `memcpy`, `strcpy`, `sprintf`, `gets`, `malloc`,
`system`, `execve`, and others. Error functions include `abort`, `exit`,
`__assert_fail`, and `__stack_chk_fail`.

Printable strings from `.rodata` (>= 4 bytes) are extracted into a mutation
dictionary.

### Phase 2: Execution

Each fuzz iteration forks a child process that exec's the target with ptrace
`TRACEME`. The parent inserts INT3 breakpoints at the top-scored block
addresses via `PTRACE_POKETEXT`, then resumes the child. On breakpoint hit,
the parent restores the original byte, single-steps, and re-inserts the
breakpoint.

Crashes are detected by catching `SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGBUS`,
and `SIGILL` via the ptrace stop mechanism. The parent reads registers and
walks the frame-pointer chain to compute a stable crash hash.

Timeouts are enforced via `setitimer(ITIMER_REAL)` / `SIGALRM`.

### Phase 3: Mutation and Corpus Management

The mutation engine selects from 7 strategies using adaptive weights. When a
strategy discovers new coverage, its weight is boosted by 2x while all weights
decay by 0.95x, preventing starvation while favoring productive strategies.

The corpus manager maintains a priority queue of inputs sorted by coverage
contribution. New inputs that trigger previously unseen edges are added to the
queue. Crashes are deduplicated by hash and saved to the output directory. In
parallel mode, each worker keeps its own queue and crash directory shard.

## License

MIT -- see [LICENSE](LICENSE).
