# Fathom

[![CI](https://github.com/notzenco/fathom/actions/workflows/ci.yml/badge.svg)](https://github.com/notzenco/fathom/actions/workflows/ci.yml)

A coverage-guided fuzzer for **uninstrumented** binaries, steered by static
analysis. Fathom fuzzes ELF, Mach-O and PE executables on Linux, macOS and
Windows, for x86-64 and arm64, without recompiling the target.

## What it does

Before fuzzing, Fathom disassembles the target, builds a control-flow graph
and scores every basic block: calls to dangerous functions (`memcpy`,
`strcpy`, `system`, ...), loop headers, error paths and complex branching.
It then runs the target under the operating system's debugger API with a
breakpoint on every reachable block, so each run reports which blocks
executed. Inputs that reach new blocks join the corpus, and inputs that
reach high-scoring blocks are fuzzed first.

```
binary ──► load ──► disassemble ──► CFG ──► score blocks ──► dictionary
                                                    │
         ┌──────────────────────────────────────────┘
         ▼
   pick input ──► mutate ──► run under debugger ──► new blocks? ──► corpus
         ▲                    (one-shot breakpoints)      │
         └────────────────────────────────────────────────┘
                                      crash? ──► dedupe ──► crashes/
```

## Platform support

| Host OS | Target format | Architectures | Debugger backend |
|---------|---------------|---------------|------------------|
| Linux   | ELF           | x86-64, arm64 | `ptrace`, `/proc/<pid>/mem` |
| macOS   | Mach-O, incl. universal | x86-64, arm64 | `ptrace` + Mach task port |
| Windows | PE32+         | x64, ARM64    | Win32 debug API |

Analysis mode (`-a`) reads any of the three formats on any host, so a
Linux machine can analyze a Windows `.exe`. Fuzzing needs a target that
runs natively on the host, so emulated targets are not supported
(x86-64 binaries under Rosetta 2 or Windows ARM64 emulation).

CI builds and tests all six OS and architecture combinations on native
runners. Time for each to solve the maze target (below) from the seed
`AAAA`, from one CI run with `-s 1`:

| Platform       | Runs to first crash | Time    |
|----------------|--------------------:|--------:|
| Linux x86-64   | 383                 | 0.4 s   |
| Linux arm64    | 203                 | 0.3 s   |
| macOS arm64    | 203                 | 0.9 s   |
| macOS x86-64   | 203                 | 2.4 s   |
| Windows ARM64  | 296                 | 10.0 s  |
| Windows x64    | 1,739               | 53.7 s  |

Process creation dominates: Linux runs roughly 1,000 targets a second,
macOS a few hundred, and Windows 30 to 40. On Windows the statically
linked MinGW runtime also adds about 100 startup blocks to every run.

## How coverage works without instrumentation

AFL-style fuzzers need the target recompiled with coverage hooks. Fathom
gets block coverage from the unmodified binary instead:

1. The target is started suspended under the debugger (`PTRACE_TRACEME`
   on Linux and macOS, `DEBUG_ONLY_THIS_PROCESS` on Windows).
2. The ASLR slide is read (Linux: `AT_ENTRY` from the aux vector; macOS:
   the executable's Mach-O header in the task; Windows: the image base in
   the process-creation event).
3. Every instrumentable block start is overwritten in one bulk write with
   a breakpoint instruction (`int3`, or `brk` on arm64).
4. When a breakpoint fires, its block is marked in the coverage map, the
   original bytes are restored, and the target resumes. Each breakpoint
   fires at most once per run, so after warm-up the target runs at native
   speed.

Breakpoints overwrite code, so they must land on real instruction
boundaries. Rather than trust every block found by linear sweep (which can
misread data embedded in code), Fathom only instruments blocks reachable
from the entry point, function symbols, direct call targets and code
addresses the program takes (such as `lea rdi, [rip+main]`, which is how
`_start` reaches `main` in a stripped binary).

## Static analysis

- **Import resolution** across PLT stubs (including `.plt.sec`), Mach-O
  `__stubs`, MinGW thunks and direct `call [rip+IAT]`, so calls into libc
  or the CRT are named even in stripped binaries.
- **Block scoring**, which feeds corpus priority:

  | Signal                          | Score  |
  |---------------------------------|--------|
  | Call to dangerous function      | +10.0  |
  | Loop header (back-edge target)  | +5.0   |
  | Error handling path             | +3.0   |
  | High fan-out (per extra edge)   | +2.0   |

- **Dictionary extraction**: printable strings from read-only data, plus
  the constants the code compares against (`cmp al, 0x46`,
  `subs w8, w8, #0x46`), which random mutation rarely guesses.
- **Frontier tokens**: during fuzzing, constants compared in covered
  blocks whose branch still has an uncovered side, favouring blocks
  reached most recently. This keeps a statically linked runtime's
  comparisons from drowning out the target's.
- **CFG** with back-edge (loop) detection and immediate dominators.

## Fuzzing

- Seven mutation strategies (bitflip, byteflip, arithmetic, interesting
  values, dictionary, havoc, splice) with adaptive weights: a strategy that
  finds new coverage is boosted 2x, and all weights decay by 0.95x.
- Seedable xorshift PRNG (`-s`), so runs are reproducible.
- Crash deduplication by FNV-1a hash of the crash PC and the frame-pointer
  return chain, using only link-time addresses inside the main image. The
  same bug hashes the same way across ASLR runs, and a smashed stack does
  not turn one bug into hundreds of "unique" crashes.
- Hangs are detected per run with a timeout (`-t`). Targets run in their
  own process group, so Ctrl-C and group signals are never miscounted as
  crashes.
- Parallel mode (`-j`) runs isolated worker processes with sharded output
  directories.

## Quick start

```sh
make                   # build fathom (signs it on macOS, see below)
make targets           # build the vulnerable test programs

# Static analysis only
./fathom -a -- tests/targets/maze

# Fuzz for up to two minutes, stopping at the first crash
mkdir seeds && printf 'AAAA' > seeds/a
./fathom -i seeds -o out -T 120 --until-crash -- tests/targets/maze

# Four parallel workers
./fathom -i seeds -o out -j 4 -- ./my_target
```

`tests/targets/maze` crashes only on input starting with `FUZZ`, each
byte checked in its own branch. Fuzzing from `AAAA`, Fathom solves it one
byte at a time. Without coverage feedback, all four bytes would have to be
guessed in a single mutation.

## CLI usage

```
Usage: fathom [options] -- /path/to/target [target_args...]

Options:
  -i <dir>    Input corpus (seeds)
  -o <dir>    Output directory (default: ./fathom-out)
  -t <ms>     Timeout per exec (default: 1000)
  -j <n>      Parallel instances (default: 1)
  -T <secs>   Stop after this many seconds (default: run until Ctrl-C)
  -s <seed>   Random seed, for reproducible runs
  --until-crash  Stop after the first unique crash
  -a          Analysis-only mode (print CFG + scores, no fuzzing)
  -v          Verbose output
  --dict <f>  Extra dictionary file
  -h          Show this help
```

Input reaches the target on stdin. The output directory holds `queue/`
(inputs that found new coverage), `crashes/` (one file per unique crash)
and `fuzzer_stats` (executions, coverage, crashes, hangs and time to first
crash). With `-j`, each worker writes to `out/worker-NNN/`.

## Building

Fathom is C11 with one dependency,
[Capstone](https://www.capstone-engine.org/) (tested with 4.0 and 5.0),
found through `pkg-config`.

**Linux**

```sh
sudo apt install libcapstone-dev pkg-config   # Debian/Ubuntu
make
```

**macOS**

```sh
brew install capstone pkg-config
make
```

`make` ad-hoc signs `fathom` with the `com.apple.security.cs.debugger`
entitlement (`macos/fathom.entitlements`), which `task_for_pid()` needs to
attach to targets. When not root, macOS asks for authorization the first
time (developer tools access); headless machines such as CI should run
fathom with `sudo`. Targets built with the hardened runtime and no
`get-task-allow` entitlement, which includes Apple's system binaries,
cannot be debugged.

**Windows** (MSYS2 UCRT64 for x64, CLANGARM64 for ARM64)

```sh
pacman -S make mingw-w64-ucrt-x86_64-cc mingw-w64-ucrt-x86_64-capstone mingw-w64-ucrt-x86_64-pkgconf
make
```

Other targets: `make test` (unit tests), `make targets` (test programs),
`DEBUG=1 make`, `ASAN=1 make`, `make install` (`PREFIX=/usr/local`).

The build produces `fathom`, the `libfathom.a` static library and its
public header `include/fathom.h`.

## Testing

```sh
make test                  # unit tests
bash tests/integration.sh  # end-to-end fuzzing
```

- **Unit tests** load prebuilt fixtures (`tests/fixtures/`: the same
  program compiled as ELF, Mach-O, universal Mach-O and PE for both
  architectures, plus a stripped gcc PIE), so every format is tested on
  every host. Executor tests run the real debugger backend against the
  maze and a hanging target.
- **Integration tests** fuzz from a seed that contains none of the bytes
  the bugs need. The maze must be solved on every platform. They also check
  that hangs are not reported as crashes and that parallel workers shard
  their output and exit cleanly.

## Project structure

```
include/fathom.h            Public API
lib/
  binary.c                  Format detection, shared loader helpers
  fmt_elf.c                 ELF64 loader (sections, symbols, PLT/GOT imports)
  fmt_macho.c               Mach-O loader (universal slices, stubs, indirect symbols)
  fmt_pe.c                  PE32+ loader (sections, IAT imports, COFF symbols)
  disasm.c                  Capstone linear sweep, x86-64 + arm64 decoding
  cfg.c                     Basic blocks, edges, loops, dominators
  analyze.c                 Import resolution, scoring, dictionary, reachability
  mutate.c                  Mutation strategies and adaptive weights
  exec.c                    Breakpoint table, coverage marking, crash hashing
  exec_posix.c              Linux and macOS debugger backend
  exec_windows.c            Windows debugger backend
  coverage.c                Block coverage maps
  corpus.c                  Queue, scheduling, crash dedup
  osdep.c                   Small OS helpers (time, temp dir, entropy)
src/main.c                  CLI driver and parallel supervisor
tests/                      Unit tests, fixtures, targets, integration script
macos/fathom.entitlements   Debugger entitlement for task_for_pid
```

## Limitations

- **Block coverage, not edge coverage.** One-shot breakpoints record
  which blocks ran, not how often or in which order.
- **One process launch per input.** There is no fork server or persistent
  mode, so throughput is bounded by process creation, which is slowest on
  Windows. On macOS, `task_for_pid()` adds roughly 10 ms per run unless
  fathom runs as root.
- **Inputs arrive on stdin only.** File-path (`@@`) delivery is not
  implemented.
- **64-bit only.** 32-bit x86/ARM and big-endian targets are rejected.
- Linear-sweep disassembly can miss code reached only through indirect
  jumps; those blocks are left uninstrumented.

## License

MIT, see [LICENSE](LICENSE).
