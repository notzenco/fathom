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
3. Every instrumentable block start is overwritten with a breakpoint
   instruction (`int3`, or `brk` on arm64), written in clusters of
   breakpoints at most a page apart so gaps between sections are never
   touched. A block whose own first instruction is already that trap is
   left alone: its trap belongs to the target.
4. When a breakpoint fires, its block is marked in the coverage map, the
   original bytes are restored, and the target resumes. Each breakpoint
   fires at most once per run, so after warm-up the target runs at native
   speed. On macOS breakpoints are serviced on a Mach exception port
   rather than through ptrace stops.
5. While fuzzing, blocks that are already covered are left unpatched, so
   most runs trap only on blocks nothing has reached yet. A run that does
   reach one is repeated with every breakpoint in place to record its
   full path.
6. Loop headers are the exception: a temporary breakpoint on the header's
   second instruction re-arms the header once its first instruction has
   run, up to 8 times per run. The iteration count lands in AFL-style
   buckets (1, 2, 3, 4-7, 8+), so an input that runs a loop a different
   number of times counts as new coverage.

Processes the target starts are handled too. On Linux a vfork child is
traced like a thread, and a forked child gets its original code back and
runs uninstrumented. On macOS forked children inherit the exception port,
so their breakpoints are serviced and count as coverage. A target that
re-executes itself is instrumented again; one that execs another program
runs it uninstrumented. Every run ends by killing the target's process
group (a job object on Windows), so nothing it started outlives the run.

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
  `subs w8, w8, #0x46`) in both byte orders, which random mutation rarely
  guesses.
- **Frontier tokens**: during fuzzing, constants compared in covered
  blocks whose branch still has an uncovered side, favouring blocks
  reached most recently. This keeps a statically linked runtime's
  comparisons from drowning out the target's.
- **Jump tables**: the indirect jump of a dense `switch` gets an edge to
  every case, decoded from the table for x86-64 (PIC relative and no-PIE
  absolute) and arm64 (scaled byte, halfword and word entries). Without
  this, case blocks would be unreachable and uninstrumented.
- **CFG** with back-edge (loop) detection and immediate dominators.

## Fuzzing

- Seeds are run unmutated first: their coverage seeds the map, and seeds
  that crash (saved as crashes) or time out are dropped.
- AFL-style scheduling: each block's smallest, fastest input is
  *favored*, and a greedy subset of favored inputs covering every reached
  block gets nearly all the fuzzing. Each pick gets a number of mutated
  runs (its energy) that grows with speed, coverage, static score and
  freshness, and with how close the input gets to uncovered high-scoring
  blocks: each covered block is worth the score of the best uncovered
  scored block it can reach, halved per CFG edge (directed fuzzing in the
  style of AFLGo, using the static scores as targets).
- `--trim` shrinks queue inputs while they reach the same blocks. It is
  off by default because breakpoints cannot see loop counts, so trimming
  would cut inputs below the length an overflow needs.
- Ten mutation strategies (bitflip, byteflip, arithmetic, interesting
  values, dictionary, havoc, splice, insert, delete, clone) with adaptive
  weights: a strategy that finds new coverage is boosted 2x, and all
  weights decay by 0.95x. Arithmetic and interesting values use 8- to
  64-bit widths in either byte order, insert and delete change the length,
  and havoc stacks all of them.
- Seedable xorshift PRNG (`-s`), so runs are reproducible.
- Crash deduplication by FNV-1a hash of the crash PC and the frame-pointer
  return chain. Main-image addresses count at their link-time value and
  library addresses as module path plus offset, so the same bug hashes the
  same way across ASLR runs. Addresses in no module are ignored, so a
  smashed stack does not turn one bug into hundreds of "unique" crashes.
- Faults the target recovers from in its own handler (`sigsetjmp`, SEH,
  vectored handlers) are not crashes. A fault counts if the target dies
  from it, faults again at the same place, or then exits non-zero.
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

Input reaches the target on stdin, or as a file whose path replaces
every @@ in target_args (then stdin is empty).

Options:
  -i <dir>    Input corpus (seeds)
  -o <dir>    Output directory (default: ./fathom-out)
  -t <ms>     Timeout per exec (default: 1000)
  -j <n>      Parallel instances (default: 1)
  -T <secs>   Stop after this many seconds (default: run until Ctrl-C)
  -s <seed>   Random seed, for reproducible runs
  --until-crash  Stop after the first unique crash
  --trim      Shrink queue inputs that keep the same blocks (off by
              default: coverage cannot see loop counts)
  -a          Analysis-only mode (print CFG + scores, no fuzzing)
  -v          Verbose output
  --dict <f>  Extra dictionary file
  -h          Show this help
```

Input reaches the target on stdin, or as a file: every `@@` in the
target's arguments (also inside one, as in `--input=@@`) is replaced by
the path of a file holding the input, and stdin is then empty:

```sh
./fathom -i seeds -o out -- ./parser --strict @@
```

The output directory holds `queue/`
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
  maze, a hanging target, and targets that fork, re-exec themselves,
  recover from a fault, or start a block with a trap instruction.
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
  which blocks ran, not in which order. Only loop headers count how often
  they ran, up to 8 times per run.
- **One process launch per input.** There is no fork server or persistent
  mode, so throughput is bounded by process creation, which is slowest on
  Windows. On macOS, `task_for_pid()` adds roughly 10 ms per run unless
  fathom runs as root.
- **64-bit only.** 32-bit x86/ARM and big-endian targets are rejected.
- Code reached only through indirect jumps other than recognised jump
  tables (function pointers stored in data, computed gotos) is left
  uninstrumented.
- Descendants that leave the target's process group (`setsid`) are not
  killed at the end of a run. On Linux, forked children are not covered.

## License

MIT, see [LICENSE](LICENSE).
