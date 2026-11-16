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
reach, or come close to, high-scoring blocks are fuzzed hardest. Values the
target compares its input against are read at run time and written back
into the input, which gets past magic numbers and string checks.

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
| macOS   | Mach-O, incl. universal | x86-64, arm64 | `ptrace`, Mach task and exception ports |
| Windows | PE32+         | x64, ARM64    | Win32 debug API |

Analysis mode (`-a`) reads any of the three formats on any host, so a
Linux machine can analyze a Windows `.exe`. Fuzzing needs a target that
runs natively on the host, so emulated targets are not supported
(x86-64 binaries under Rosetta 2 or Windows ARM64 emulation).

CI builds and tests all six OS and architecture combinations on native
runners. Runs and time for each to solve the maze target (below) from the
seed `AAAA`, from one CI run with `-s 1`; seeds and platforms vary, so
compare these within a row rather than across rows:

| Platform       | Runs to first crash | Time    |
|----------------|--------------------:|--------:|
| Linux x86-64   | 140                 | 0.08 s  |
| Linux arm64    | 598                 | 0.6 s   |
| macOS arm64    | 210                 | 0.7 s   |
| macOS x86-64   | 168                 | 1.8 s   |
| Windows ARM64  | 252                 | 6.7 s   |
| Windows x64    | 329                 | 5.6 s   |

Process creation dominates: Linux runs a few thousand targets a second
(more with `--fork-server` when startup is expensive), macOS under a
hundred without root (`task_for_pid()` costs about 10 ms), and Windows 30
to 50. On Windows the statically linked MinGW runtime also adds about 100
startup blocks to every run.

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

Processes the target starts are handled too. On Linux every fork, vfork
and thread is traced, and a breakpoint is restored in the memory of the
process that hit it; on macOS forked children inherit the exception port.
Either way their code counts as coverage. A target that re-executes
itself is instrumented again; one that execs another program runs it
uninstrumented. Every run ends by killing the target's process group and
also any descendant that left it with `setsid` (on Linux it is still
traced or was recorded when it exec'd; on macOS a process started during
the run that carries our exception port is one), or the job object on
Windows, so nothing the target started outlives the run.

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
- **Comparison logging** (input-to-state, as in RedQueen and AFL++'s
  CmpLog). The first time an input is fuzzed it runs once with a one-shot
  probe on every register or memory comparison (`cmp`, `subs`, `ccmp`)
  and every call to `memcmp`, `strcmp` and their relatives. Each probe
  records what was compared; wherever one side's bytes appear in the
  input, in either byte order and as narrower values, the other side
  (and its neighbours +-1) is written there and run. This finds magic
  values that `-O2` code loads into a register, which static extraction
  cannot see. `--no-cmplog` turns it off.
- `--det` adds AFL's deterministic stage: the first time an input of up
  to 256 bytes is fuzzed, every single-bit flip, byte +-1..16 and
  interesting 8/16/32-bit value (both byte orders) at every position is
  tried. It is off by default: with frontier tokens and comparison
  logging, random mutation usually gets there in fewer runs (the maze
  took 3-4x as many with it).
- `--trim` shrinks queue inputs while they reach the same blocks. It is
  off by default because breakpoints cannot see loop counts, so trimming
  would cut inputs below the length an overflow needs.
- Ten mutation strategies (bitflip, byteflip, arithmetic, interesting
  values, dictionary, havoc, splice, insert, delete, clone) with adaptive
  weights: a strategy that finds new coverage is boosted 2x, and all
  weights decay by 0.95x. Arithmetic and interesting values use 8- to
  64-bit widths in either byte order, insert and delete change the length,
  and havoc stacks all of them.
- Seedable xorshift PRNG (`-s`), so runs are reproducible: with a seed,
  scheduling also ignores run times, which vary from run to run.
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
- **Fork server** (`--fork-server`, Linux). The target starts once and
  stops at its entry point, after the dynamic loader. Each run injects a
  `fork` into that template, so execve and dynamic linking are paid once;
  the child starts from the entry point with the template's registers,
  breakpoints and file descriptors. It helps most where startup is
  expensive: a target linked against libcapstone ran 2.6x faster (3,455
  against 1,304 runs a second), while for a trivial target the extra
  ptrace round trips cost about as much as they save. It falls back to a
  fresh process per run if the template cannot be set up.
- **Shared libraries** (`--lib <path>`, repeatable). The library is
  analysed like the target and its blocks become extra coverage slots,
  with loop counts, comparison logging and dictionary tokens. Its
  breakpoints go in once it is mapped: on Linux and macOS when the
  target reaches its entry point (the loader has mapped its dependencies
  by then), on Windows as the DLL loads. A maze inside `libmaze` is
  solved in a few hundred runs with `--lib` and not at all without it.
  Libraries loaded later with `dlopen` are not covered.
- Parallel mode (`-j`) runs worker processes with sharded output
  directories. Every 10 seconds each worker runs the queue entries its
  peers added and keeps those that reach something new for it; a crash a
  peer already saved is not saved again; and with `--until-crash` the
  first worker to find one stops them all.

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

# A target that takes a file name, with its parser in a shared library
./fathom -i seeds -o out --lib ./libparse.so -- ./my_target --input @@
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

Input and output:
  -i <dir>           Seed inputs
  -o <dir>           Output directory, resumed if it already has a queue
                     (default: ./fathom-out)
  --dict <file>      Extra dictionary file
  --lib <path>       Also instrument this shared library the target loads
                     at startup (.so, .dylib, .dll); repeatable

Running:
  -t <ms>            Timeout per run (default: 1000)
  -j <n>             Parallel workers (default: 1)
  -T <secs>          Stop after this many seconds (default: until Ctrl-C)
  --max-execs <n>    Stop after n target runs
  --until-crash      Stop at the first unique crash
  --fail-on-crash    Exit with status 2 if any unique crash was found
  --fork-server      Linux: fork each run from the target stopped at its
                     entry point instead of starting it afresh

Fuzzing:
  -s <seed>          Random seed, for reproducible runs
  --max-input <n>    Largest input to generate, in bytes (default: 1048576)
  --no-cmplog        Skip comparison logging (input-to-state)
  --det              Try every deterministic edit (bit flips, small
                     arithmetic, interesting values) of new inputs up to
                     256 bytes
  --trim             Shrink queue inputs that keep the same blocks (off by
                     default: coverage cannot see loop counts)

Other modes:
  -a                 Analysis only: print the CFG summary and top blocks
  --replay <file>    Run one input and report the outcome (exit status
                     0 ok, 2 crash, 3 hang)
  --minimize <file>  Shrink a crashing input to <file>.min, keeping the crash
  -v                 Verbose: print every coverage gain
  --version          Show the version
  -h                 Show this help
```

Every `@@` in the target's arguments, also inside one as in
`--input=@@`, is replaced by the path of a file holding the input:

```sh
./fathom -i seeds -o out -- ./parser --strict @@
```

The output directory holds:

- `queue/`: inputs that found new coverage;
- `crashes/`: one input per unique crash, with a `.txt` report naming
  the signal or exception, the function it happened in, when it was found
  and the command that replays it;
- `hangs/`: inputs that timed out, one per distinct path, at most 256;
- `fuzzer_stats`, rewritten every second: executions and their rate,
  coverage, crashes, hangs, time to the first crash and to the last
  coverage gain, and how often each mutation strategy ran and found new
  coverage.

To look at a crash again, or shrink it to the bytes that matter:

```sh
./fathom --replay out/crashes/crash_<hash> -- ./target     # exit status 2: crashed
./fathom --minimize out/crashes/crash_<hash> -- ./target   # writes crash_<hash>.min
```

With `-j`, each worker writes to `out/worker-NNN/`.

Running again with the same `-o` resumes: the existing queue replaces the
seeds from `-i`, new queue entries are numbered after it, and crashes
already saved are not saved again.

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
bash tests/bench.sh 30 5   # time to crash per target: 30 s budget, 5 seeds
```

- **Unit tests** load prebuilt fixtures (`tests/fixtures/`: the same
  program compiled as ELF, Mach-O, universal Mach-O and PE for both
  architectures, plus a stripped gcc PIE), so every format is tested on
  every host. Analysis tests check jump tables, steering and frontier
  tokens on synthetic and compiled code. Executor tests run the real
  debugger backend against the maze, a hanging target, and targets that
  fork, `setsid`, re-exec themselves, recover from a fault, start a block
  with a trap instruction, read their input from a file, run a loop
  input-dependent times, compare against hidden magic values, or keep
  their logic in a shared library, and compare fork-server runs with
  fresh ones.
- **Benchmark** (`tests/bench.sh`): fuzzes each benchmark target from
  `AAAA` with several seeds and prints how many runs found the crash and
  the median time, executions, execution rate and coverage. Besides the
  test targets it covers known hard cases: a `memcmp` magic string, a
  big-endian length field, and an `-O2` comparison against a magic value
  kept in data, so it is never an immediate operand. Run it on two builds
  to compare them.
- **Integration tests** fuzz from a seed that contains none of the bytes
  the bugs need. The maze and the maze inside a shared library (`--lib`)
  must be solved on every platform, and with `--fork-server` on Linux.
  They also check replay and minimisation of the crash found, its report,
  `--fail-on-crash`, that hangs are not reported as crashes, that
  parallel workers shard their output, stop together and save a crash
  once, and that two runs with the same `-s` produce identical queues.

## Project structure

```
include/fathom.h            Public API
lib/
  binary.c                  Format detection, shared loader helpers
  fmt_elf.c                 ELF64 loader (sections, symbols, PLT/GOT imports)
  fmt_macho.c               Mach-O loader (universal slices, stubs, indirect symbols)
  fmt_pe.c                  PE32+ loader (sections, IAT imports, COFF symbols)
  disasm.c                  Capstone linear sweep, x86-64 + arm64 decoding, compare sites
  cfg.c                     Basic blocks, edges, loops, dominators
  analyze.c                 Import resolution, scoring, dictionary, reachability,
                            steering, frontier tokens
  mutate.c                  Mutation strategies, adaptive weights, deterministic stage
  trim.c                    Trimming and crash minimisation
  exec.c                    Breakpoint table, coverage marking, crash hashing
  exec_posix.c              Linux and macOS debugger backend
  exec_windows.c            Windows debugger backend
  coverage.c                Block coverage maps
  corpus.c                  Queue, scheduling, crash dedup
  osdep.c                   Small OS helpers (time, temp dir, entropy)
src/main.c                  CLI driver and parallel supervisor
tests/                      Unit tests, fixtures, targets, integration and
                            benchmark scripts
macos/fathom.entitlements   Debugger entitlement for task_for_pid
```

## Limitations

- **Block coverage, not edge coverage.** One-shot breakpoints record
  which blocks ran, not in which order. Only loop headers count how often
  they ran, up to 8 times per run.
- **One process launch per input**, except with `--fork-server` on Linux.
  There is no persistent mode, so throughput is bounded by process
  creation, which is slowest on Windows. On macOS, `task_for_pid()` adds
  roughly 10 ms per run unless fathom runs as root.
- **64-bit only.** 32-bit x86/ARM and big-endian targets are rejected.
- Code reached only through indirect jumps other than recognised jump
  tables (function pointers stored in data, computed gotos) is left
  uninstrumented.
- Coverage of forked children stops at an exec into another program.
- Only the target and the libraries named with `--lib` are instrumented,
  and only libraries loaded at startup; ones loaded later with `dlopen`
  are not covered.

## License

MIT, see [LICENSE](LICENSE).
