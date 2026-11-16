# Changelog

## 0.3.0

### Breaking changes

- `fathom_cfg_build` takes the binary as a third argument (`NULL` keeps
  the old behaviour); the entry point, function symbols and taken code
  addresses now start blocks.
- `FATHOM_MAP_SIZE` is gone: `fathom_coverage_init` takes the number of
  slots, normally the breakpoint count.
- Public structures grew fields: `fathom_insn_t`, `fathom_input_t`,
  `fathom_corpus_t`, `fathom_coverage_t` and `fathom_config_t`. Code that
  builds them must zero-initialise them.
- `fathom_mutation_t` has three more strategies before
  `FATHOM_MUT_COUNT`.
- Running again with the same `-o` resumes that directory instead of
  overwriting it.

### Fixed

- Crash deduplication no longer stops fuzzing after 3,072 unique crashes.
- Data embedded in code sections is no longer instrumented; only code
  addresses a program takes (`lea`, `adr`) count as code roots.
- Large binaries keep every reachable block instead of the 65,536
  lowest-addressed ones.
- Mach-O load commands are read within `cmdsize` and `sizeofcmds`.
- Executor:
  - a block that starts with a trap instruction is the target's, not a
    breakpoint;
  - a failed restore is an executor error, not a hang or a fake crash;
  - breakpoints are written in clusters, so gaps between sections are
    never touched;
  - faults the target recovers from in its own handler are not crashes;
  - library crashes are deduplicated by module and offset;
  - forked children are covered (Linux keeps them traced, macOS services
    them on the inherited exception port) and nothing the target starts,
    including `setsid` daemons, outlives a run;
  - a target that re-executes itself stays instrumented;
  - macOS attributes a crash to the faulting thread;
  - Windows passes breakpoints it does not own to the target.
- Empty seeds are mutated.
- Seeded runs (`-s`) stay reproducible.
- Leaks, a NULL `qsort` and a deprecated `sprintf` found by the
  sanitizers.

### Added

- Scheduling: seeds run unmutated first; favored inputs (the cheapest
  per block) get most of the fuzzing; each pick gets an energy from
  speed, coverage, static score, freshness and distance to uncovered
  high-scoring blocks.
- Mutations: insert, delete and clone; 8- to 64-bit values in either
  byte order; comparison constants in both byte orders; an opt-in
  deterministic stage (`--det`).
- Loop headers count their iterations (up to 8) as coverage.
- Covered blocks are disarmed, so most runs only trap on new blocks.
- Switch jump tables are decoded into edges for x86-64 and arm64.
- Comparison logging: register, memory and `memcmp`/`strcmp` comparisons
  are probed at run time and solved input-to-state (`--no-cmplog` turns
  it off).
- `@@` passes the input as a file path.
- `--lib` instruments shared libraries the target loads.
- `--fork-server` (Linux) forks every run from the target stopped at its
  entry point.
- Saved hangs, `.txt` crash reports, `--replay` and `--minimize`.
- Live `fuzzer_stats`, `-v` coverage gains, `--max-execs`, `--max-input`,
  `--fail-on-crash`, `--version`, opt-in `--trim`.
- Parallel workers share their queues, deduplicate crashes across
  workers and stop together under `--until-crash`.
- `tests/bench.sh` and benchmark targets; CI runs the unit tests under
  ASan and UBSan and checks `make install`.
