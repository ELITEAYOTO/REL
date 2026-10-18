# P1.5-A — First cross-platform RSS/CPU observations

**Status:** sampling harness verified on Windows/Ubuntu in [PR #19](https://github.com/ELITEAYOTO/REL/pull/19) and [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706). This is a **measurement only**, not a resource limit or sandbox. This is a **measurement only**, not a resource limit or a sandbox.

## Why this step

REL previously measured overall CLI wall time on synthetic PE input sizes, not RAM/CPU. The 512 MiB byte-read ceiling and 16 MiB JSON report ceiling **do not bound** parser allocations, peak resident memory, CPU usage, or time. Before imposing a hard threshold, we need repeatable observations from the *actual compiled CLI*.

## Independent harness

`scripts/profile_resources.py` is a standalone Python profiler; it does not change Rust modules, public JSON schemas or CLI arguments.

- Only executes `rel-inspect analyze`. The PE fixture is **never executed**.
- Launches the child process using `psutil.Popen`; samples the child's RSS and cumulative user+system CPU time at a nominal **2 ms** interval.
- Uses temporary files for stdout/stderr to prevent pipe deadlocks; checks the resulting manifest's SHA-256 and declared size against the source bytes.
- Measures elapsed wall time per process; terminates a run that exceeds **30 seconds** and returns an error.
- Controlled corpus: hash-validated 2 KiB PE32 and PE64 synthetic seeds and zero-filled overlays at 1 MiB and 4 MiB for each architecture. On Windows additionally inspects the locally compiled REL Release EXE and the separate CI-built MSVC x64 probe and candidate Clang-cl x64 build from the same tracked C source. See [corpus provenance](security/P15A_CORPUS_PROVENANCE.md).
- Performs one warmup and five measured executions per scenario; stores **all measurements**, medians, maximum observed RSS/CPU and environment information.
- Pins `psutil==7.0.0` **in CI** and uploads `rel-resources.json` as a per-platform artifact. Local use may require installing this version explicitly.

## Reproduce

```bash
cargo build --locked --release -p rel-inspect
python -m pip install psutil==7.0.0
python scripts/profile_resources.py --binary target/release/rel-inspect --samples 5 --warmup 1 --output rel-resources.json
```

Windows binary: `target/release/rel-inspect.exe`. Output-file creation refuses silent overwrites. This script is a profiling convenience, not a security boundary.

## Interpretation limitations

- **Sampled peak RSS is an underestimate of the true peak**: allocations between samples may go unseen, particularly for tiny files. If all observations miss the child, the field is `null`, not 0.
- `last_sampled_cpu_ms` is not a perfect final process CPU total; short-lived jobs may exit between samples. Process startup, I/O, hashing, parse, and serialization are included.
- The nominal 2 ms poll cadence is not guaranteed; runner scheduling differs by OS. Report CPU/RSS as observations, **not guaranteed upper bounds**.
- Hosted GitHub runners vary in hardware/load. Do not draw cross-run speedup conclusions or assert memory safety from these samples.
- Hash-validated PE32 and PE64 seeds and their zero-filled overlays exercise two architectures, file I/O and hashing, **not** complex import/resource/relocation tables. The CI-built Windows REL EXE and MSVC C probe add two genuine compiler-produced layouts but are not a representative cross-compiler corpus.
- The profiler's **own** CPU/RSS overhead is not included in child-process memory measurements; it contributes to observed wall time and runner load.
- The 30-second timeout applies to this profiling harness only. The REL CLI **does not yet enforce its own timeout, RSS ceiling, or process isolation**.

## Next engineering gates

1. Compare [per-platform resource artifacts from CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706) against future runs, noting runner hardware and short-lifetime sampling gaps.
2. Expand independent licensed PE corpus with meaningful structural complexity; measure resource percentiles/variance on stable hardware.
3. Define a justified policy for maximum input bytes, PE structural counts, output, and RAM/CPU budgets before enforcing numbers.
4. Evaluate worker-process boundaries with OS-specific limits and tests before accepting arbitrary hostile files.
5. Keep P1.5-A open until the required enforceable resource controls and path-race concerns are addressed.

See [ROADMAP](../ROADMAP.md), [alpha threats](security/THREAT_MODEL_ALPHA.md), [prior wall-clock benchmarks](P15_BENCHMARKS.md) and [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).

## Structured Windows PE resource/relocation cases (candidate)

When the CI provides the two new source-built Windows PE paths, this profiler includes 11 Windows scenarios rather than 9; Linux remains at 6. The source-built `.rsrc` and `.reloc` inputs are independently checked by pefile and then passed to REL **only as data**. Sampled RSS and CPU are observations, not hard ceilings or a claim that REL semantically decodes resources or relocations. Corpus licensing is unresolved. See [source and rights policy](security/P15A_CORPUS_PROVENANCE.md).

## Paired measurement evidence gate (PR candidate — CI pending)

The separate `scripts/check_measurement_evidence.py` cross-checks the **already generated** `rel-benchmark.json` and `rel-resources.json` of the **same CI OS job**. It requires identical case sets, exact source/binary fingerprints and provenance, consistent sample counts, wall-time medians and maximum sampled resources; it rejects duplicate cases, NaN/infinite values and malformed measurements. It does not call REL and it **never executes the inspected PE**.

Run on the reports generated in the same job:

```bash
python scripts/test_measurement_evidence.py
python scripts/check_measurement_evidence.py --benchmark rel-benchmark.json --resources rel-resources.json --expected-cases 6 --output rel-measurement-evidence.json
```

For Windows use `--expected-cases 11`. Both platforms upload `rel-measurement-evidence.json` as an additional artifact. The `rel-measurement-evidence-v1` contract is **only a Python QA observation artifact**, not a new REL native binary-manifest schema. It includes per-case `benchmark_relative_wall_spread`, RSS/CPU observed run counts and explicit missing-sample flags. Resource sampling missed during short child lifetimes must remain **missing**, never silently become zero.

Passing these checks only establishes *internal integrity of paired reports from one hosted runner job*. They do **not** calibrate CPU/RAM budgets, quantify true peak RSS, certify final CPU totals, ensure reproducibility across runner images, compare different CPUs fairly or create a sandbox. In particular, spread within five timing samples is descriptive, not a statistically validated performance regression threshold. Fixed-hardware repeated independent runs and licensed structurally diverse PEs remain open.
