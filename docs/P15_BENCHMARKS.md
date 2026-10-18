# P1.5 — Reproducible CLI benchmarks

## Scope

`scripts/benchmark_cli.py` measures an **entire invocation** of the compiled `rel-inspect analyze` command, including process creation, reading input, hashing, parsing and JSON printing. The benchmark does not execute the analyzed PE and has no access to Apex or its services.

Controlled fixtures: tracked, SHA-256-verified 2 KiB PE32 and PE64, each with generated zero-filled overlays to reach 1 MiB and 4 MiB; additionally the current CI-compiled Windows REL EXE and a CI-built MSVC x64 C probe on Windows. See [provenance policy](security/P15A_CORPUS_PROVENANCE.md). The padded scenarios test file size on hashing/I/O, **not** PE structural complexity. The MSVC-built probe and optional Clang-cl build exercise different C compiler frontends on Windows; they may share the linker/SDK and do not constitute a representative compiler corpus. Per-case stable identifiers and origins are included in result JSON. The report validates both input size and SHA-256 returned by the CLI each time.

The script performs two default warmups and nine timed iterations per size, recording every value, the median and a nearest-rank p95. No hard speed target is enforced: hosted CI runner performance varies.

## Commands

```bash
cargo build --locked --release -p rel-inspect
python scripts/benchmark_cli.py --binary target/release/rel-inspect --output benchmark.json
```

Windows uses `target/release/rel-inspect.exe`. By default the script prints a report to stdout; `--output` creates a new file and refuses to overwrite an existing one.

## Continuous integration

Windows and Ubuntu CI run a short benchmark after the main parser/CLI gates. A benchmark result is uploaded for each OS using GitHub Actions artifacts. Results are observational only, **not** performance regressions unless collected under comparable, controlled conditions.

## Limitations

- Process startup biases small samples; timings are not isolated parse CPU times.
- CI machines change; do not compare raw numbers as a speed-up claim.
- Allocations, CPU/RAM peaks and adversarial worst-case data are not measured here.
- Zero-filled overlay padding is not a substitute for genuine complex Windows executables.
- Formal performance budgeting and independent reference samples are still P1.5 tasks.

## Additional structured PE cases (candidate)

Windows CI can measure two more controlled source-built PE32+ files using independent MSVC and Clang-cl frontends plus a shared RC asset. A separate pinned pefile oracle checks RCDATA and DIR64 relocation entries without executing them. In the benchmark output, the two case IDs are `msvc-x64-structured` and `clang-cl-x64-structured`, with independent C/RC source hashes. These increase structural variety but still do not define representative CPU/RAM performance or license-cleared redistribution rights. See [corpus provenance](security/P15A_CORPUS_PROVENANCE.md).

## Paired timing/resource quality check (candidate)

CI cross-checks the five timing observations for each benchmark case against the corresponding sampled-resource case of the same OS job. The independent `rel-measurement-evidence-v1` output checks manifest identity, sample consistency and aggregate median/p95, and reports the **relative spread within the timing sample** `(max - min) / median`. This is an observational quality indicator, not a performance threshold or a reliable cross-run speed-up estimate. See [resource evidence policy](P15_RESOURCE_PROFILING.md).
