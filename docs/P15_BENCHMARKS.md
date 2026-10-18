# P1.5 — Reproducible CLI benchmarks

## Scope

`scripts/benchmark_cli.py` measures an **entire invocation** of the compiled `rel-inspect analyze` command, including process creation, reading input, hashing, parsing and JSON printing. The benchmark does not execute the analyzed PE and has no access to Apex or its services.

Synthetic fixture: `fixtures/pe64-basic.exe` (2 KiB), with zero-filled overlay data to reach 1 MiB and 4 MiB. This tests the effect of total file size on hashing/I/O, **not** PE structural complexity. The report validates both input size and SHA-256 returned by the CLI each time.

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
