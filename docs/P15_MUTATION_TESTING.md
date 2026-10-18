# P1.5 — Deterministic mutation regression

## Intent

Introduce repeatable negative tests against the public `rel-pe::inspect` parser without bringing in a fuzzing engine, UI or new runtime dependency.

## Exact cases

- Both original, synthetic 2048-byte PE32/PE32+ fixtures.
- Truncation every 17 bytes from length zero to 2048 (inclusive through intact sample).
- 512 fixed-seed mutations per fixture, comprising 1–12 byte XOR edits.
- Positions sampled across PE/COFF header, PE optional header, section headers, import/export data, and other file regions; roughly every seventh mutation is truncated.
- Each case requires `inspect` to return normally (either `Ok` or `Err`), never unwind.

The seeded xorshift64 generator is **not cryptographic** and is used solely for determinism. Passing these tests is **not evidence of comprehensive parser security**, complete PE support, or robustness on arbitrary files. This is neither coverage-guided fuzzing nor a substitute for libFuzzer/cargo-fuzz.

## Reproduce

```bash
cargo test --locked -p rel-pe --test mutation_regression -- --nocapture
```

Windows and Linux GitHub Actions also run this as part of the workspace test suite.

## What remains

- Coverage-guided fuzzing in a separate harness and a CI-compatible time budget.
- Detailed crash triage and minimized persistent regression samples.
- Independent reference PE binaries with verified redistribution rights.
- Time/memory profiling with a corpus that includes large and complex PE files.

See [P1 validation](P1_VALIDATION.md) for the currently verified P1 scope.
