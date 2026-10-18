# P1 — Proof-driven validation

## Static-only scope

The input executable is never executed. The PE32/PE32+ fixtures are synthetic, authored for this project, and contain an inert dummy instruction. The fixture corpus is **not** evidence of suitability for every real-world Windows executable.

## Ground truth

- `fixtures/expected.json` lists the expected SHA-256, architecture, section names, imports and exports.
- Both binary fixtures are 2048-byte files built with fixed PE headers and deterministic import/export tables.
- `crates/rel-pe/tests/fixture_pe.rs` checks parser output and failure modes.
- `scripts/smoke_cli.py` runs the compiled CLI on both fixtures, validates JSON Schema, and tests output overwrite protection.
- `.github/workflows/ci.yml` runs both on Linux and Windows.

## Gates

1. Rust formatting, Clippy, unit/integration tests and release build pass on both operating systems.
2. Both generated fixture SHA-256 values match the registry.
3. A malformed file produces a nonzero status, not a crash.
4. A pre-existing report and the original binary cannot be silently overwritten.
5. All emitted P1 JSON obeys `contracts/schemas/binary-manifest.schema.json`.

## Known limitations

- Parsing via `goblin` is currently a provisional adapter; suitability on complex PE files remains untested.
- Non-PE binaries are out of scope for P1.
- No decompilation, behavioral simulation, anti-cheat interaction or live process instrumentation.
- Fuzz testing, streaming I/O, reproducible Cargo.lock and large-file benchmarks remain future work.
- CI results must be inspected before calling any gate passed.
