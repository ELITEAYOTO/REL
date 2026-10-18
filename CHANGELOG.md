# Changelog

## [Unreleased]

### P1.5 — experimental, pending CI
- Added a CLI benchmark harness (2 KiB, 1 MiB, 4 MiB synthetic overlays), controlled repetitions and per-platform JSON artifacts.
- No claimed performance thresholds: timings are environment-specific and benchmarking complex real PE files is still pending.

### Added — 2026-10-18
- Modular Rust workspace: `rel-contracts`, `rel-pe`, `rel-inspect`.
- Static PE32/PE32+ inspection and JSON manifests with SHA-256.
- Synthetic PE32 and PE32+ fixtures with known imports/exports and expected hashes.
- Parser integration tests, negative test cases and executable CLI smoke test.
- Draft 2020-12 JSON Schema validation.
- Linux and Windows GitHub Actions gates; source formatting brought into compliance.
- Governance: decision baseline, refactor thresholds, evidence log, handoff instructions.

- Added tracked `Cargo.lock` and strict `--locked` Rust CI execution.
- **Verified:** [PR #3](https://github.com/ELITEAYOTO/REL/pull/3) merged at `01367e5c208c44ecccd8e943cb43a7a48f93c6d7`; [CI run 39097322823](https://github.com/ELITEAYOTO/REL/actions/runs/39097322823) passed on Windows and Ubuntu with locked builds, tests and smoke checks.

### Verified
- [PR #1](https://github.com/ELITEAYOTO/REL/pull/1) merged as `58ddb71d25c3d9698ee6acbb5446c9b5cc1b497a`.
- [Actions run 39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395) succeeded on Ubuntu and Windows: `cargo fmt`, `clippy -D warnings`, unit/integration tests, release build, JSON-schema-backed CLI smoke tests.

### Not verified / not implemented
- Arbitrary real-world PE corpus compatibility, coverage-guided fuzzing, representative benchmarks or release reproducibility.
- Ghidra integration, function matching, decompilation, simulation or classification.
- No general security assurance beyond the explicitly tested paths.
