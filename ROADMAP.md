# REL roadmap and acceptance gates

Every item requires test evidence before the checkbox is marked complete. ADRs govern architecture changes.

## P0 — Foundational architecture — DONE

- [x] CLI-first modular workspace; separate contracts, parser and CLI.
- [x] Rust core; Python for future adapters; desktop postponed.
- [x] Initial security and provenance principles.

## P1 — Binary Inspector alpha — DONE within narrow scope

- [x] PE32 and PE32+ reading without executing inputs.
- [x] Sections, imports, exports, SHA-256 and JSON schema v1.0.0.
- [x] Corpus of two synthetic reference PEs, corruption tests and CLI overwrite guard.
- [x] Rust formatting, Clippy, unit/integration tests and release builds on Windows and Ubuntu.
- [x] CLI smoke test matches reference fixtures and validates JSON Schema.

**Evidence:** [PR #1](https://github.com/ELITEAYOTO/REL/pull/1) and [CI run 39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395). **Do not interpret this as production readiness or universal PE correctness.**

## P1.5 — Binary Inspector hardening — NEXT

- [x] Commit and pin `Cargo.lock`; enforce `--locked` in Linux/Windows CI.
- [ ] Evaluate dependency MSRV, known advisories and license inventory.
- [ ] Expand corpus: real redistributable Windows binaries with independent reference oracle; PE edge cases.
- [ ] Fuzz malformed/truncated headers and import/export tables, establish crash-free behavior.
- [ ] Benchmark input size, memory and runtime with a reproducible methodology.
- [ ] Add deterministic limits for expensive PE structures, test input symlinks and path edge cases.
- [ ] Establish release/archive provenance and binary integrity checks.

## P2 — Ghidra adapter

- [ ] Independent Python CLI; pinned Ghidra version and documented Java requirements.
- [ ] Headless function/call graph export into a dedicated schema; benchmark on known-source samples.
- [ ] Graceful timeout, memory/error isolation and proof record; no embedded decompiler fork.

## Later

- [ ] P3 — Version matcher with ground-truth comparisons.
- [ ] P4 — Provenance and evidence storage.
- [ ] P5 — Function classifier with confidence calibration and UNKNOWN class.
- [ ] P6 — Optional isolated/authorized behavior lab.
- [ ] P7 — Desktop UI only after stable headless workflows.
- [ ] P8 — Release hardening, portability and packaging.

**Scope control:** Apex/R5Flowstate is a future optional case study, not a dependency or an excuse for anti-cheat bypass.
