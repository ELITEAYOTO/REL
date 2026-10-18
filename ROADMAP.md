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

## P1.5 — Binary Inspector hardening — IN PROGRESS

- [x] Commit and pin `Cargo.lock`; enforce `--locked` in Linux/Windows CI.
- [ ] Evaluate dependency MSRV, known advisories and license inventory.
- [ ] Expand corpus: license-verified redistributable PE samples spanning multiple compilers and unusual edge cases.
- [x] Verify native Windows PE self-inspection against independent pinned `pefile` ([PR #6](https://github.com/ELITEAYOTO/REL/pull/6), CI 39098961562).
- [x] Run deterministic seeded mutation/truncation regressions against synthetic PE32/PE32+ fixtures ([PR #4](https://github.com/ELITEAYOTO/REL/pull/4), CI 39098578436).
- [ ] Run coverage-guided fuzzing against malformed PE fields and preserve minimized failures.
- [ ] Establish representative runtime **and memory** benchmarks across complex PE files.
- [x] Verify initial CLI timing harness on Windows/Linux with uploaded JSON observations ([PR #5](https://github.com/ELITEAYOTO/REL/pull/5), CI 39098808184).
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
