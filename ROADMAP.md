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

## P1.5 — Binary Inspector hardening — IN PROGRESS (critical scope before pilot)

- [x] Commit and pin `Cargo.lock`; enforce `--locked` in Linux/Windows CI.
- [ ] Evaluate dependency MSRV, known advisories and license inventory.
- [ ] Expand corpus: license-verified redistributable PE samples spanning multiple compilers and unusual edge cases.
- [x] Verify native Windows PE self-inspection against independent pinned `pefile` ([PR #6](https://github.com/ELITEAYOTO/REL/pull/6), CI 39098961562).
- [x] Run deterministic seeded mutation/truncation regressions against synthetic PE32/PE32+ fixtures ([PR #4](https://github.com/ELITEAYOTO/REL/pull/4), CI 39098578436).
- [x] Validate bounded coverage-guided libFuzzer smoke using the preserved F001 regression and pinned goblin 0.10.7 ([PR #10](https://github.com/ELITEAYOTO/REL/pull/10), fuzz CI 39101228893 and regular CI 39101228912).
- [ ] Pin fuzz-specific Cargo.lock and nightly compiler, then conduct longer campaigns with coverage trend tracking.
- [ ] Minimize F001 and investigate upstream fix; preserve original input evidence.
- [ ] Run extended fuzz campaigns and persist new distinct failures.
- [ ] Establish representative runtime **and memory** benchmarks across complex PE files.
- [x] Verify initial CLI timing harness on Windows/Linux with uploaded JSON observations ([PR #5](https://github.com/ELITEAYOTO/REL/pull/5), CI 39098808184).
- [x] **P1.5-A increment:** bounded single-descriptor reader, strict byte cap, observable file-change and path-policy tests ([PR #17](https://github.com/ELITEAYOTO/REL/pull/17), [Windows/Linux CI](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604)).
- [ ] **P1.5-A remaining:** atomic no-follow path handling, same-length concurrent modifications, stronger Windows/Linux path tests and CPU/RSS/output budgets ([issue #9](https://github.com/ELITEAYOTO/REL/issues/9)).
- [ ] **P1.5-A:** measure and enforce resource limits (output size, CPU/RSS and pathological structures); expand licensed PE corpus.
- [ ] **P1.5-B:** extend coverage-guided fuzzing, worker isolation and long-term robustness, without claiming general security ([issues #8](https://github.com/ELITEAYOTO/REL/issues/8), [#11](https://github.com/ELITEAYOTO/REL/issues/11), [#12](https://github.com/ELITEAYOTO/REL/issues/12)).
- [ ] Establish release/archive provenance and binary integrity checks.

## EX-01 — Experimental evidence/coverage envelope — AFTER CRITICAL P1.5-A

- [ ] Separate versioned observation schema: source hash, extractor/version/config, exact domain coverage, diagnostics and unknown states ([issue #14](https://github.com/ELITEAYOTO/REL/issues/14)).
- [ ] Golden tests for present/absent-in-scope/partial/failed/unsupported, invalid byte offsets, repeatability and v1 compatibility.
- [ ] Do not change `binary-manifest.schema.json` v1.0.0 or create speculative crates.

## EX-02 — Metadata-only PE manifest diff pilot — BEFORE P2 (ADR-0013)

- [ ] Independent Rust CLI/library comparing two strictly validated v1 manifest JSON files, separate diff output schema ([issue #15](https://github.com/ELITEAYOTO/REL/issues/15)).
- [ ] Golden A/B, inversion symmetry, deterministic ordering, ambiguous sections/imports, extraction failures and incompatible schema.
- [ ] Benchmark legal paired builds and validate Windows/Linux CI; **no function-diff or behavioral claim**.

**Product strategy and sequence:** [RFC-0001](docs/rfc/RFC-0001-EVIDENCE-EVOLUTION.md), [ADR-0013](docs/adr/ADR-0013-vision-evidence-evolution.md), [gates](docs/governance/STRATEGY_AND_GATES.md). P1.5-B continues and is NOT silently declared done.

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

## License decision (not yet completed)

- [ ] Review and choose REL source licensing and contribution policy, then add a LICENSE if approved ([issue #16](https://github.com/ELITEAYOTO/REL/issues/16)). Until then the public repository is **not automatically licensed for redistribution**.
