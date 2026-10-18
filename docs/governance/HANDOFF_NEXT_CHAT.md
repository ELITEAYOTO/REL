# REL — Handoff for next ChatGPT / contributor

## Repository and current state
- Repository: https://github.com/ELITEAYOTO/REL
- Source of truth: `main`; read it before suggesting changes.
- P1 alpha passed Windows/Linux GitHub CI on 2026-10-18: [run 39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395), merged via [PR #1](https://github.com/ELITEAYOTO/REL/pull/1).
- P1.5 increments verified: [PR #4](https://github.com/ELITEAYOTO/REL/pull/4) mutation regression (CI 39098578436); [PR #5](https://github.com/ELITEAYOTO/REL/pull/5) CLI timings (CI 39098808184); [PR #6](https://github.com/ELITEAYOTO/REL/pull/6) Windows compiled EXE cross-check against pefile (CI 39098961562).
- The tested CLI handles two synthetic PE fixtures and its own Windows Release EXE. This **does not** establish production robustness.

## Before action
1. Read `AGENTS.md`, `ROADMAP.md`, `README.md`, architecture and governance docs.
2. Inspect current `main` commit and open PRs/issues; don't assume files absent.
3. Keep each new tool independent; no monolithic refactor.
4. Do not regress the JSON manifest contract without a versioning ADR.
5. Implement one measurable P1.5 gate at a time; compile and verify CI on PR.
6. Update changelog and validation evidence with real run IDs.
7. Do not attempt to execute or bypass protection on current online games; use authorized offline fixtures.

## Immediate priorities
1. Cargo.lock is now tracked; keep it updated only with deliberate dependency changes and green `--locked` CI.
2. Expand reference corpus beyond synthetic fixtures and the CI-built REL Windows executable; verify each source/license.
3. Maintain already-implemented **bounded coverage-guided** fuzzing (PR #10), pin fuzz-nightly toolchain/dependencies, extend campaigns and keep F001 original regression.
4. Extend benchmarks to diverse PE complexity, peak memory, and repeatable local baselines; CLI wall-clock measurements are already present.
5. Per accepted ADR-0013, after critical P1.5-A gates, build EX-01 experimental evidence/coverage contract then EX-02 metadata-only PE diff before a separate Ghidra adapter (P2). Do not conflate EX-02 with P3 function matching.

## Nonnegotiable distinctions
- VERIFIED: directly observed code/test/CI result.
- DESIGN: chosen REL constraints.
- UNKNOWN: lacks sufficient evidence; preserve as unknown.
- HYPOTHESIS: explicitly labeled and accompanied by validation plan.

Future assistants must not claim these modules exist: source decompiler, version matcher, classifier, emulator or desktop UI. They remain roadmap items.

## Strategic decision from PR #13 (18 October 2026)

- **Accepted:** [RFC-0001](../rfc/RFC-0001-EVIDENCE-EVOLUTION.md) with explicit amendments in [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md) and [STRATEGY_AND_GATES](STRATEGY_AND_GATES.md).
- REL continues as a **full reverse-engineering platform**. The Evidence & Evolution approach focuses on source-backed, version-aware, reproducible findings, without reducing product scope.
- Official milestones: **P1.5-A critical input hardening -> EX-01 minimal observation/coverage contract -> EX-02 PE manifest metadata diff -> P2 Ghidra -> P3 deep matching**. P1.5-B continuous hardening remains incomplete.
- **NOT BUILT:** EX-01, EX-02, Ghidra, advanced classifier, behavior lab, UI, graph engine. Do not silently mark them complete or change existing v1.0.0 schema.
- First inspect [EX-01 spec](../specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02 spec](../specs/METADATA_DIFF_PILOT.md), [alpha threats](../security/THREAT_MODEL_ALPHA.md) before implementation.
- Source license is **not yet decided**. Need dependency/license review and a separate deliberate policy decision.
- F001 preserved and mitigated for the tested goblin 0.10.7 version, not a claim of universal hostile-input safety.
- LOC/complexity limits remain review triggers, no speculative monolithic refactor.

## P1.5-A bounded input increment (validated, P1.5-A overall open)

- Reader work: `tools/rel-inspect/src/input.rs` acquires file bytes through one descriptor and refuses symlinks/non-regular inputs; hard actual-read cap replaces path-metadata+unbounded read. Documentation: [P15A_BOUNDED_INPUT](../security/P15A_BOUNDED_INPUT.md).
- Preserve the distinction: **size/timestamp checks are not atomic snapshots** and pre-open symlink check can race; do not declare arbitrary hostile files secure. CPU/RSS/output and worker isolation remain unproven.
- Verified [PR #17](https://github.com/ELITEAYOTO/REL/pull/17) with [CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604) on Ubuntu/Windows. Remaining path races, true snapshots, resource budgets and process isolation still require their own gates.

## P1.5-A JSON output bound (CI verified; resource hardening incomplete)

- Work in PR for `tools/rel-inspect/src/report.rs`, a byte-for-byte compatible pretty-JSON serializer enforcing **16 MiB JSON bytes** before writing file or stdout.
- The 16 MiB constant is provisional; normal output v1.0.0 is unchanged. This bound does **not** cap parsing RAM/CPU or prevent partial files from disk-write errors.
- Read [P15A_BOUNDED_OUTPUT](../security/P15A_BOUNDED_OUTPUT.md) and retain the exact CI evidence.
- [PR #18](https://github.com/ELITEAYOTO/REL/pull/18) validated Windows/Linux [CI #39104382262](https://github.com/ELITEAYOTO/REL/actions/runs/39104382262). The report size guard is complete within its narrow scope; broader P1.5-A is still open.

## P1.5-A resource profiling (CI verified; limits not implemented)

- New independent `scripts/profile_resources.py`, executed by matrix CI with `psutil==7.0.0`. Measures observed RSS/CPU/wall of the actual compiled REL CLI; results written to `rel-resource-profile-<OS>` artifacts.
- Sampled memory can miss true peaks; this **does not** impose hard process RSS/CPU limits. [Method and caveats](../P15_RESOURCE_PROFILING.md).
- [PR #19](https://github.com/ELITEAYOTO/REL/pull/19) passed [Windows/Linux CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706), artifacts uploaded. Issue #9 still tracks **enforceable budgets**, path races, representative corpus and isolation.

## P1.5-A PE header preflight (CI pending)

- New `crates/rel-pe/src/preflight.rs` validates conservative header bounds **before** goblin. Limits: NT header offset ≤1 MiB, 1–96 sections, optional header 2–4096 bytes and complete section-header table.
- No new crate, dependency or manifest v1.0.0 change. Golden + malformed + public API tests added. Windows/Linux CI and fuzz gate must pass before claiming verified.
- [Policy and security caveats](../security/P15A_PE_PREFLIGHT.md): parser imports/TLS/exports, CPU/RSS, arbitrary hostile-input processing and sandboxing remain **unresolved**. Some unusual parseable PEs may now be rejected.
