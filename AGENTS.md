# REL agent / contributor contract (mandatory)

## Read first
1. `README.md`, `ROADMAP.md`, `CHANGELOG.md`.
2. `docs/ARCHITECTURE.md`, `docs/governance/DECISIONS_FIGEES.md` and accepted `docs/adr/ADR-0013-vision-evidence-evolution.md`.
3. `docs/governance/CODE_QUALITY.md`, `docs/governance/STRATEGY_AND_GATES.md`, **`docs/governance/CURRENT_STATE.md`**, then `docs/governance/HANDOFF_NEXT_CHAT.md` only for historical detail. Always verify current GitHub state.
4. Relevant public contracts and tests before editing source.

## Immutable-by-default architecture
- A monorepo of **independent modules**, not a monolithic executable.
- `rel-contracts` has no dependency on `rel-pe` or the CLI.
- `rel-pe` consumes shared contracts; the CLI depends on both, never the reverse.
- Each new tool has its own CLI, tests, documentation and measurable acceptance gate.
- Keep Rust for native parsing/diff/core. Python adapters around established external tools. Java, C++, C# or TypeScript enter only for a justified module.
- Keep Ghidra/BinDiff/BSim as external reference engines; do not rewrite them speculatively.
- The **full reverse-engineering mission** is adopted; Evidence & Evolution is a cross-cutting provenance/change workflow, NOT a reduction to import scanning, compliance or AI narration.
- **Formal sequence ADR-0013:** critical P1.5-A -> EX-01 experimental observations/coverage -> EX-02 metadata-only manifest diff -> P2 Ghidra -> P3 function matching. **Limited EX-01 producers and the EX-02 metadata-only pilot (PR #62) are merged on main, but neither full gate is complete.** P1.5-B continues. Verify live GitHub and the dated CURRENT_STATE snapshot rather than repeating the former draft-PR status.
- Preserve `binary-manifest` v1.0.0; no breaking contract change or empty speculative crates. Negative findings require precise scope and verified coverage; `imports: []` is not proof of behavioral impossibility.
- Controlled-input alpha is not an arbitrary hostile-binary sandbox. `catch_unwind` does not contain aborts/OOM.
- P1 is **static-only**. Imported executables must not be launched, loaded or instrumented.
- Future execution is explicitly authorized, opt-in and isolated. No bypass of anti-cheat or protected online software.

## How to change architecture
1. Reproduce a real problem, failed test, bottleneck or incompatibility.
2. Write an ADR stating current design, evidence, alternatives, migration and rollback.
3. Add tests and get review before breaking APIs/schema/stack.
4. Update docs and CHANGELOG with verified status. Never silently rewrite history.

## Quality and refactor rules
- Handwritten Rust files: soft 350 LOC / hard 500 LOC; functions soft 50 / hard 80 LOC.
- Hard boundaries require documented exceptions or justified decomposition; soft thresholds only request review.
- Cyclomatic complexity >10 triggers review, >15 requires a mitigation or exception.
- No style-only broad refactors; no abstraction solely to reduce line count; no duplicate project-wide frameworks.
- Rust `unsafe` needs precise invariants, minimal scope and tests. Avoid panic paths on untrusted input.
- Parser tests must cover malformed input, negative paths, resource caps and golden samples.
- CI: `cargo fmt --all -- --check`, Clippy with warnings denied, full workspace tests, Windows/Linux build and executable smoke.
- Pin toolchains/dependencies and record exact validation evidence.

## Facts and progress
- Distinguish VERIFIED (code/tests), MAINTAINER CLAIM, DESIGN DECISION, HYPOTHESIS and UNKNOWN.
- Never infer feature maturity from file presence or successful compilation alone.
- Incomplete tasks are NOT DONE. Link to run IDs, commits and exact fixtures.
- No fabricated timings, performance, security guarantees or capability claims.
