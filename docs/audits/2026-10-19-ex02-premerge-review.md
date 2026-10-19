# EX-02 — Pre-merge review record for experimental PR #62

**Snapshot reviewed:** 2026-10-19. **Review scope:** selected static code/contract/CI examination and live GitHub file inventory; **not** an exhaustive security or third-party code audit.

## Baseline and scale

- PR [#62](https://github.com/ELITEAYOTO/REL/pull/62), branch `feat/ex02-metadata-diff-slice`, currently **draft**, **not merged**.
- Review checkpoint: commit [`45ee42d`](https://github.com/ELITEAYOTO/REL/commit/45ee42dfc928a269d7d5834f66690e960f8d1440) had green Windows/Linux [CI #39215044062](https://github.com/ELITEAYOTO/REL/actions/runs/39215044062) and [CI #39215049809](https://github.com/ELITEAYOTO/REL/actions/runs/39215049809). **Subsequent commits must have their own final-head validation.**
- GitHub reported **118 commits**, **28 changed files**, approximately **2,703 additions / 3 deletions** relative to its original base at that checkpoint. Not a tiny feature patch; independent review, testing and an appropriate merge strategy are important.
- PR originally based on `main` SHA `48fb8e5`, while the already-updated `main` was `e063931`. GitHub reported `mergeable: true` / `clean` at the checkpoint, but do **not** infer the branch is freshly synchronized or guaranteed to remain conflict-free after more merges.
- Public `binary-manifest v1.0.0` **unchanged**; the output contract is independent `contracts/experimental/manifest-diff.schema.json` (`0.1.0-experimental`).

## Scope covered in review

| Area | Observed implementation | Review disposition |
| --- | --- | --- |
| `rel-diff` CLI and input validation | Controlled PE manifest v1; bounded 16 Mio per input; strict shape, required nullable keys; rejects extraction warnings/raw duplicate strings; Unix `O_NONBLOCK` and leaf `O_NOFOLLOW` | Candidate for **experimental controlled-input** pilot only; **not** an arbitrary hostile-input sandbox |
| Section diffs | Name-based only for unique exact names; duplicates yield `ambiguous` without partial section observations | Honest but narrow; no rename or function correlation |
| Imports/exports | Exact string sets, original evidence retained, limited ASCII DLL-case hint with collision abstention | Does not capture ordinal/delay-load/dynamic semantics |
| Output JSON | Contract separately versioned; 16 Mio serialization cap pre-stdout, typed report schema | Global CPU/RSS and partial OS stdout failures **not** fully bounded |
| Rust and Python tests | Workspace Rust + real CLI, negative JSON/collision/numeric-boundary cases, independent `jsonschema` oracle | Strong controlled regression evidence; cannot claim exhaustiveness |
| Windows compiled corpus | 4 C variants × MSVC/Clang-cl = 8 PE; 16 selected A/B pairs, independently checked with `pefile` | Source-controlled evidence; **not** 16 distinct software products |
| Reproducibility | Timestamp-byte root cause located in controlled repeat builds; optional `/Brepro` showed 8/8 bit-identical builds and cross-job identities under matched provenance | Maintain raw SHA; a repeatable build is not functional equivalence |
| Performance | Synthetic RSS/wall-time measurements archived with environment context | Not representative real-software benchmark or hard process limits |
| Governance | Proposed ADR-0014, spec, changelog and README updated in PR | ADR **not accepted on `main`** until deliberate decision |

## Concrete findings and remaining gates

**R1 — Provenance comparison, P2 correctness:** the helper comparing two build-evidence reports originally considered two **missing** provenance fields equivalent (`None == None`). A scoped fix adds `check_provenance` and negative tests for missing source/build SHA, linker, SDK/VC, image, and now missing linker mode. This is in active PR #62; **verify newest commit and CI before marking reviewed/closed**. A small residual future enhancement is pinning/verifying structured corpus evidence with a dedicated JSON Schema, if it materially helps.

**R2 — PR size and reviewability, P2 process:** the pilot has accumulated more than a hundred historical commits. A green CI is necessary but insufficient: require a focused **net-diff review**, confirm dependency/tool licensing and toolchain flags, decide review/squash strategy, and verify current base/HEAD. Avoid splitting merely to satisfy a line-count number, but prefer independent future PRs for further feature work.

**R3 — Domain limits, P2 acceptance:** the contract describes *observed metadata* and admits ambiguity. **Open acceptance issue [#15](https://github.com/ELITEAYOTO/REL/issues/15)** still requires representative, authorized independent software-version pairs, extraction/coverage limits and performance confidence. **Do not** report the entire EX-02 gate complete or P2/Ghidra available after merging an experimental pilot.

**R4 — Known audit issues:** [#63](https://github.com/ELITEAYOTO/REL/issues/63) FIFO corrected on draft only; [#67](https://github.com/ELITEAYOTO/REL/issues/67) public JSON Schema integer vs Rust `u64` fidelity documented as accepted **subset**, no silent v1 change; [#68](https://github.com/ELITEAYOTO/REL/issues/68) output bytes limited, RSS/CPU not globally capped; [#69](https://github.com/ELITEAYOTO/REL/issues/69) controlled reproducibility evidenced and under continuing toolchain-provenance scrutiny. Query issue states before closure.

**R5 — Code organization:** `tools/rel-diff/src/main.rs` now roughly 269 lines after extracting tests; that's sensible. The Python compiled-corpus oracle is roughly 335 lines, above the soft 300-line threshold but below the hard 450-line threshold, so **review** cohesion but do not refactor solely because of a metric. Recheck source metrics if it changes.

## Explicit merge checklist for a *pilot*, not full EX-02 gate

- [ ] PR head/base compared against **current** `main`, no accidental changes from unrelated work; review every added dependency and CI action.
- [ ] Latest PR HEAD: Windows and Linux fmt, Clippy, Rust tests, compiled/release CLI oracles and negative-case regressions **all completed successfully**, with exact run IDs.
- [ ] Independent review of the net diff (not merely a repeat of CI status), especially input/output contract, file access, Windows source builder and provenance comparator.
- [ ] ADR-0014 disposition **explicit** (accept as scoped design decision or keep proposed); neither raw SHA normalization nor behavioral conclusions introduced.
- [ ] README, changelog, roadmap and handoff agree: experimental pilot only; no unsupported “fully shipped” claims.
- [ ] License/redistribution implications reviewed, especially [issue #16](https://github.com/ELITEAYOTO/REL/issues/16); synthetic PE outputs not executed or redistributed casually.
- [ ] Merge method chosen; consider **squash** to keep `main` readable, preserving PR discussion and CI references.
- [ ] After merge (only if accepted): **new `main` Windows/Linux CI** passes, then issue #63 status can be reconciled. Main-only handoff checkpoint refreshed.
- [ ] Full EX-02 milestones **remain open** until their own independent gates are satisfied.

## Restart instructions

**Start with [CURRENT_STATE.md](../governance/CURRENT_STATE.md).** Fetch `main`, PR #62, issue #15 and the latest CI on their actual SHAs. Work on one **proven** blocker, not on arbitrary features; keep tests and docs. This file captures a dated review only. The next chat should **not assume** that #62 remained at `45ee42d`, that #70 merged, or that any formerly green CI proves a later commit safe.
