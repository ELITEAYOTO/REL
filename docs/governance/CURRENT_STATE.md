# REL — Current state and next-chat entry point

**Snapshot:** 2026-10-19, during EX-02 consolidation. This page is an **entry point**, not a live API or source of truth. **Recheck GitHub before any work.** Most detailed legacy history remains in [HANDOFF_NEXT_CHAT.md](HANDOFF_NEXT_CHAT.md); do **not** read that multi-session archive as a current work order.

## 0. How to resume (mandatory)

1. Read the repository root [AGENTS.md](../../AGENTS.md), [README](../../README.md), [ROADMAP](../../ROADMAP.md), [CODE_QUALITY](CODE_QUALITY.md), [frozen decisions](DECISIONS_FIGEES.md) and [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).
2. Query GitHub **now**: latest `main` commit, open PRs/issues, actual head SHAs, branch divergence, mergeability and *CI runs for the latest SHA*. Do not reuse CI from an older head. Re-evaluate this page's snapshot.
3. Follow [PR #62](https://github.com/ELITEAYOTO/REL/pull/62) for the active EX-02 pilot: read its diff, [EX-02 specification](../specs/METADATA_DIFF_PILOT.md) and its branch files before choosing a change.
4. Reproduce a concrete issue, implement a scoped improvement, run format/Clippy/workspace tests and appropriate independent oracles; wait for completed Windows **and** Linux CI when practically available. A pass on a predecessor SHA is not a pass on the latest head.
5. Update evidence, docs, issue/PR notes and this short page **only when a material state or next priority changes**. Favor a consolidated, precise French report over many micro-commit summaries.

## 1. Actual verified state at snapshot time

- **Repository:** [ELITEAYOTO/REL](https://github.com/ELITEAYOTO/REL), modular Rust offline-first static PE analysis. Vision: broader authorized reverse engineering and version evolution through evidence, **not** currently full decompilation or Apex version reconstruction.
- **`main` snapshot:** [`f053f09`](https://github.com/ELITEAYOTO/REL/commit/f053f09e6e4172ad32b9b98ed5fe003ec7824bde), containing merged audit [#65](https://github.com/ELITEAYOTO/REL/pull/65), EX-01 fix [#66](https://github.com/ELITEAYOTO/REL/pull/66), and durable handoff [#70](https://github.com/ELITEAYOTO/REL/pull/70). Latest verified post-merge [main CI #39216188780](https://github.com/ELITEAYOTO/REL/actions/runs/39216188780) completed successfully on Windows and Linux. **Recheck GitHub for newer commits before claiming this is current.**
- **EX-02 pilot only on draft [PR #62](https://github.com/ELITEAYOTO/REL/pull/62)**, branch `feat/ex02-metadata-diff-slice`, **not merged into `main`**. Review checkpoint [`124b89e`](https://github.com/ELITEAYOTO/REL/commit/124b89eabb9e4274ac8b61f30d9a15deb15386bb), after 135 commits / 29 changed files. BOTH [CI #39218333220](https://github.com/ELITEAYOTO/REL/actions/runs/39218333220) and [CI #39218338335](https://github.com/ELITEAYOTO/REL/actions/runs/39218338335) finished successfully on Windows/Linux for this exact SHA. This is a **dated checkpoint**, not perpetual validation; require an independent net-diff review and explicit scoped-pilot merge decision.
- **Active code:** independent `tools/rel-diff` Rust CLI taking two controlled PE `binary-manifest 1.0.0` JSON files, returning separate experimental `0.1.0-experimental` JSON diff. Compares observed strings and uniquely named sections; abstains for ambiguous section naming; no functional/decompilation conclusion. [README in PR branch](https://github.com/ELITEAYOTO/REL/blob/feat/ex02-metadata-diff-slice/tools/rel-diff/README.md), [output JSON Schema](https://github.com/ELITEAYOTO/REL/blob/feat/ex02-metadata-diff-slice/contracts/experimental/manifest-diff.schema.json).
- **Tests/oracles:** Rust unit and CLI tests, independent `scripts/test_manifest_diff_cli.py`, 16 controlled PE A/B comparisons produced from 8 Windows compiler-built cases with `pefile` oracle; source `fixtures/probes/diff_version_probe.c`, [corpus document](https://github.com/ELITEAYOTO/REL/blob/feat/ex02-metadata-diff-slice/docs/EX02_COMPILER_CORPUS.md). **Only four C variants from one source and two compilers**; not 16 independent software products/releases.
- **Reproducibility finding [#69](https://github.com/ELITEAYOTO/REL/issues/69):** normal duplicate builds had two changed timestamp-field bytes per PE, causing differing raw SHA-256. Controlled `/Brepro` builds were 8/8 byte-identical both in-job and across two jobs with recorded source/compiler/toolchain identity. [ADR-0014](https://github.com/ELITEAYOTO/REL/blob/feat/ex02-metadata-diff-slice/docs/adr/ADR-0014-binary-identity-vs-reproducible-build.md) is **proposed only** in draft PR #62, not adopted in `main`. Preserve raw binary SHA; do not erase PE timestamp bytes or imply equivalent behavior.
- **Other audit findings:** [#63](https://github.com/ELITEAYOTO/REL/issues/63) FIFO (fix verified on PR #62, not shipped yet); [#67](https://github.com/ELITEAYOTO/REL/issues/67) consumer `u64` vs public JSON integer schema; [#68](https://github.com/ELITEAYOTO/REL/issues/68) output-byte budget and synthetic resource measurements; [#15](https://github.com/ELITEAYOTO/REL/issues/15) EX-02 acceptance. Query statuses rather than closing just from branch CI. Existing EX-01 proof-free absence [#64](https://github.com/ELITEAYOTO/REL/issues/64) corrected through merged #66.

## 1b. Latest EX-02 audit and validation delta (2026-10-19)

On the *unmerged* PR #62, the provenance comparator `scripts/compare_ex02_corpus_runs.py` now rejects missing/contradictory source, compiler, linker, SDK/VC, runner and build-script identity. It bounds extracted evidence JSON or ZIP member bytes at **2 MiB**, rejects **duplicate JSON keys**, requires eight coherently labeled builds, validates all **16 specified A/B pairs** and detects contradictory import/export counts or delta oracles for **byte-identical PE inputs**. Direct strict equality is limited to `/Brepro` builds. Added negative tests for omissions, malformed IDs, pair duplicates, count mismatches, contradictory oracles and invalid JSON.

The Windows independent `check_windows_diff_pairs.py` previously lowercased Unicode DLL prefixes with Python's `lower()`, unlike Rust's ASCII-only normalization; now it uses ASCII-only character mapping. Windows helper tests and the Linux/Windows compiled Rust CLI oracle cover Unicode false-equivalence and legitimate ASCII-only DLL case equivalence. **No public binary-manifest v1.0.0 or experimental report schema change**.

**Latest validated CI for that branch at this snapshot:** [#39218333220](https://github.com/ELITEAYOTO/REL/actions/runs/39218333220), [#39218338335](https://github.com/ELITEAYOTO/REL/actions/runs/39218338335), both green Windows/Linux for `124b89e`. There were earlier **failed intermediate commits** during the work; do not cite them as final results or erase this history. PR #62 remains draft, unreviewed independently, and **full EX-02 gate #15 remains OPEN**.

**Immediate next technical action:** review the *full net diff* and acceptance contract of #62 against **fresh `main`** (including dependencies, [CI supply-chain pinning #72](https://github.com/ELITEAYOTO/REL/issues/72), data-input limits, independent oracle integrity, and path consistency), address only provable findings in scoped PRs, and seek independent review before a decision to merge the experimental pilot. Do not start Ghidra/P3 or close the full EX-02 milestone from a synthetic four-variant source corpus.

## 2. Priority / state machine for the next session

**Current priority: independent PR #62 consolidation and handoff quality, not starting P2/Ghidra.** See the [dated pre-merge review checklist](../audits/2026-10-19-ex02-premerge-review.md) for explicit blockers and acceptance gates.

A. Inspect #62 **as a whole**, not just the latest commits: changed files, size, naming/architecture contracts, acceptance criteria, build steps and producer/consumer boundaries. Verify today's head and diff relative to *current* `main`. Look for unsupported data, weak oracles, stale/contradictory docs, supply-chain gaps and hidden regressions.

B. Fix **proven** bugs and make negative test assertions. The report-comparison helper `scripts/compare_ex02_corpus_runs.py` is a current focus: requiring **nonempty matching provenance**, not considering two omitted fields equivalent. Tests should fail for missing SHA/source, linker, SDK/VC versions, runner image and build-script identity. Check latest CI for this work; do not assume it is merged or green.

C. Determine an **honest merge gate for an experimental pilot** versus an **entire EX-02 acceptance milestone**. Do not merge a 116+ commit PR solely on success status; check independent review, main conflicts, reproducibility of scripts, bounds and unit/integration coverage. If not ready, keep draft and document blockers. Avoid wholesale refactor or rewriting public `binary-manifest v1.0.0`.

D. Full EX-02 remains open: truly diverse, authorized software-build pairs with known independent oracles, representative performance/RSS, coverage/ordinal/delayed imports, numeric schema fidelity, and confidence/abstention semantics. Do not claim these tests have been completed from a synthetic corpus.

## 3. Reproducible commands / evidence to verify

Rust baseline (use toolchain pinned in repo; run on Windows/Linux):
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

EX-02 independent checks, using release executables:
```bash
python scripts/test_manifest_diff_cli.py --binary target/release/rel-diff --inspector target/release/rel-inspect
python scripts/test_compare_ex02_corpus_runs.py
python scripts/test_windows_diff_repro.py
```
Append `.exe` to Windows binaries. On Windows only, the CI additionally calls `scripts/build_windows_diff_pairs.cmd` and its `repro` mode, then `scripts/check_windows_diff_pairs.py`, `scripts/check_windows_diff_repro.py`, `scripts/compare_ex02_corpus_runs.py`; preserve the independently uploaded artifacts. Tool dependencies and workflow details live in [CI config](../../.github/workflows/ci.yml) **on the PR branch**. Do not execute the PE corpus binaries.

## 4. Working method and reporting

User preference: **substantive technical sessions**, ideally aiming for ~20 minutes when useful and possible, with actual code review, tests, fixes, docs and completed CI, rather than two-minute micro-commit reports. Do **not** insert arbitrary delays, claim asynchronous progress, or prolong finished work just to meet a timer. Do not request confirmation for routine scoped improvements; do request user decision for a breaking public API, destructive action, license, paid cost or radical direction.

Write French progress summaries with links to **real** PR/commit/CI, and distinguish `VERIFIED`, `PENDING`, `HYPOTHESIS`, `LIMITATION`. No inventing commit IDs, no false functionality claims, no unwarranted green status if latest job is still running. Keep two separate facts visible: **feature is present in a draft branch** vs **feature is integrated on main**.

**If nearing chat limit:** update this page with timestamp, fresh HEADs, latest completed CI, unmerged work, confirmed blockers and one next action. Then a new chat with the user's universal REL master prompt can simply read this file after querying `main`. The prompt alone supplies philosophy; **this living page supplies missing project state**.
