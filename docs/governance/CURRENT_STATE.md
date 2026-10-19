# REL — Current state and next-chat entry

**Snapshot: 2026-10-19, after the controlled EX-02 pilot squash merge.**
This is a dated checkpoint, **not** a live GitHub API or proof of future CI.
Always recheck `main`, open issues/PRs, and exact latest commit workflow runs.
The historical multi-session account remains in [HANDOFF_NEXT_CHAT.md](HANDOFF_NEXT_CHAT.md).

## 0. Resume procedure

1. Read [AGENTS.md](../../AGENTS.md), [ROADMAP](../../ROADMAP.md),
   [CODE_QUALITY](CODE_QUALITY.md), [DECISIONS_FIGEES](DECISIONS_FIGEES.md),
   [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md) and
   the relevant contracts before changing source code.
2. Query GitHub for current `main`, open PRs/issues, changed files and
   current-head **completed** CI; never apply this historical snapshot blindly.
3. Reproduce a demonstrated defect or an independently justified feature
   gate. Work in a scoped PR; run Windows and Linux locked Rust tests,
   Python regressions and independent source/PE oracles where applicable.
4. Confirm the **exact squashed `main` SHA** in completed Windows/Linux CI
   before closing a bug or claiming something is shipped. Record remaining
   risks and future work without asserting global hostile-input security.

## 1. Verified merge checkpoint

**Repository:** [ELITEAYOTO/REL](https://github.com/ELITEAYOTO/REL).
**`main` at this snapshot:** [`0e990e8`](https://github.com/ELITEAYOTO/REL/commit/0e990e8f208aafe80a3252a7eb355a46c8efc96e).
The exact [post-merge `main` CI #39305827604](https://github.com/ELITEAYOTO/REL/actions/runs/39305827604)
completed successfully on **Windows and Ubuntu**.

Four formerly pending changes were squash-merged sequentially, each with
its own successful post-merge Windows/Ubuntu CI:

| PR | `main` squash SHA | Post-merge CI | Shipped narrow scope |
| --- | --- | --- | --- |
| [#75](https://github.com/ELITEAYOTO/REL/pull/75) | `9e0359a` | [#39304156275](https://github.com/ELITEAYOTO/REL/actions/runs/39304156275) | `rel-observe` final-leaf no-follow/reparse guard and tests |
| [#77](https://github.com/ELITEAYOTO/REL/pull/77) | `5e71874` | [#39304522471](https://github.com/ELITEAYOTO/REL/actions/runs/39304522471) | Bounded EX-01 verifier reads and strict JSON duplicate-key handling |
| [#79](https://github.com/ELITEAYOTO/REL/pull/79) | `8387e6e` | [#39304964698](https://github.com/ELITEAYOTO/REL/actions/runs/39304964698) | Sampled watchdog stdout/stderr spool budgets |
| [#62](https://github.com/ELITEAYOTO/REL/pull/62) | `0e990e8` | [#39305827604](https://github.com/ELITEAYOTO/REL/actions/runs/39305827604) | Standalone experimental `rel-diff` metadata-only pilot |

Prior test-only [integration PR #78](https://github.com/ELITEAYOTO/REL/pull/78)
was deliberately **closed without merging** after green combined CI.
The historical pilot branch contained 149 commits; its actual integration
was one squash commit. **No independent formal GitHub review approvals were
recorded** on these four PRs at the checkpoint; the owner explicitly
authorized finalization, and that process exception was documented on the PRs.

## 2. Capabilities and limits

- **P1:** `rel-inspect` statically observes bounded PE32/PE32+ metadata and
  produces the established `binary-manifest 1.0.0` JSON. It does not execute
  inspected PE files, decompile code, or prove all PE parsing correct.
- **EX-01:** `rel-observe` has limited, source-backed DOS/COFF/section-header
  observations, with bounded controlled-input acquisition and separately
  versioned evidence. Not all coverage claims are implemented.
- **EX-02 pilot:** `rel-diff` compares two v1 PE JSON manifests for observed
  architecture/size/import/export/uniquely named section metadata, with
  abstention for repeated section names. The output is a **separate**
  `0.1.0-experimental` contract. Eight compiler-generated PE inputs from one
  source C and sixteen selected pairs were checked with an independent
  `pefile` oracle. This is **not** sixteen independent products or the full
  EX-02 acceptance gate.
- **Provenance:** raw PE SHA-256 remains authoritative. Controlled
  `/Brepro` comparisons demonstrated repeatable bytes only for the
  specified compiler/source/runner conditions. [ADR-0014](../adr/ADR-0014-binary-identity-vs-reproducible-build.md)
  remains **proposed**, not automatically accepted by merging its document.
- **Threat boundary:** controlled offline alpha, **not** a hostile-file
  sandbox. No atomic filesystem snapshot; Windows ancestor races and
  same-file concurrent mutation remain. Watchdog RSS, stdout/stderr spool
  checks are sampled; CPU/RSS/process-tree/disk isolation remains partial.

## 3. Open acceptance gates

- [Full EX-02 #15](https://github.com/ELITEAYOTO/REL/issues/15):
  independent legal software-version pairs, real-world accuracy/abstention,
  ordinal and delayed imports, repeatable representative RSS/CPU measurements.
- [EX-01 #14](https://github.com/ELITEAYOTO/REL/issues/14):
  versioned observation/coverage completeness beyond currently implemented
  producers.
- [P1.5 #8](https://github.com/ELITEAYOTO/REL/issues/8),
  [#9](https://github.com/ELITEAYOTO/REL/issues/9),
  [#12](https://github.com/ELITEAYOTO/REL/issues/12):
  longer and pinned fuzz campaigns, diverse licensed corpora, resource caps.
- [F001 #11](https://github.com/ELITEAYOTO/REL/issues/11):
  third-party `goblin` malformed PE panic root-cause follow-up.
- [#67](https://github.com/ELITEAYOTO/REL/issues/67),
  [#68](https://github.com/ELITEAYOTO/REL/issues/68),
  [#69](https://github.com/ELITEAYOTO/REL/issues/69):
  v1 JSON integer versus Rust `u64` representability, full resource
  budgets, and reproducibility provenance beyond the synthetic sample.
- [License and contributor policy #16](https://github.com/ELITEAYOTO/REL/issues/16):
  requires a **project-owner decision**, not an assistant-selected license.
- **Future P2/P3:** Ghidra integration and function matching are *not yet
  shipped*. No bypass of anti-cheat or protected online software.

Resolved narrow input defects [#63](https://github.com/ELITEAYOTO/REL/issues/63)
and [#76](https://github.com/ELITEAYOTO/REL/issues/76) were closed only
after code reached `main` with completed CI. Historical audit material
remains in [2026-10-19 pre-merge review](../audits/2026-10-19-ex02-premerge-review.md);
do not mistake its then-draft PR descriptions for current status.

**Immediate next step:** work on one evidenced unfulfilled gate (the legal
representative PE-version corpus or pinned fuzzing are strong candidates),
not a speculative redesign or a false claim of full reverse engineering.
