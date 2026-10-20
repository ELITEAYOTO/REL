# REL — Current state and next-chat entry

**Checkpoint: 2026-10-20, immediately after PR #89.** This is a dated
verification, NOT a live GitHub API. Always fetch current main SHA, open PRs,
issues and completed CI before acting. The large
[historical handoff archive](HANDOFF_NEXT_CHAT.md) contains old snapshots;
the canonical entry point is THIS document.

## 0. Mandatory resumption

1. Read [AGENTS](../../AGENTS.md), [ROADMAP](../../ROADMAP.md),
   [CODE_QUALITY](CODE_QUALITY.md), [DECISIONS_FIGEES](DECISIONS_FIGEES.md),
   [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md) and the relevant
   contracts/security docs. The project is modular, static and Rust-first.
2. Query GitHub for latest main, PRs, issues, exact-head checks and reviews.
   Do not trust this checkpoint as the current GitHub state.
3. Pick one demonstrated defect or explicit acceptance gate. Use scoped PRs
   and negative tests; avoid cosmetic mass refactors or undocumented API
   changes. Preserve binary-manifest version 1.0.0.
4. Require exact final PR HEAD passing Windows + Ubuntu CI, plus bounded fuzz
   and independent PE oracles when applicable; inspect failure artifacts.
   Formal independent reviewer approval must not be invented.
5. Under the owner's delegated merge authority, prefer squash of reviewed
   scoped changes, then require separate passing Windows + Ubuntu CI on the
   EXACT NEW MAIN SHA before calling the work shipped or closing an issue.
6. Record proof, input hashes, actual runner metrics and residual risks.
   Never infer hostile-file safety from green tests.

## 1. Last verified integration

Repository: [ELITEAYOTO/REL](https://github.com/ELITEAYOTO/REL).
Main at this checkpoint:
[c9d092ccfc4d0a92edc0f5d70440ab2f977326a4](https://github.com/ELITEAYOTO/REL/commit/c9d092ccfc4d0a92edc0f5d70440ab2f977326a4).
[Exact post-squash CI #39345880829](https://github.com/ELITEAYOTO/REL/actions/runs/39345880829)
**completed/success on Windows AND Ubuntu**.
**Open PR count: 0. Open issue count: 10** at this dated checkpoint.

Last shipped increment:
[PR #89](https://github.com/ELITEAYOTO/REL/pull/89) (squashed as c9d092c).
New scripts profile deterministic malformed-PE CLI rejection and upload
reproducible per-OS JSON evidence. **No production parser, dependency,
public schema or existing positive benchmark format changed.**

Relevant earlier integrated milestones:

| Work | Verified proof and status |
| --- | --- |
| EX-01 input and evidence | [#75](https://github.com/ELITEAYOTO/REL/pull/75), [#77](https://github.com/ELITEAYOTO/REL/pull/77): narrow source-backed producers/verifier, full #14 gate OPEN |
| EX-02 metadata-only pilot | [#62](https://github.com/ELITEAYOTO/REL/pull/62), [main CI #39305827604](https://github.com/ELITEAYOTO/REL/actions/runs/39305827604): pilot on main, full #15 gate OPEN |
| Watchdog stdout/stderr spool checks | [#79](https://github.com/ELITEAYOTO/REL/pull/79): sampled, NOT a hard disk quota |
| Pinned isolated fuzz toolchain | [#83](https://github.com/ELITEAYOTO/REL/pull/83), [main CI #39316683354](https://github.com/ELITEAYOTO/REL/actions/runs/39316683354): fuzz-specific dated nightly and Cargo-generated lock; scoped #12 CLOSED |
| Extended PE fuzz | [run #39318875380](https://github.com/ELITEAYOTO/REL/actions/runs/39318875380): 2,562,113 executions / 301 s, no crash in THAT run. Trigger-only temporary PR #84 closed unmerged; NOT a verified manual dispatch event on main |
| Goblin TLS F001 | [#86](https://github.com/ELITEAYOTO/REL/pull/86) and [#88](https://github.com/ELITEAYOTO/REL/pull/88), [main CI #39340610502](https://github.com/ELITEAYOTO/REL/actions/runs/39340610502): historical Goblin 0.9.3 OOB reproduced in isolated code; 1048-byte reduced witness; scoped #11 CLOSED |

## 2. Last negative-PE campaign: issue #9, PARTIAL

[Technical issue evidence](https://github.com/ELITEAYOTO/REL/issues/9#issuecomment-6280193664).
[PR #89](https://github.com/ELITEAYOTO/REL/pull/89) generates **13
controlled malformed PE32/PE32+/F001 cases**, including a malformed 8 MiB
overlay, from already tracked, checksum-verified fixtures. Each case was run
three times per OS. **39/39 expected status-1 rejections on Ubuntu; 39/39
on Windows; 78 total. No partial JSON stdout**, and required diagnostics
and cross-OS case SHA-256 identities matched.

The independently downloaded exact PR-head artifacts
([Ubuntu #12231085818](https://github.com/ELITEAYOTO/REL/actions/runs/39345383358/artifacts/12231085818);
[Windows #12230303347](https://github.com/ELITEAYOTO/REL/actions/runs/39345383358/artifacts/12230303347))
reported:

| Hosted-runner observation | Ubuntu | Windows |
| --- | ---: | ---: |
| Median direct-child wall time over 39 runs | 2.3517 ms | 7.7217 ms |
| Maximum observed direct-child wall time | 4.5291 ms | 20.9959 ms |
| Largest SAMPLED direct-child RSS | 7,573,504 bytes | 21,553,152 bytes |
| Missing resource-sampling runs | 0 | 0 |

Exact-head [push CI #39345383358](https://github.com/ELITEAYOTO/REL/actions/runs/39345383358)
and [PR CI #39345393827](https://github.com/ELITEAYOTO/REL/actions/runs/39345393827)
were green Windows/Ubuntu on e9bfdb504f28994ac88252128111b16cd43d45f2;
post-squash main CI also passed as above.

**Important limitations:** these measurements do NOT establish real peak
RSS, kernel CPU/RAM/disk limits or representative performance. This test
profiler kills its direct child after 20 seconds or oversized diagnostic
spools (64 KiB), but does NOT provide a universal process-tree sandbox.
No externally licensed PE corpus was added. [Issue #9](https://github.com/ELITEAYOTO/REL/issues/9)
is OPEN.

## 3. Functional and security boundary

- **P1:** static PE32/PE32+ metadata, SHA-256 and manifest version 1.0.0.
  Inspected PE files are never run or loaded.
- **EX-01:** limited experimental source-backed DOS, COFF and section
  observations plus strict evidence validation, not full proof of coverage.
- **EX-02:** experimental Rust metadata-only rel-diff is merged, separate
  versioned output, not executable function matching or decompilation.
- **P2/P3:** future external Ghidra integration and function matching;
  **neither is shipped**. Gameplay network/server lab is a separate
  future authorized offline research issue, not REL implementation.
- **Threat:** controlled-input alpha, NOT arbitrary hostile binary/file
  sandbox. No atomic filesystem snapshot. Unix/Windows path guarantees
  differ; concurrent changes, CPU/RSS/process tree and disk budgets
  remain partial. Upstream F001 regression success is narrow.
- **License:** repository is public but no source LICENSE decision has
  been approved. Do not assume permission to redistribute existing
  binaries or third-party Windows samples; owner decision #16 required.

## 4. Open issues and next concrete work

At this snapshot the **10** open issues are:
[#8](https://github.com/ELITEAYOTO/REL/issues/8) fuzz diversity,
[#9](https://github.com/ELITEAYOTO/REL/issues/9) representative licensed
PE corpus and enforced resource limits,
[#14](https://github.com/ELITEAYOTO/REL/issues/14) full EX-01,
[#15](https://github.com/ELITEAYOTO/REL/issues/15) full EX-02,
[#16](https://github.com/ELITEAYOTO/REL/issues/16) owner source-license choice,
[#44](https://github.com/ELITEAYOTO/REL/issues/44) separate offline gameplay lab,
[#67](https://github.com/ELITEAYOTO/REL/issues/67) JSON integer/u64,
[#68](https://github.com/ELITEAYOTO/REL/issues/68) rel-diff resource budgets,
[#69](https://github.com/ELITEAYOTO/REL/issues/69) reproducible build hash drift,
[#72](https://github.com/ELITEAYOTO/REL/issues/72) supply-chain/CI pin review.

**First priority:** advance #9 with a **license-cleared independently
verified PE32/PE32+ EXE/DLL corpus**, mapping producer/version, exact
redistribution terms, SHA-256, odd imports/exports/sections and a
separate pefile oracle; alternatively demonstrate and close ONE concrete
OS-specific resource containment gap. Do not ingest proprietary game EXEs
or claim a representative corpus before those gates.

**Secondary:** #8 longer campaigns with varied lawful seeds and distinct
crash triage; #14/#15 coverage and real-world metadata accuracy; #68
measured output/CPU/RAM budgets; #16 awaits owner decision.

No automatic future work occurs after a chat ends. New chat should
re-query GitHub, check this checkpoint and proceed with one scoped PR.
