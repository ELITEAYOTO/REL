# REL — Current state and next-chat entry

**Checkpoint: 2026-10-20, after PR #99 and exact post-squash main CI.** This is a dated
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
Main at this dated checkpoint:
[5f412de9573d806cfa43e02ed426da04331d8769](https://github.com/ELITEAYOTO/REL/commit/5f412de9573d806cfa43e02ed426da04331d8769).
[Exact post-squash main CI #39362984158](https://github.com/ELITEAYOTO/REL/actions/runs/39362984158)
**completed/success on Windows AND Ubuntu**.
**Open PR count: 0. Open issue count: 9** at this dated checkpoint.

Selected scoped, integrated partial gates (issue #9 remains OPEN):

| Work | Exact-head validation | Squashed main validation |
| --- | --- | --- |
| [PR #91](https://github.com/ELITEAYOTO/REL/pull/91): optional Linux watchdog starts a dedicated process group, cleans ordinary descendants on failure/normal exit; two Linux regressions | [PR CI #39351908549](https://github.com/ELITEAYOTO/REL/actions/runs/39351908549) and [branch #39351884313](https://github.com/ELITEAYOTO/REL/actions/runs/39351884313), both Windows/Ubuntu success on d695fe3 | [24ef315](https://github.com/ELITEAYOTO/REL/commit/24ef31545685377a34c179754c726eae2cde82d7), [CI #39352685559](https://github.com/ELITEAYOTO/REL/actions/runs/39352685559) success |
| [PR #92](https://github.com/ELITEAYOTO/REL/pull/92): two Windows-runner-built x86 PE32 DLL inputs (MSVC/Clang-cl) inspected by pinned independent pefile; evidence JSON uploaded | [PR CI #39353143656](https://github.com/ELITEAYOTO/REL/actions/runs/39353143656) and [branch #39353113893](https://github.com/ELITEAYOTO/REL/actions/runs/39353113893), both Windows/Ubuntu success on eda2468 | [ce6c4e0](https://github.com/ELITEAYOTO/REL/commit/ce6c4e057bdb07806082169d6b3a49f721a7686e), [CI #39353437460](https://github.com/ELITEAYOTO/REL/actions/runs/39353437460) success |

More recent scoped integrations, verified on the exact new main SHA:

- [PR #94](https://github.com/ELITEAYOTO/REL/pull/94): tracked local Markdown path checking in Windows/Ubuntu CI, with negative regressions and current-document status corrections; [post-squash CI #39356181149](https://github.com/ELITEAYOTO/REL/actions/runs/39356181149) passed. This gate does not prove every document is current or discover unreferenced/obsolete source files.
- [PR #95](https://github.com/ELITEAYOTO/REL/pull/95): Linux opt-in supervisor installs a per-file `RLIMIT_FSIZE` ceiling in its analyzer child before exec. Kernel-limit and burst/EFBIG regressions passed exact-head [CI #39357101394](https://github.com/ELITEAYOTO/REL/actions/runs/39357101394) and post-squash [main CI #39357415523](https://github.com/ELITEAYOTO/REL/actions/runs/39357415523), both Windows/Ubuntu. This is **not** an aggregate disk quota or hostile-process sandbox.

Further verified scoped progress:

- [PR #97](https://github.com/ELITEAYOTO/REL/pull/97) documented and regression-tested the four JSON/`u64` compatibility fields of the EX-02 metadata-only pilot. [Exact main CI #39359445896](https://github.com/ELITEAYOTO/REL/actions/runs/39359445896) passed Windows/Ubuntu; the scoped consumer-boundary audit [#67](https://github.com/ELITEAYOTO/REL/issues/67) closed, **without** extending the public schema or completing EX-02 #15.
- [PR #98](https://github.com/ELITEAYOTO/REL/pull/98) expanded the controlled temporary malformed PE rejection corpus from 13 to 21 cases (export RVA/count variants), with 3 trials per OS. [Exact main CI #39361179574](https://github.com/ELITEAYOTO/REL/actions/runs/39361179574) passed Windows/Ubuntu; representative licensed samples and full resource limits remain open under #9.
- [PR #99](https://github.com/ELITEAYOTO/REL/pull/99) moved only three import-only Python modules to `scripts/_internal/`; all CI/CLI entrypoint paths remain unchanged. [Exact main CI #39362984158](https://github.com/ELITEAYOTO/REL/actions/runs/39362984158) passed Windows/Ubuntu. No mass rewrite; [scripts layout](../../scripts/README.md) records what belongs where.

**Boundaries:** watchdog process-group cleanup is not a cgroup, full
process-tree kill guarantee or aggregate CPU/RSS/disk quota. Generated PE32
DLLs are never loaded/executed or committed to Git; source/binary
redistribution status is **not-established**, and the two frontends can share
linker, CRT and Windows SDK. Neither change completes #9. No public
`binary-manifest v1.0.0` change or production parser edit.

Earlier milestones:

| Work | Verified proof and status |
| --- | --- |
| Malformed PE resource observations | [#89](https://github.com/ELITEAYOTO/REL/pull/89), [main CI #39345880829](https://github.com/ELITEAYOTO/REL/actions/runs/39345880829): 13 controlled malformed cases, 39 expected rejects per OS; sample-based, not representative |
| EX-01 input and evidence | [#75](https://github.com/ELITEAYOTO/REL/pull/75), [#77](https://github.com/ELITEAYOTO/REL/pull/77): narrow source-backed producers/verifier, full #14 gate OPEN |
| EX-02 metadata-only pilot | [#62](https://github.com/ELITEAYOTO/REL/pull/62), [main CI #39305827604](https://github.com/ELITEAYOTO/REL/actions/runs/39305827604): pilot on main, full #15 gate OPEN |
| Watchdog stdout/stderr spool checks | [#79](https://github.com/ELITEAYOTO/REL/pull/79): sampled, NOT a hard disk quota |
| Pinned isolated fuzz toolchain | [#83](https://github.com/ELITEAYOTO/REL/pull/83), [main CI #39316683354](https://github.com/ELITEAYOTO/REL/actions/runs/39316683354): fuzz-specific dated nightly and Cargo-generated lock; scoped #12 CLOSED |
| Extended PE fuzz | [run #39318875380](https://github.com/ELITEAYOTO/REL/actions/runs/39318875380): 2,562,113 executions / 301 s, no crash in THAT run; temporary trigger-only PR #84 closed unmerged |
| Goblin TLS F001 | [#86](https://github.com/ELITEAYOTO/REL/pull/86) and [#88](https://github.com/ELITEAYOTO/REL/pull/88), [main CI #39340610502](https://github.com/ELITEAYOTO/REL/actions/runs/39340610502): historical 0.9.3 OOB reproduced; 1048-byte reduced witness, scoped #11 CLOSED |

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

At this snapshot the **9** open issues are:
[#8](https://github.com/ELITEAYOTO/REL/issues/8) fuzz diversity,
[#9](https://github.com/ELITEAYOTO/REL/issues/9) representative licensed
PE corpus and enforced resource limits,
[#14](https://github.com/ELITEAYOTO/REL/issues/14) full EX-01,
[#15](https://github.com/ELITEAYOTO/REL/issues/15) full EX-02,
[#16](https://github.com/ELITEAYOTO/REL/issues/16) owner source-license choice,
[#44](https://github.com/ELITEAYOTO/REL/issues/44) separate offline gameplay lab,
[#68](https://github.com/ELITEAYOTO/REL/issues/68) rel-diff resource budgets,
[#69](https://github.com/ELITEAYOTO/REL/issues/69) reproducible build hash drift,
[#72](https://github.com/ELITEAYOTO/REL/issues/72) supply-chain/CI pin review.

**First priority:** advance #9 beyond the controlled CI-built PE32 DLLs with a **license-cleared independently
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
