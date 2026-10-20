# REL — Current state and next-chat entry

**Checkpoint: 2026-10-20, after PR #118 and exact post-squash main CI.** This is a dated
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

## 1. Latest verified integration (dated checkpoint)

Repository: [ELITEAYOTO/REL](https://github.com/ELITEAYOTO/REL).
As checked on **2026-10-20**, `main` was
[`dcc87a225c6e52519c364caa1e991e12111e917e`](https://github.com/ELITEAYOTO/REL/commit/dcc87a225c6e52519c364caa1e991e12111e917e).
The **separate exact-new-main**
[CI #39388373089](https://github.com/ELITEAYOTO/REL/actions/runs/39388373089)
finished successfully on **Windows (170 s) and Ubuntu (82 s)**.
There were **zero open PRs and nine open issues** at this checkpoint.
This information is historical by design: query GitHub again before merging
or claiming a newer state.

Since the older #113 checkpoint, these scoped changes were integrated:

- [#114](https://github.com/ELITEAYOTO/REL/pull/114) reconciled verified
  Windows-native resource-accounting documentation; new-main
  [CI #39378958134](https://github.com/ELITEAYOTO/REL/actions/runs/39378958134)
  passed on `2e4c3a69`.
- [#115](https://github.com/ELITEAYOTO/REL/pull/115) fixed Windows venv
  redirector process identity **in controlled Python supervisor tests only**.
  Squash `e0e7a53f` passed
  [exact-main CI #39383597713](https://github.com/ELITEAYOTO/REL/actions/runs/39383597713).
- [#116](https://github.com/ELITEAYOTO/REL/pull/116) added dense/escaped
  import/export/section input oracles to the **existing** `rel-diff`
  CLI suite; squash `1dc06f85` passed
  [exact-main CI #39383179851](https://github.com/ELITEAYOTO/REL/actions/runs/39383179851).
  This did **not** add resource ceilings; #68 remains open.
- [#117](https://github.com/ELITEAYOTO/REL/pull/117) strengthened the
  deterministic PE mutation oracle to reject returned
  `PeError::DependencyPanic`, with **96** top-level import/export/TLS
  RVA/size mutations. Squash `88da2926` passed
  [exact-main CI #39385968827](https://github.com/ELITEAYOTO/REL/actions/runs/39385968827).
- [#118](https://github.com/ELITEAYOTO/REL/pull/118) added **96**
  in-memory mutations of import/export *internal table pointers* and a
  negative DLL-name RVA assertion. Exact PR HEAD `c5d9ffa1` passed
  [Windows/Ubuntu PR CI #39387949449](https://github.com/ELITEAYOTO/REL/actions/runs/39387949449)
  and a bounded [libFuzzer run #39387949435](https://github.com/ELITEAYOTO/REL/actions/runs/39387949435):
  555,662 executions over 31 s with no crash reported during that run.
  Squash `dcc87a22` passed the separate exact-main CI noted above.

**Remaining limits:** No new production parser correction was demonstrated
in #115–#118, and no PE submitted for inspection was executed. These
checks do not establish hostile-file security, full process-tree CPU/RSS
ceilings, complete TLS callback/import semantics or a legally cleared
representative PE corpus. No independent review approvals are claimed.
`binary-manifest v1.0.0` remains unchanged. #8, #9, #14, #15, #68
and licensing #16 remain open. Prior evidence and decisions continue below.

## 1a. Historical baseline before PR #114

Repository: [ELITEAYOTO/REL](https://github.com/ELITEAYOTO/REL).
Main at this dated checkpoint:
[958c1f40c4999149af7c4e1520cba9d33cf7de26](https://github.com/ELITEAYOTO/REL/commit/958c1f40c4999149af7c4e1520cba9d33cf7de26).
[Exact post-squash main CI #39378280259](https://github.com/ELITEAYOTO/REL/actions/runs/39378280259)
**completed/success on Windows AND Ubuntu**.
**Open PR count: 0. Open issue count: 9** at this dated checkpoint.

### Previously latest scoped integration (#113)

[PR #113](https://github.com/ELITEAYOTO/REL/pull/113) adds Windows direct-analyzer
native peak working set and final CPU through an owned duplicate of the
creation handle, without replacing sampled RSS/CPU or Linux wait4 fields.
Exact head `7d9f3aae293fb445bdf514ff48bec857acaeac6c` passed
[PR CI #39378024313](https://github.com/ELITEAYOTO/REL/actions/runs/39378024313)
and [branch CI #39377996849](https://github.com/ELITEAYOTO/REL/actions/runs/39377996849),
both Windows/Ubuntu. Squash
[958c1f4](https://github.com/ELITEAYOTO/REL/commit/958c1f40c4999149af7c4e1520cba9d33cf7de26)
passed separate [exact-main CI #39378280259](https://github.com/ELITEAYOTO/REL/actions/runs/39378280259)
on Windows/Ubuntu. Native Windows logs show all six tests passed, including
real rel-inspect with psutil sampling denied. The paired gate requires all
55 Windows measured runs (11 cases x 5) to contain valid native accounting;
Linux still requires its seven-case wait4 evidence. Original-handle closure,
immediate/nonzero exit and WinAPI failures are covered. Local controlled-child
tests also passed Windows 10 build 19045. No independent reviewer approval is
claimed; the author reviewed the scoped diff and checked exact CI evidence.

**Limits:** direct process only, no descendant totals; Windows working set
is neither committed memory nor a cross-OS equivalent of Linux ru_maxrss.
CPython private creation-handle dependency fails closed. No inspected PE
executes, no public contracts change, no new enforced budget or sandbox;
issue #9 remains OPEN. See [resource measurements](../P15_RESOURCE_PROFILING.md).

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

- [PR #100](https://github.com/ELITEAYOTO/REL/pull/100) reconciled the canonical dated handoff after #97–#99. [Exact main CI #39364083241](https://github.com/ELITEAYOTO/REL/actions/runs/39364083241) passed Windows/Ubuntu on 9ab3640. This documentation PR did not alter runtime behavior.
- [PR #101](https://github.com/ELITEAYOTO/REL/pull/101) expanded EX-02's independent output-budget oracle (accepted report >15 MiB, fail-closed above 16 MiB) and added a controlled mixed import/export/section resource-profile scenario. [Exact main CI #39364978891](https://github.com/ELITEAYOTO/REL/actions/runs/39364978891) passed Windows/Ubuntu on dc2fa60. Host-runner RSS/CPU results are sampled observations, **not** enforced parser resource ceilings; #68 and #15 remain open.
- [PR #102](https://github.com/ELITEAYOTO/REL/pull/102) made the libFuzzer target fail on `PeError::DependencyPanic` instead of swallowing it, verified byte-identical PE32/PE32+ fuzz seeds and strengthened legacy F001 regressions. Final-head [Windows/Ubuntu CI #39366136881](https://github.com/ELITEAYOTO/REL/actions/runs/39366136881) and [bounded libFuzzer CI #39366136892](https://github.com/ELITEAYOTO/REL/actions/runs/39366136892) passed; [exact post-squash main CI #39366427190](https://github.com/ELITEAYOTO/REL/actions/runs/39366427190) passed Windows/Ubuntu on a920c87. Fuzzer reported 455,715 executions/30 seconds with no crash **in that run**; #8 stays open.

Additional narrowly integrated follow-ups on 2026-10-20:

- [PR #104](https://github.com/ELITEAYOTO/REL/pull/104) now archives the bounded libFuzzer smoke log and exact provenance on success/failure and triggers on canonical seed-verification changes. Its exact final-head [fuzz CI #39368429610](https://github.com/ELITEAYOTO/REL/actions/runs/39368429610) and [Windows/Ubuntu PR CI #39368429622](https://github.com/ELITEAYOTO/REL/actions/runs/39368429622) passed; artifact `rel-pe-fuzz-smoke-39368429610-1` exists. Squash [6298979](https://github.com/ELITEAYOTO/REL/commit/6298979f7da08f6a1835af6b03a2a804e756488a) passed separate [main CI #39368846707](https://github.com/ELITEAYOTO/REL/actions/runs/39368846707). This does **not** expand the fuzz corpus or guarantee resource limits; #8 stays OPEN.
- [PR #105](https://github.com/ELITEAYOTO/REL/pull/105) adds a Rust serializer regression requiring all public v1 schema keys and explicit `null` for nullable `arch` and section `virtual_address`. Exact final-head [Windows/Ubuntu PR CI #39369050776](https://github.com/ELITEAYOTO/REL/actions/runs/39369050776) and separate [new-main CI #39369336388](https://github.com/ELITEAYOTO/REL/actions/runs/39369336388) passed on squash [6a7c354](https://github.com/ELITEAYOTO/REL/commit/6a7c354b9fc1fbd703e50538c5bd3a41ac04e010). No schema, runtime, dependency or behavioral change; the Python JSON Schema oracle remains the independent end-to-end validator.

- [PR #106](https://github.com/ELITEAYOTO/REL/pull/106) reconciled the canonical handoff and obsolete hypothetical `rel-diff` wording; [new-main CI #39370011224](https://github.com/ELITEAYOTO/REL/actions/runs/39370011224) succeeded on Windows/Ubuntu.
- [PR #107](https://github.com/ELITEAYOTO/REL/pull/107) reuses the controlled C source to build a GNU GCC/MinGW-w64 PE32+ x64 static sample on Ubuntu, adding a distinct compiler/linker lineage and an independent `pefile` full section-table oracle. Initial CI surfaced a COFF string-table name representation difference, handled in the **oracle**, not the parser; bounded long-name resolver has malformed-offset regressions on both OS. Exact-head [Windows/Ubuntu PR CI #39371723078](https://github.com/ELITEAYOTO/REL/actions/runs/39371723078) succeeded; squash [a9f8160](https://github.com/ELITEAYOTO/REL/commit/a9f816009dd00388118771c6a1b441be4582e1e1) passed separate [main CI #39371988276](https://github.com/ELITEAYOTO/REL/actions/runs/39371988276). JSON evidence only; redistribution `not-established`, APT/runner versions not immutable, #9 still OPEN.

- [PR #108](https://github.com/ELITEAYOTO/REL/pull/108) reconciled the last canonical handoff; [post-squash main CI #39372631425](https://github.com/ELITEAYOTO/REL/actions/runs/39372631425) succeeded Windows/Ubuntu.
- [PR #109](https://github.com/ELITEAYOTO/REL/pull/109) extended the existing paired CLI timing/child RSS+CPU profiling to the GNU MinGW-w64 PE, giving Ubuntu seven cases (Windows stays eleven) with source/toolchain/PE hash checks and negative regressions. Exact final-head [PR CI #39373542657](https://github.com/ELITEAYOTO/REL/actions/runs/39373542657), [fuzz #39373542617](https://github.com/ELITEAYOTO/REL/actions/runs/39373542617) and separate [new-main CI #39373817606](https://github.com/ELITEAYOTO/REL/actions/runs/39373817606) succeeded. Squash [addd5adf](https://github.com/ELITEAYOTO/REL/commit/addd5adf4ddbfa6f1094694a7efdb5c57805b6c0). Source PE never executed; sampled RSS/CPU are **not** actual peaks/ceilings, and cross-run compiled-byte equality is not guaranteed. Issue #9 remains OPEN.

- [PR #110](https://github.com/ELITEAYOTO/REL/pull/110) reconciled the resource and handoff docs; exact [new-main CI #39374595036](https://github.com/ELITEAYOTO/REL/actions/runs/39374595036) passed on Ubuntu/Windows.
- [PR #111](https://github.com/ELITEAYOTO/REL/pull/111) adds *Linux direct-child* `wait4` kernel high-water RSS and final CPU accounting to the existing resource profiler without replacing 2 ms samples, changing Windows or executing any inspected PE. After fixing a test which incorrectly re-waited a reaped child, exact final-head [branch CI #39375978891](https://github.com/ELITEAYOTO/REL/actions/runs/39375978891) and [PR CI #39375982940](https://github.com/ELITEAYOTO/REL/actions/runs/39375982940) passed Windows/Ubuntu; squash [7107a87](https://github.com/ELITEAYOTO/REL/commit/7107a874921a5db4efd8c9b70359efed2986dae6) passed separate [main CI #39376290685](https://github.com/ELITEAYOTO/REL/actions/runs/39376290685). Linux now requires complete kernel usage for seven cases in the paired-evidence gate; historic reports remain readable. No enforceable process-tree RAM/CPU budgets or licensed corpus; #9 OPEN.

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

## 2. Historical negative-PE campaign (#89); later expanded by #98

[Technical issue evidence](https://github.com/ELITEAYOTO/REL/issues/9#issuecomment-6280193664).
**Historical observation, not the current corpus count.** [PR #98](https://github.com/ELITEAYOTO/REL/pull/98) later increased the temporary controlled negative cases to **21**, with [main CI #39361179574](https://github.com/ELITEAYOTO/REL/actions/runs/39361179574) successful. The following retained observations belong specifically to [PR #89](https://github.com/ELITEAYOTO/REL/pull/89), which generated **13
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
