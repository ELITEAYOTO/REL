# REL — Handoff for next ChatGPT / contributor

## Fresh resume checkpoint — 2026-10-20 after PR #102

The canonical current-oriented source is [CURRENT_STATE.md](CURRENT_STATE.md).
This header is a **dated handoff**, not live GitHub state. On resumption,
read [AGENTS.md](../../AGENTS.md), architecture, roadmap, frozen decisions,
quality gates and [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md);
then **query GitHub live** before making changes.

**Last exact-main verification:** `a920c87a1f37171833d2b33d2104cc07515cf8fd`
([commit](https://github.com/ELITEAYOTO/REL/commit/a920c87a1f37171833d2b33d2104cc07515cf8fd)),
[CI #39366427190](https://github.com/ELITEAYOTO/REL/actions/runs/39366427190)
**completed/success on Windows + Ubuntu**. At the checkpoint: **0 open PRs,
9 open issues** (#72, #69, #68, #44, #16, #15, #14, #9, #8).

Recent integrations, each separately verified on its squashed `main`:
- [#98](https://github.com/ELITEAYOTO/REL/pull/98): 21 temporary
  synthetic malformed-PE cases, not a legally cleared representative corpus
  ([main CI #39361179574](https://github.com/ELITEAYOTO/REL/actions/runs/39361179574)).
- [#99](https://github.com/ELITEAYOTO/REL/pull/99): move three import-only
  helpers to `scripts/_internal/`, preserving script/CI entrypoints and
  avoiding an unnecessary mass move
  ([main CI #39362984158](https://github.com/ELITEAYOTO/REL/actions/runs/39362984158)).
- [#100](https://github.com/ELITEAYOTO/REL/pull/100): dated canonical
  documentation reconciliation
  ([main CI #39364083241](https://github.com/ELITEAYOTO/REL/actions/runs/39364083241)).
- [#101](https://github.com/ELITEAYOTO/REL/pull/101): EX-02 output
  boundary and mixed metadata profiling
  ([main CI #39364978891](https://github.com/ELITEAYOTO/REL/actions/runs/39364978891)).
  Metrics are runner observations, **not** RSS/CPU ceilings; #68 open.
- [#102](https://github.com/ELITEAYOTO/REL/pull/102): captured backend
  `DependencyPanic` is visible to libFuzzer; PE32/PE32+ fuzz copies
  must match pinned source hashes. Exact final PR-head
  [fuzz #39366136892](https://github.com/ELITEAYOTO/REL/actions/runs/39366136892)
  and [Windows/Ubuntu CI #39366136881](https://github.com/ELITEAYOTO/REL/actions/runs/39366136881)
  succeeded; the separate [new-main CI #39366427190](https://github.com/ELITEAYOTO/REL/actions/runs/39366427190)
  succeeded. Issue #8 remains open.

**Next technical priorities:** #9 — authorized license-cleared PE/DLL
corpus, independent oracles, enforceable resource limits; #8 —
extended coverage-guided campaigns, distinct crash triage and minimized
regressions; #68 — resource budgets and representative workload evidence.
#14/#15 are experimental **partial** gates. #16 (project license) needs
owner decision. #44 is a separate future authorized offline research
concept, **not** a mandate to alter REL or run game binaries.

**Development protocol:** one concrete defect or acceptance gate per PR;
no cosmetic reorganizations of `scripts/` and no new source file without
clear ownership. Preserve the public `binary-manifest v1.0.0` contract.
Never execute analyzed PE/DLL data. Require exact final-head tests,
Windows/Ubuntu CI and applicable independent or fuzz oracles **before**
squash; verify the **new** main CI separately. A caught dependency panic,
clean CI or bounded fuzz smoke is not evidence of arbitrary hostile-file
safety. Record outcomes and unknowns precisely.

**The archive below is historical.** Do not turn dated observations into
current claims or append another ever-growing snapshot for ordinary
checkpoint maintenance.

---

## Historical checkpoint — 2026-10-20 after PR #89

**READ [CURRENT_STATE.md](CURRENT_STATE.md) first.** This file is a
historical multi-session archive whose older status statements are
not automatically correct. For example EX-02 PR #62 is now merged,
scoped F001 #11 and reproducible fuzz #12 are closed, and the latest
malformed PE resource campaign #89 is integrated.

Main at this checkpoint:
[c9d092c](https://github.com/ELITEAYOTO/REL/commit/c9d092ccfc4d0a92edc0f5d70440ab2f977326a4).
[Postmerge Windows/Ubuntu CI #39345880829](https://github.com/ELITEAYOTO/REL/actions/runs/39345880829)
success; zero open PRs and ten open issues at that instant.
[Issue #9](https://github.com/ELITEAYOTO/REL/issues/9)
remains OPEN: 13 controlled malformed input cases, 39 expected
rejections per OS and sampled resources passed, but licensing and
representative EXE/DLL corpus diversity and genuine hard resource
isolation are still outstanding.

**Next chat:** fetch live GitHub state, read AGENTS/ROADMAP/ADR-0013,
then work on a measured missing gate in #9; avoid modifying public
contracts or adding unlicensed samples. If authorized to squash a PR,
verify final-head CI AND new main SHA postmerge CI. Preserve this
historical archive as provenance, not a live todo list.

---

> **Start with [CURRENT_STATE.md](CURRENT_STATE.md)** for the short, current-oriented resume protocol. This long file is a multi-session **historical archive** and its older "Immediate priorities" sections are not necessarily current. Query GitHub HEADs, PRs and CI again; never infer shipping status from these logs.

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
- **PARTIALLY BUILT (EXPERIMENTAL):** EX-01 has three narrow controlled-file producers (`dos-magic`, `coff-machine`, `section-headers`) plus a source-backed evidence verifier; see the later verified EX-01 sections and PRs #57/#59. EX-01 remains incomplete and does not establish atomic snapshots or hostile-input safety.
- **NOT SHIPPED ON `main`:** EX-02, Ghidra, advanced classifier, behavior lab, UI, graph engine. **EX-02 has a partially implemented draft PR #62** with a standalone Rust metadata comparer, independent versioned JSON output schema and CI oracle; this is not a completed acceptance gate. Inspect PR #62's **current** head and workflow results rather than trusting a historical snapshot. Do not silently mark these complete or change existing v1.0.0 schema.
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

## P1.5-A PE header preflight (verified, overall P1.5-A still open)

- New `crates/rel-pe/src/preflight.rs` validates conservative header bounds **before** goblin. Limits: NT header offset ≤1 MiB, 1–96 sections, optional header 2–4096 bytes and complete section-header table.
- No new crate, dependency or manifest v1.0.0 change. Golden + malformed + public API tests added. [PR #20](https://github.com/ELITEAYOTO/REL/pull/20) passed [Windows/Linux CI 39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717) and [fuzz 39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726), 642,364 fuzz cases over 31s. Remaining P1.5-A risks are still open.
- [Policy and security caveats](../security/P15A_PE_PREFLIGHT.md): parser imports/TLS/exports, CPU/RSS, arbitrary hostile-input processing and sandboxing remain **unresolved**. Some unusual parseable PEs may now be rejected.

## P1.5-A directory budget preflight (verified, overall P1.5-A incomplete)

- New `crates/rel-pe/src/preflight/directories.rs` bounds the *declared* import/export directory size to 1 MiB each and export count fields to 65,536; maps the 40-byte export directory header through raw section data.
- Header preflight, parser API and JSON v1.0.0 remain structurally unchanged; some unusual PE layouts may be rejected.
- Read [P15A_DIRECTORY_BUDGETS](../security/P15A_DIRECTORY_BUDGETS.md). A directory declaration cap is **not a parser CPU/RSS/allocations cap**. [PR #21](https://github.com/ELITEAYOTO/REL/pull/21) verified by [Windows/Linux CI #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688) and [libFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686), 586,015 executions/31s. This is only a declared-field budget, **NOT** a CPU/RSS/allocations guarantee; keep issue #9 open.

## P1.5-A atomic report publication (validated on PR CI)

Branch `fix/p15a-atomic-report-publish` stages the fully serialized report in a same-directory temporary file, syncs it and publishes via no-replace hard link. Target bytes remain complete on pre-publish write failure. Added unit/smoke regressions and [scope notes](../security/P15A_ATOMIC_REPORT.md). **[Windows/Linux PR CI #39107936412](https://github.com/ELITEAYOTO/REL/actions/runs/39107936412) succeeded; verify the post-merge `main` run before marking integrated.** The directory path may race, temporary cleanup can fail, separate hard links can alias an analyzed input, and a synced file alone does not guarantee crash-durable directory entries.


## P1.5-A raw section range preflight (PR CI verified)

Branch `fix/p15a-pe-section-raw-bounds` adds a narrow allocation-free check of non-empty PE raw section ranges against the byte slice before the goblin backend. Existing 1–96 section-table preflight is reused; virtual-only zero raw sizes remain permitted. Unit and public inspect tests are proposed. **Verified on [Windows/Linux CI #39108469504](https://github.com/ELITEAYOTO/REL/actions/runs/39108469504) and [libFuzzer #39108469495](https://github.com/ELITEAYOTO/REL/actions/runs/39108469495); confirm merged main independently.** No schema or dependency change; no CPU/RSS/hostile-input sandbox claim. Some unusual legal PEs may be rejected. See [preflight policy](../security/P15A_PE_PREFLIGHT.md) and [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).

## P1.5-A Unix final-component no-follow opening (verified on PR CI)

Branch `fix/p15a-unix-nofollow-open` changes only Unix CLI input opening to `O_NOFOLLOW | O_NONBLOCK`; still validates descriptor type and enforces 512 MiB actual-read cap. Unit regressions model a path switched to a final-component symlink and a no-writer FIFO. Windows behavior remains unchanged, as do PE parser and manifest schema. `libc = =0.2.191` (already in lockfile) is a new direct Unix-only dependency. **[Windows/Linux CI #39109205165](https://github.com/ELITEAYOTO/REL/actions/runs/39109205165) completed successfully for PR #24. Confirm post-merge `main` CI separately.** Not a sandbox: ancestor directories, Windows reparse points, same-length modifications, full IO stalls and CPU/RAM caps remain open.

## Windows final-component reparse-point guard (PR CI verified)

Branch `fix/p15a-windows-reparse-open`: CLI input `open_candidate` on Windows uses `FILE_FLAG_OPEN_REPARSE_POINT`, then rejects `FILE_ATTRIBUTE_REPARSE_POINT` on the same opened handle. Unix opening and parser stay unchanged. Windows tests cover normal regular files, swapping a final component into a symlink when creation is allowed (otherwise explicitly SKIP), and a directory substitution. Scoped CI on Windows/Linux passed [CI Windows/Linux #39146000935](https://github.com/ELITEAYOTO/REL/actions/runs/39146000935), including a focused Windows test that printed `PASS Windows final-component symlink was created and refused`. Check the **post-merge main run** independently before declaring integrated. Do **not** claim an arbitrary hostile-path sandbox: parent junctions, hard links, remote filesystems, same-length edits and worker CPU/RSS remain open. Manifest v1.0.0 preserved.

## P1.5-A Windows read-sharing increment (PR CI verified)

Branch `fix/p15a-windows-read-sharing` changes only Windows `open_candidate` to `FILE_SHARE_READ` while retaining `FILE_FLAG_OPEN_REPARSE_POINT`. Tests verify two simultaneous readers and denial of both new and existing conflicting write handles. Existing `read_open_file`, Unix logic, CLI behavior for ordinary static files, lockfile and manifest v1.0.0 are unchanged. **Verified in PR:** [Windows/Linux CI #39146872882](https://github.com/ELITEAYOTO/REL/actions/runs/39146872882) passed on Windows and Linux, including the native PE oracle and both targeted Windows writer-sharing tests. Inspect the post-merge `main` run before claiming integration. Existing writers can now cause a sharing error (intended alpha compatibility tradeoff). Memory mappings, driver/privileged changes, ancestor path races, true snapshots, CPU/RSS worker limits and diverse legal PE coverage remain unresolved. [Details](../security/P15A_BOUNDED_INPUT.md).

## P1.5-A opt-in bounded inspector watchdog (PR CI verified)

Branch feat/p15a-bounded-worker-watchdog adds a separate scripts/run_bounded_inspection.py entry point. It runs rel-inspect analyze (never the supplied PE) as a direct child with a default 30 s wall-clock kill, sampled RSS threshold (default 512 MiB), and captures stdout in a temporary file released only on success. Exit codes: 124 timeout, 125 sampled-RSS breach, 1 child/monitor/output failure. The Python test suite covers timeout, observed RSS, error isolation, stdout cap and actual fixture manifest compatibility. CI Windows/Linux runs it after psutil 7.0.0 installation. The implementation and regression suite passed [Windows/Linux PR CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060); **verify post-merge main CI independently before calling integrated.** Do not claim a kernel memory cap, a CPU-time budget, full descendant termination, bounded temporary-disk usage or arbitrary hostile-input isolation. Legacy direct REL CLI is unchanged. See [watchdog scope](../security/P15A_SUPERVISOR_V0.md) and issue #9.


## Linux opt-in RLIMIT_AS virtual address-space cap (scoped PR CI verified)

Branch `feat/p15a-linux-address-space-limit` adds a Linux-only `--max-address-space-mib` argument to the existing Python watchdog (not the Rust CLI). The wrapper sets child soft/hard `resource.RLIMIT_AS` before exec; tests check observed kernel limit and denied large allocation, plus a real REL PE64 manifest run with a 2048 MiB ceiling. Implemented and scoped regression tests passed [Windows/Linux PR CI #39149771201](https://github.com/ELITEAYOTO/REL/actions/runs/39149771201); verify final PR-head and post-merge main CI before calling integrated. Windows explicitly rejects the Linux-only flag; normal execution is unchanged. **This is virtual process address space, not a strict resident-memory/RSS limit, cgroup or multi-process sandbox.** Windows Job Objects, aggregate memory, CPU-time budgets, process descendants and disk quotas remain open in issue #9.

## Windows Job Object memory/process-tree increment (PR CI verified)

Branch `feat/p15a-windows-job-object` adds `scripts/windows_job.py` and optional watchdog `--max-job-memory-mib` (Windows only). Creates the analyzed CLI process **suspended**, configures aggregate job memory *commit* budget (not resident set / physical RSS) and KILL_ON_JOB_CLOSE, attaches and verifies job membership, resumes the main thread, then closes job at completion/failure to kill associated descendants. Native Windows tests cover a real REL manifest under 512 MiB, excessive allocation rejection, descendant termination after watchdog timeout, and fail-closed setup; Linux rejects the Windows option. Implementation and native regressions passed [Windows/Linux PR CI #39151722498](https://github.com/ELITEAYOTO/REL/actions/runs/39151722498) on Windows/Linux; **verify final-head PR and post-merge main CI before calling integrated.** Do not claim a sandbox: elevated/hostile code, process breakaway allowed in *ancestor* job, malicious handle inheritance/duplication, external mappings, cgroups, CPU-time and disk quotas remain unaddressed. See [supervisor V0](../security/P15A_SUPERVISOR_V0.md) and issue #9.


## P1.5-A Linux CPU-time RLIMIT_CPU increment (PR CI verified)

Branch `feat/p15a-linux-cpu-time-limit` extends the *opt-in* Python watchdog with Linux-only `--max-cpu-seconds` (1–300). `resource.RLIMIT_CPU` soft/hard limits N/N+1 seconds are applied to the analyzer child before exec, alongside existing optional RLIMIT_AS. Native tests check both kernel limits and SIGXCPU for a busy process; CLI flag rejection on Windows and a real PE64 manifest under both limits are included. No Rust crates or binary-manifest v1.0.0 changes. Linux native-limit and Windows negative-path checks passed [Windows/Linux CI #39152737826](https://github.com/ELITEAYOTO/REL/actions/runs/39152737826) and [CI #39152742301](https://github.com/ELITEAYOTO/REL/actions/runs/39152742301). **Verify final-head and post-merge main CI before declaring integrated.** This is per-process CPU time, not process-tree cumulative CPU, a scheduler quota or sandbox. Windows Job Object memory budgets, Linux virtual address space and the existing watchdog stay otherwise unchanged. Issue #9 remains open.

## P1.5-A controlled benchmark corpus case inventory (PR CI verified)

Branch `feat/p15a-corpus-provenance-baselines` adds `scripts/corpus_cases.py` and cross-platform `scripts/test_corpus_cases.py`. Both benchmark/profiler share verified existing PE32 and PE64 seed/overlay cases, stable case IDs/source hashes/explicit `redistribution_status=not-established`, and the current Windows CI-built REL binary (no committed third-party sample). Controlled inventory, tamper detection, unchanged Rust/schema/PE oracle and resource artifact uploads passed [Windows/Linux CI #39153900290](https://github.com/ELITEAYOTO/REL/actions/runs/39153900290) and [CI #39153927673](https://github.com/ELITEAYOTO/REL/actions/runs/39153927673). Check exact final PR-head and post-merge main CI before claiming verified. The project has no chosen LICENSE: origin records do NOT establish permission to redistribute. Diverse independent-compiler/legal corpus and calibrated budgets remain open in issues #9 and #16.

## P1.5-A CI-built MSVC PE source probe (PR CI verified)

Branch `feat/p15a-msvc-pe-corpus` adds `fixtures/probes/msvc_probe.c`, `scripts/build_windows_msvc_probe.cmd` and an independent pinned pefile oracle. Windows CI compiles MSVC x64 PE to ignored `compiler-probes/` (no checked-in binary), validates structural imports/exports, and passes the artifact to both profilers as an eighth case; Linux remains six cases. New corpus metadata records tracked C source hash, and measured binary hash in case report. The executable is **never run**. The compiler image may change, and binary/toolchain redistribution rights are **not established** (no repository LICENSE). The Windows x64 compile, independent pefile import/export oracle, six Linux cases, eight Windows cases, and both profilers passed [Windows/Linux CI #39155346166](https://github.com/ELITEAYOTO/REL/actions/runs/39155346166) and [CI #39155351313](https://github.com/ELITEAYOTO/REL/actions/runs/39155351313). Post-merge `main` must still be checked before declaring integrated. Real license-verified external samples, independent compiler families and robust complexity coverage remain open in issues #9 and #16.

## P1.5-A Clang-cl cross-frontend corpus increment (PR CI verified)

Branch `feat/p15a-clang-cl-compiler-probe` compiles `fixtures/probes/msvc_probe.c` with MSVC and Clang-cl in Windows CI. Both generated EXEs are **static data only** and are never executed. The pinned independent pefile oracle checks x64 headers, sections, `GetTickCount64` import and `rel_probe_transform` export for each. The corpus and both profilers gain `clang-cl-x64-local-build`, source SHA-256, binary SHA-256 and observed first-line compiler version; Windows rises from 8 to 9 cases, Linux remains at 6. Missing LLVM/compiler version must fail rather than skip. The implementation and corpus/regression tests passed [Windows/Linux CI #39156574382](https://github.com/ELITEAYOTO/REL/actions/runs/39156574382) and [CI #39156578707](https://github.com/ELITEAYOTO/REL/actions/runs/39156578707). Verify the exact final PR head and post-merge main CI before calling it integrated. No project license or toolchain pin is implied; compiler frontends may share the linker and Windows SDK. The independently licensed, genuinely representative external PE corpus remains open (#9/#16).

## P1.5-A Windows RC and base-relocation structural corpus (PR CI verified)

Branch `feat/p15a-structured-pe-rc-reloc` adds tracked `fixtures/probes/structured_probe.c` and `.rc` (RCDATA #101, initialized exported pointer for DIR64 relocation), Windows RC/MSVC/Clang-cl builds, and pinned pefile independent oracle. Generated PE files are never executed nor committed. Benchmark/profile tools gain 2 Windows structured cases (11 Windows / 6 Linux), each recording C/RC source SHA-256 and explicit unverified redistribution status. REL's v1.0.0 manifest is unchanged; pefile alone checks resource/relocation semantics, REL only checks section/exports and hash/size. The independent structural oracles and two-platform regression/measurement gates passed [Windows/Linux CI #39157915184](https://github.com/ELITEAYOTO/REL/actions/runs/39157915184) and [CI #39157910924](https://github.com/ELITEAYOTO/REL/actions/runs/39157910924). Verify final PR-head and post-merge `main` CI before calling integrated. Toolchains are not pinned and licensing is not established (#9/#16); P1.5-A remains open.

## P1.5-A paired measurement evidence integrity (PR CI verified)

Branch `feat/p15a-measurement-evidence-gate` adds independent `scripts/check_measurement_evidence.py` and `scripts/test_measurement_evidence.py`; CI validates/exports `rel-measurement-evidence.json` for paired per-OS benchmark and resource profiles, requiring 11 Windows or 6 Linux controlled cases, matching input SHA/size/source/licensing metadata and correct aggregates. Missing sampled RSS/CPU is **explicit**, never replaced with zero. No analyzer/input execution, public JSON manifest change or threshold. Implementation, Python negative-path tests and output uploads passed [Windows/Linux CI #39158995252](https://github.com/ELITEAYOTO/REL/actions/runs/39158995252) and [CI #39158999274](https://github.com/ELITEAYOTO/REL/actions/runs/39158999274). Verify the final PR head and post-merge `main` independently before calling this integrated. See [resource measurement docs](../P15_RESOURCE_PROFILING.md); no calibrated budgets or sandbox/representative corpus claims (#9/#16).

## P1.5-A measurement host identity (candidate; CI pending)

Branch `feat/p15a-hardware-provenance` adds `scripts/measurement_environment.py` for both benchmark and profiler, with canonical context SHA-256 and streamed exact analyzer binary hash. Reports describe observed CPU model/core/affinity, reported host RAM, kernel/platform, Rust compiler/cargo/Python/psutil, GitHub run/attempt and runner image version when available. The separate evidence gate rejects altered fingerprints and combining different runner jobs/binaries/toolchains, with negative tests. `psutil==7.0.0` is installed *before* benchmark/context tests on both platforms. This is not pinned host hardware, a security attestation, guaranteed memory quota or cross-run CPU/RSS budget. Verify final-head Windows/Linux PR CI, post-merge main CI, and update issue #9 with honest limits; manifest v1.0.0 unchanged.

## P1.5-A independent cross-campaign evidence comparison (PR CI verified)

Branch `feat/p15a-cross-campaign-evidence` adds an offline standalone `scripts/compare_measurement_campaigns.py` and negative-path tests. It reads two independent job pairs (`rel-benchmark.json` + `rel-resources.json`) and validates each via existing `build_evidence`. Distinct recorded GitHub run IDs are required; only run IDs/attempts are excluded from strict equality of all recorded host and toolchain fields, including the actual REL SHA and case SHA/provenance. If unequal, returns a list of blockers with **no ratios** (CLI writes evidence and exits 2). If compatible, reports descriptive median timing differences only. No RSS/CPU cross-run comparisons, hardware attestation, statistical threshold, input execution or native v1 schema change. CI uses synthetic tests; real repeated fixed-host experiments and license clearance remain open in issues #9/#16. Controlled comparison and negative-path Windows/Linux CI passed [Windows/Linux CI #39162247353](https://github.com/ELITEAYOTO/REL/actions/runs/39162247353) and [CI #39162250970](https://github.com/ELITEAYOTO/REL/actions/runs/39162250970). Verify final-head Windows/Linux CI and post-merge main before marking integrated.

## P1.5-A input-byte second-pass consistency increment (PR CI verified)

Branch `fix/p15a-second-pass-input-check` updates `tools/rel-inspect/src/input.rs` to rewind/re-read the initial max-512 MiB bytes using one 64 KiB scratch array and the same open descriptor, then re-check metadata. It rejects observable same-size content swaps and premature EOF before parsing. Four focused Rust tests (same-size replacement, multi-chunk stable bytes, truncation, empty) supplement original change/path tests. Unix no-follow and Windows leaf-reparse/read-sharing rules are preserved; no PE execution, new schema, dependency or parser modifications. **This is not a coherent filesystem snapshot**: content races can evade two reads, and I/O overhead increases. The 4 new focused Rust tests, plus format, lint, locked tests, Release, CLI smoke/oracle and benchmark/profile gates passed [Windows/Linux CI #39163640989](https://github.com/ELITEAYOTO/REL/actions/runs/39163640989) and [CI #39163645354](https://github.com/ELITEAYOTO/REL/actions/runs/39163645354) on both OSes. Verify the exact final PR-head and post-merge `main` CI before calling integrated. Keep #9 open.

## P1.5-A Unix input identity check — VERIFIED on main

[PR #39](https://github.com/ELITEAYOTO/REL/pull/39) merged as [`a2bb013`](https://github.com/ELITEAYOTO/REL/commit/a2bb013a9d1c20d7c6de50853f93ce6f3b61d907). Unix `st_dev/st_ino` equality check between path preflight and opened-handle metadata rejects observable same-size/same-mtime file replacement. Targeted unit tests, formatting, Clippy, locked workspace, Windows PE oracle and CLI smoke passed final-head [PR CI #39165266295](https://github.com/ELITEAYOTO/REL/actions/runs/39165266295) and [main CI #39165446361](https://github.com/ELITEAYOTO/REL/actions/runs/39165446361), both Windows/Linux. No coherent snapshot or Windows identity guarantee.

## P1.5-A Unix no-follow ancestor walk — VERIFIED on main

[PR #40](https://github.com/ELITEAYOTO/REL/pull/40) merged as [`86cba02`](https://github.com/ELITEAYOTO/REL/commit/86cba02d64ffa0ace6290615fc7135d46875df12). The new `tools/rel-inspect/src/input/unix_open.rs` uses descriptor-relative Unix `openat` on path components, refusing ancestor and leaf symlinks; three regression tests verify ordinary nested input, a parent symlink, and an ancestor swap after preflight. [Final PR CI #39165747222](https://github.com/ELITEAYOTO/REL/actions/runs/39165747222) and [post-merge main #39165928503](https://github.com/ELITEAYOTO/REL/actions/runs/39165928503) passed Windows/Linux. It may reject execute-only parent directories or symlinked paths, keeps `..` allowed, and is not root-confined or snapshot-safe. Windows ancestor reparse/junction policy and broader resource safety remain open in issue #9. Preserve `binary-manifest v1.0.0`.

## P1.5-A Windows ancestor reparse observations — MERGED, CI VERIFIED

[PR #42](https://github.com/ELITEAYOTO/REL/pull/42) merged as [`144657c`](https://github.com/ELITEAYOTO/REL/commit/144657c2428039aff2a24680a12ac8f6fffd8c59) and completed [post-merge main CI #39167703067](https://github.com/ELITEAYOTO/REL/actions/runs/39167703067) successfully on Windows/Linux. The new `tools/rel-inspect/src/input/windows_path.rs` checks `FILE_ATTRIBUTE_REPARSE_POINT` on Windows ancestor paths both before initial leaf preflight and directly after guarded leaf acquisition, rejecting observable junctions/links. Windows PR logs from [#39167525417](https://github.com/ELITEAYOTO/REL/actions/runs/39167525417) confirm three tests passed: ordinary nested input, real `mklink /J` junction, deterministic after-stat junction substitution. No new dependencies, Unix change or JSON manifest v1.0.0 change.

**Do not overclaim:** this is not an atomic Windows directory walk. Restore/swap races, regular-directory substitution, hard links, namespace/remote filesystem behavior, in-place writes and broader CPU/RAM containment remain unresolved; legitimate junction-backed paths may now fail. [Issue #9](https://github.com/ELITEAYOTO/REL/issues/9) stays open. Next study Windows path identity and/or process resource enforcement as a separate evidence-backed gate.

## P1.5-A Windows 128-bit opened-handle identity — MERGED, CI VERIFIED

[PR #45](https://github.com/ELITEAYOTO/REL/pull/45) merged as [`d1102f7`](https://github.com/ELITEAYOTO/REL/commit/d1102f7def2c86801f9a6d3688a214fb312c82e3). Final-head [push #39171652919](https://github.com/ELITEAYOTO/REL/actions/runs/39171652919), [PR #39171656519](https://github.com/ELITEAYOTO/REL/actions/runs/39171656519) and [post-merge main #39171804456](https://github.com/ELITEAYOTO/REL/actions/runs/39171804456) all passed Windows/Linux. The Windows log shows three new real filesystem regressions passed (same-file handles, distinct files with identical length and mtime, hard-link aliases). A new `tools/rel-inspect/src/input/windows_identity.rs` calls Win32 `GetFileInformationByHandleEx(FileIdInfo)` through minimal documented FFI and checks volume+full 128-bit file identity of the opened input against a subsequent guarded path open, fail-closed on mismatch or unavailable IDs. No dependencies, parser, Linux or manifest v1.0.0 modifications.

**Do not overclaim:** this is a post-open observation; original `symlink_metadata` is not bound to that identity. Fast/privileged swaps, mutable file contents and Windows ancestor path races remain possible; unsupported filesystem IDs cause compatibility failures. A second open adds unmeasured I/O overhead. Keep issue #9 open and resume critical hardening or the evidence/coverage pilot only according to ADR-0013 gates.

## P1.5-A complete declared PE directory record coverage — MERGED, CI VERIFIED

[PR #47](https://github.com/ELITEAYOTO/REL/pull/47) merged as [`f26b34d`](https://github.com/ELITEAYOTO/REL/commit/f26b34d557e5bd892a7855bc253a6b07880c9709). The allocation-free preflight check `crates/rel-pe/src/preflight/directories.rs` rejects `NumberOfRvaAndSizes` that claims more 8-byte records than fit in the optional header. Earlier code checked only the first one/two slots. Exact-capacity and over-capacity regressions exercise PE32 and PE32+, plus a public `rel_pe::inspect` failure; Windows job logs showed the new tests as `ok`. [Final PR CI #39173751519](https://github.com/ELITEAYOTO/REL/actions/runs/39173751519), [bounded fuzz CI #39173751518](https://github.com/ELITEAYOTO/REL/actions/runs/39173751518) and [post-merge main #39173973900](https://github.com/ELITEAYOTO/REL/actions/runs/39173973900) succeeded on their respective environments. No parser, ABI, manifest v1.0.0 or dependency change.

**Scope:** declaration inconsistency only, not an import-thunk bound, parse-time CPU/RSS isolation, universal PE validation or arbitrary hostile-binary sandbox. Preserve the existing roadmap order P1.5 critical → EX-01 → EX-02, and leave [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) open.

## EX-01 contract-only envelope and validator — MERGED, SCOPED CI VERIFIED

[PR #49](https://github.com/ELITEAYOTO/REL/pull/49) merged as [`bbbec20`](https://github.com/ELITEAYOTO/REL/commit/bbbec203409c478462b6fd8398640f868ee9c3c7). Final-head [push CI #39176068549](https://github.com/ELITEAYOTO/REL/actions/runs/39176068549), [PR CI #39176105548](https://github.com/ELITEAYOTO/REL/actions/runs/39176105548), and [post-merge `main` CI #39176279141](https://github.com/ELITEAYOTO/REL/actions/runs/39176279141) succeeded on Windows/Linux. The Windows logs include five golden `present / absent_in_scope / partial / failed / unsupported` examples and the legacy manifest v1 isolation check.

Standalone `contracts/experimental/observation-envelope.schema.json` (`0.1.0-experimental`), Python semantic validation and five hand-authored examples based on owned PE32 fixture bytes are available. These validate report shape, integrity and specifically scoped negative observations, **not** an actual extraction engine or truth of arbitrary reports. The existing Rust CLI remains v1-only, no manifest v1.0.0 change. Next implement a minimal controlled-source EX-01 producer that computes actual byte evidence and reproducible run IDs; only then consider broader extraction/coverage. **Overall EX-01, P1.5-A, EX-02, Ghidra and P3 remain open.** [Issue #14](https://github.com/ELITEAYOTO/REL/issues/14) tracks EX-01.

## EX-01 first real controlled-source DOS-magic producer — MERGED, SCOPED CI VERIFIED

[PR #51](https://github.com/ELITEAYOTO/REL/pull/51) merged as [`10f38c8`](https://github.com/ELITEAYOTO/REL/commit/10f38c807668a6a7b5afd46c4d1936afc7125109). Final-head [branch CI #39179309964](https://github.com/ELITEAYOTO/REL/actions/runs/39179309964), [PR CI #39179314336](https://github.com/ELITEAYOTO/REL/actions/runs/39179314336) and [post-merge `main` CI #39179499279](https://github.com/ELITEAYOTO/REL/actions/runs/39179499279) passed on both Windows and Linux. Windows/Linux real binary smoke logs explicitly show the producer's SHA, byte-evidence, deterministic run-ID and unsupported/short/oversize rejection assertions succeeding.

New standalone Rust `tools/rel-observe` CLI (Cargo workspace+lock) emits `0.1.0-experimental` observations from real controlled PE32/PE32+ bytes. It reports file SHA and size, verified two-byte offsets, and a run-ID built from file/config/domain/version with Python independent verification. The **only** truthful claims are `MZ` present and `NE` absent at DOS offsets [0,2); a two-byte negative conclusion is not about imports or program capability. A 2 MiB limit applies, with minimal MZ/PE signature checks and no hostile-input sandbox or atomic file snapshot. Files are **never executed**. `rel-inspect` and `binary-manifest v1.0.0` remain unchanged.

[Issue #14](https://github.com/ELITEAYOTO/REL/issues/14) remains open: broader real extraction domains, confidence/coverage semantics and failure-mode output still required. P1.5-A [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) remains open. EX-02, external Ghidra integration and function matching not implemented; preserve ADR-0013 ordering. Next choose a single provable static PE-domain expansion with fixtures, error/abstention cases and independent validation, not Apex-specific reverse engineering.

## EX-01 COFF Machine observation and scoped partial abstention — MERGED, CI VERIFIED

[PR #53](https://github.com/ELITEAYOTO/REL/pull/53) merged to `main` as [`e60e978`](https://github.com/ELITEAYOTO/REL/commit/e60e978fb7f6359122ae817f853b4629b8a34ab2). Final-head [branch #39182119983](https://github.com/ELITEAYOTO/REL/actions/runs/39182119983) and [PR #39182124339](https://github.com/ELITEAYOTO/REL/actions/runs/39182124339) both passed Windows/Linux, and [post-merge `main` CI #39182313199](https://github.com/ELITEAYOTO/REL/actions/runs/39182313199) succeeded on both platforms. Actual cross-platform Python oracle logs show `PASS EX-01 COFF Machine: real offsets, partial abstention, deterministic ID`.

`rel-observe coff-machine` observes **only** the two-byte little-endian COFF Machine field at file offset `e_lfanew + 4` on owned controlled PE32/PE32+ inputs. It reports actual byte-offset evidence, subject SHA, deterministic domain/config-specific run ID, and cautiously normalizes `0x014c` / `0x8664` to x86 / x86_64. Unknown values remain raw hex. If zero/one bytes remain after a valid four-byte PE signature, it emits scope `partial` with `indeterminate`, null values, no decisive evidence, and `COFF_MACHINE_TRUNCATED` warning. Invalid DOS/PE framing is rejected without JSON rather than misrepresented as a complete observation.

Shared provenance and controlled file reader preserve the old `dos-magic` output and run ID (legacy oracle passes). No dependencies, `rel-inspect` or `binary-manifest v1.0.0` changes. **Do not overclaim:** the observed field is not entire PE validity, runtime architecture compatibility, decompilation, safety against hostile input or any gameplay capability. P1.5-A [#9](https://github.com/ELITEAYOTO/REL/issues/9) and overall EX-01 [#14](https://github.com/ELITEAYOTO/REL/issues/14) remain open. EX-02, Ghidra integration and function matching follow the existing roadmap.

## EX-01 declared PE section headers — MERGED, SCOPED CI VERIFIED

[PR #55](https://github.com/ELITEAYOTO/REL/pull/55) merged at [`c6ca1bb`](https://github.com/ELITEAYOTO/REL/commit/c6ca1bbd57fb0a721736c150338d858a8a081e6d). Final-head [branch CI #39184173861](https://github.com/ELITEAYOTO/REL/actions/runs/39184173861) and [PR CI #39184179438](https://github.com/ELITEAYOTO/REL/actions/runs/39184179438) passed Windows/Linux; independent Python oracle logs on both platforms show `PASS EX-01 section headers: exact 40-byte proofs, limits, partial abstention, reproducible ID`. [Post-merge main CI #39184367267](https://github.com/ELITEAYOTO/REL/actions/runs/39184367267) **also passed on Windows and Linux**. First head had rustfmt/Clippy failures, corrected on final tested head `878a6c1`; do not cite the earlier failures as final run status.

Third real `rel-observe` domain `pe.section_headers` observes at most 32 declared 40-byte COFF section headers after the optional header. It reports SHA-bound file-offset evidence, original 40-byte hex per record and bounded normalized name bytes (hex), RVA/virtual size, raw file pointer/size and flags. Incomplete COFF, optional header, or any declared section record yields `partial/indeterminate`, no decisive record proof and warning. Count >32 yields `unsupported`; zero declared sections yields `absent_in_scope` backed by two count bytes only if header span is present. No new dependencies or `binary-manifest v1.0.0` changes; DOS/COFF prior CLI regressions remained green.

This is **header data observation only**: no proof that section payloads/RVAs are valid, no executable behavior analysis, no safe arbitrary-hostile binary sandbox, and no decompilation. Overall EX-01 [issue #14](https://github.com/ELITEAYOTO/REL/issues/14) and P1.5-A [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) remain open. Future work should prioritize evidence quality, resource containment, and broaden analysis deliberately before EX-02/P2/P3.

## EX-01 source-backed evidence verifier — MERGED, SCOPED CI VERIFIED

[PR #57](https://github.com/ELITEAYOTO/REL/pull/57) merged at [`6e18d37`](https://github.com/ELITEAYOTO/REL/commit/6e18d373c27571928b1d38b8815701dec0de41f6). Final-head [branch CI #39186120971](https://github.com/ELITEAYOTO/REL/actions/runs/39186120971) and [PR CI #39186154113](https://github.com/ELITEAYOTO/REL/actions/runs/39186154113) passed Windows/Linux, with test logs on both systems showing `PASS EX-01 independent evidence audit and falsification regressions`. [Post-merge `main` CI #39186361225](https://github.com/ELITEAYOTO/REL/actions/runs/39186361225) **also passed Windows/Linux**.

The new opt-in standalone `scripts/verify_observation_evidence.py` independently cross-checks a saved `0.1.0-experimental` report against a caller-supplied controlled source binary (≤2 MiB). For `pe.dos_magic`, `pe.coff_machine` and `pe.section_headers`, it validates schema and source length/SHA, deterministic config/run ID, all raw+normalized values, precise evidence offsets/lengths/methods, observation counts and scope/diagnostic truth claims. Deliberate falsification tests reject fake records, shifted proof offsets, wrong identities, false negative and false complete claims and incorrect truncation diagnostics. Unknown domains or producers are rejected, not guessed.

**Limits:** agreement between a report and supplied bytes is NOT proof of authenticity, publisher identity, digital signature, file snapshot atomicity, supply-chain integrity, general PE correctness, sandbox safety or program behavior. A party controlling both report and file can produce matching contents. No Rust extractor, `binary-manifest v1.0.0`, experimental schema, dependency, or architecture changes. Keep overall EX-01 [#14](https://github.com/ELITEAYOTO/REL/issues/14) and P1.5-A [#9](https://github.com/ELITEAYOTO/REL/issues/9) open. Continue toward deliberate coverage/provenance and resource limits, then EX-02 under ADR-0013.

## EX-01 same-descriptor second-pass consistency — MERGED, SCOPED CI VERIFIED

[PR #59](https://github.com/ELITEAYOTO/REL/pull/59) merged as [`d435b15`](https://github.com/ELITEAYOTO/REL/commit/d435b15e3c8dd43b8b846ce376f4468f18555afa). Final-head [branch CI #39188698531](https://github.com/ELITEAYOTO/REL/actions/runs/39188698531), [PR CI #39188703138](https://github.com/ELITEAYOTO/REL/actions/runs/39188703138) and [post-merge `main` CI #39188909312](https://github.com/ELITEAYOTO/REL/actions/runs/39188909312) **passed on Windows/Linux**. Initial branch head failed only `rustfmt`; corrected final code head `f3300ca` passed tests, lint and all existing CLI oracles. The Rust test helpers confirm that a 64-KiB scratch-buffer second pass rejects observed changed first/chunk-boundary/final bytes, early EOF and appended bytes.

`rel-observe` now re-reads the ≤2 MiB controlled binary from the **same already-open file descriptor** after seeking back to offset 0. It compares bytes to the first pass, rejects trailing bytes, and checks initial/final file size and modification timestamp when available. This preserves existing report JSON, run IDs, configs, input budgets and existing DOS/COFF/sections/verifier tests. The second pass increases successful input IO to roughly twice the original; it is not a second in-memory full-file copy.

**Critically not an atomic snapshot**; concurrent writers can interleave or revert changes. No descriptor-confined ancestor path traversal, guaranteed leaf symlink race protection, arbitrary-hostile-input isolation, hard RSS/CPU limits or completed P1.5-A. Keep [P1.5-A #9](https://github.com/ELITEAYOTO/REL/issues/9) and [EX-01 #14](https://github.com/ELITEAYOTO/REL/issues/14) OPEN; after this, prioritize realistic resource isolation and path consistency (not speculative security guarantees), then planned EX-02/P2/P3.
