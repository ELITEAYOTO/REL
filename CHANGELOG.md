# Changelog

## [Unreleased] — Honor PE import section-table precedence (P1.5, #172)

- A test-only PE32/PE32+ synthetic overlap keeps a valid import descriptor in an earlier section's **file-aligned padding** but adds a later section whose strict raw mapping of the same RVA points to an unrelated zero record. Goblin reads the earlier section. The former REL preflight silently missed a malformed import `Name=0` in the earlier record: [fail-first CI #39710380761](https://github.com/ELITEAYOTO/REL/actions/runs/39710380761), test-only SHA `e0fec9c7e49f930155ad8995732537d76914979d`.
- Resolve import RVA mappings **in section-table order**, whether they are strictly raw-mapped or conservatively file-aligned. Continue to delegate genuinely unsupported layouts, use the existing descriptor scan budget, preserve the synthetic fixtures and immutable `binary-manifest v1.0.0`. This does not constitute a general PE mapping equivalence proof or sandbox.


## [Unreleased] — Check file-aligned PE import RVA padding (P1.5)

- Fail-first controlled PE32/PE32+ variants move an import descriptor to RVA `0x2014` while the section declares 16 raw bytes. The backend maps its file-aligned padding and reads imports; setting the descriptor's `Name` to zero was silently accepted on PE32 (test-only SHA `a246919e8342c53a3e8c43f3d8fd526d16967274`, Ubuntu CI #39708868057).
- Extend the existing preflight only for clearly aligned, file-backed section padding matching the parser's bounded mapping rules; retain truly nonmappable delegation, unchanged original fixtures, manifest v1.0.0 and all scan/resource limits. This focused guard does **not** assert complete import extraction, generalized PE format validity or a CPU/RAM sandbox.


## [Unreleased] — Check initial import descriptors straddling a raw-section boundary (P1.5)

- Test-only PE32/PE32+ positive controls retain imports and exports when the section contains only the first 16 bytes of the initial 20-byte descriptor; the strict backend still maps its initial RVA and reads the full contiguous record. Negative controls zero `Name` or `FirstThunk` and expose an accepted, incomplete import observation (PE32 fail-first SHA `9fa341ac1275c11c604b8d2cac23d31ca0ed9695`, Ubuntu CI #39707078470).
- Map the first **byte** of the import RVA before the bounded sequential file-offset scan instead of requiring all 20 descriptor bytes to fit the section's advertised raw size. Preserve explicit fallback for truly unmappable initial RVAs, the scan cap, unchanged fixtures, and the immutable `binary-manifest v1.0.0`. This is no global import/CPU/RAM correctness or security guarantee.

## [Unreleased] — Traverse actual contiguous raw import records across section boundaries (P1.5)

- Fail-first PE32 regression (PR #169) confirmed an accepted, truncated import observation when a malformed second descriptor lies beyond the first raw section's declared span but remains contiguous in file bytes consumed by Goblin. The controlled PE32/PE32+ positive case preserves valid imports and exports; no fixture bytes change.
- After the first RVA maps, preflight validates sequential file-offset descriptor records up to the existing 52,428-record cap, instead of remapping every successor RVA. Preserve the initial RVA fallback, manifest v1.0.0, no additional dependency or full parser sandbox claim. Final Windows/Ubuntu PR CI #39704450435 and bounded fuzz #39704450419 passed; distinct post-merge push CI must be assessed separately.

## [Unreleased] — Keep zero-Size import directories inside bounded preflight (P1.5)

- A PE32/PE32+ in-memory regression demonstrates that a nonzero import RVA with declared `Size=0` can still expose imports through the backend, but a non-null descriptor with missing `Name` could silently truncate those observations.
- Apply the already bounded, raw-mappable descriptor check whenever the import RVA is nonzero, preserving true absent pairs, unmappable delegation, existing tests, `binary-manifest v1.0.0` and binary fixture identities.

## [Unreleased] — Distinguish unmappable PE import RVAs from descriptor scan exhaustion (P1.5)

- Red/green PE32 and PE32+ regression for an unmappable initial import descriptor and a valid first descriptor followed by an unmappable slot; this situation was incorrectly reported as if the 1 MiB descriptor scan had been exhausted.
- Restore preflight delegation to the backend on a raw-unmappable descriptor and reserve the cap diagnostic for actual traversal exhaustion. No new PE fixture, public v1 schema, dependency or resource limit.

## [Unreleased] — Bound import descriptor checks beyond understated Size (P1.5)

- Reproduce a valid two-descriptor PE32/PE32+ whose import-directory `Size` advertises only the first record, then show that corrupting the second `Name` allows silent import truncation. Preserve the test-only fail-first evidence.
- Scan contiguous raw-mappable import descriptors to their zero terminator (or up to 1 MiB of complete records) rather than trusting the declared size as a traversal bound; retain clean errors for missing required fields and an explicit error at the cap. No PE fixture, public v1 schema, dependency or isolated worker budget change.

## [Unreleased] — Inspect declared span of PE import descriptors (P1.5)

- A test-only branch demonstrated that a malformed **second** import descriptor with `Name=0` was accepted as if import enumeration had finished. The positive control duplicates a valid import descriptor in PE32/PE32+ without altering fixture bytes on disk.
- Iterate only whole descriptor records within the advertised import-directory byte span (up to the existing 1 MiB declaration cap), checking required `Name` and `FirstThunk` fields and stopping at an all-zero terminator. Preserve raw-unmappable delegation, the original first-record behavior, `binary-manifest v1.0.0`, fixture hashes and dependency pins; this is not complete table validation or a security sandbox.

## [Unreleased] — Reject malformed first PE import descriptor (P1.5)

- A fail-first regression on controlled PE32/PE32+ fixtures found that a non-null first import descriptor with missing `Name` or `FirstThunk` could be accepted with a misleadingly incomplete imports list.
- Check the first raw-section-mapped descriptor before Goblin extraction and return a parse error on missing required fields. Preserve the all-zero terminator and document the narrow mapping/scope limits. No changes to original fixture bytes, parser dependency, `binary-manifest v1.0.0` or worker/resource policy.

## [Unreleased] — Explicit delay-import coverage warning (P1.5)

- A test-only PE32/PE32+ regression demonstrates that a declared delay-import data directory did not produce a v1 coverage warning even though only ordinary imports are enumerated. The first test-only CI failed at the warning assertion (after correcting formatting); no hostile PE safety or actual delayed symbol decoding is claimed.
- Preserve the ordinary `imports[]` names and `binary-manifest v1.0.0` schema. Use Goblin's existing optional-header directory accessor to warn that delayed imports are not enumerated when the PE advertises a nonempty delay-import directory. This is a declaration/coverage observation, **not** validation of the referenced directory bytes or an inference about the program's behavior.
- Retain existing PE fixtures, SHA-256, fuzz witnesses and all resource limits. Do not add a parser dependency, a new crate or an EX-02 schema variant; consumers already abstain on warnings.

## [Unreleased] — Reject nonempty PE import directories with no RVA (P1.5)

- A test-only preflight regression reproduced an observable gap: a PE32/PE32+ import directory with a nonzero declared size but zero RVA was accepted by the preflight as `Ok(())`. This is an inconsistency in declared header evidence, not proof of a demonstrated memory vulnerability or downstream parser omission.
- Check import RVA/size consistency in the existing allocation-free directory preflight; reject a zero RVA with nonzero size, while preserving the accepted explicitly absent (0,0) declaration. Add public `rel-pe::inspect` regressions for both original fixture-derived PE bitnesses.
- No change to `binary-manifest v1.0.0`, producer rights, original PE fixtures/hashes, worker budgets, dependencies or module layout. Deliberately leave nonzero-RVA/zero-size policy and comprehensive import completeness out of scope pending representative corpus evidence.

## [Unreleased] — Disambiguate ordinal-only import coverage (P1.5)

- The existing v1 `imports` strings cannot distinguish a real symbol named `ORDINAL 42` from Goblin's synthetic representation of an import-by-ordinal. Previously both returned `warnings=[]`, potentially presenting ambiguous import evidence as definitive.
- On controlled in-memory PE32 and PE32+ fixture derivatives, replace only the first ILT/IAT entries with an ordinal reference; require a warning while preserving the v1 string output. A separate positive named-symbol regression spells `ORDINAL 42` as actual hint/name text and must remain warning-free. Detect the parsed ordinal variant rather than matching the string.
- Keep public `binary-manifest v1.0.0`, old fixture bytes/SHA-256, static-only inspection, parser dependencies and existing export warning unchanged. This narrows one evidence ambiguity, not a general hostile-PE, import completeness or resource guarantee.


## [Unreleased] — Flag unrepresented export address slots (P1.5)

- Address a v1 export-evidence completeness gap: the parser previously omitted unnamed Goblin export entries via `filter_map` and returned an empty warning list even when the export address table exceeded the name-pointer table. This can conceal ordinal-only exports or unrepresented address slots.
- Preserve **binary-manifest v1.0.0** and every named export exactly. Warn when Goblin exposes an unnamed entry or `address_table_entries > number_of_name_pointers`. An extra EAT slot can be unused; the warning deliberately does not claim every slot is a live ordinal export.
- Add a controlled PE32 regression mutating only the synthetic export name-pointer count and requiring no fabricated name and a warning; preserve warning-free expectations for both untouched golden formats. No tracked binary fixture, dependency, new module or PE execution.

## [Unreleased] — Fixed SOURCE_DATE_EPOCH GNU DLL reproducibility experiment (#69)

- Compare two more **source-built controlled PE32+ AMD64 MinGW-w64 DLLs** inside the existing Ubuntu job, with the same source, output path, GCC flags, nonzero `SOURCE_DATE_EPOCH=1700000000` and explicit `-Wl,--insert-timestamp`. Preserve the original normal-timestamp pair as the control.
- Reuse the existing pinned independent `pefile` field and raw-byte evidence checker to record first/second SHA-256, exact observed COFF/export directory timestamps and all changed-byte categories, without modifying binaries or normalizing hashes. The optional experiment mode records whether all four independently decoded timestamp observations equal the supplied epoch and whether the two raw DLLs are byte-identical; **neither finding is assumed in advance**.
- Add two portable invalid/valid epoch input regressions. The evidence is an extra JSON file inside the historical MinGW oracle artifact, not a new CI job or file fixture. Do not treat a nonzero timestamp in a temporary DLL as a safe general DLL release policy; no performance, hostile-input or cross-run reproducibility guarantees.
- No parser Rust changes, dependency, executable invocation, public `binary-manifest v1.0.0` revision or source licence decision.

## [Unreleased] — Map GNU DLL export timestamp and checksum bytes (#69)

- Refine existing PE32+ GNU MinGW-w64 same-job raw-byte drift evidence using independent pinned `pefile` field offsets for `IMAGE_EXPORT_DIRECTORY.TimeDateStamp` and `OPTIONAL_HEADER.CheckSum`. Compare the decoded u32 values directly with the exact source bytes and refuse absent or inconsistent fields or mismatched build field offsets.
- Prior generic `section:.edata` and `header-or-overlay` labels now resolve to their actual structured fields where observable; preserve full raw SHA-256, total changed-byte counts, original source evidence and all other diagnostic categories. Do not assert a timestamp *caused* a build difference or that builds are behaviorally equivalent.
- Add positive/negative tests for mapped timestamp/checksum classification and unmapped changes. Reuse existing Ubuntu controlled DLL evidence and both-OS Python regression step: no new CI job, artifact name, parser change, PE execution, dependency, fixture or public `binary-manifest v1.0.0` change.

## [Unreleased] — GNU MinGW-w64 DLL same-job byte-drift evidence (#69)

- Add a bounded, static-only repeat-build diagnostic for the **already controlled** PE32+ AMD64 MinGW-w64 DLL, to investigate observed cross-run raw SHA-256 drift. Rebuild the same source and flags at the same output path in one Ubuntu CI job, retaining the first file only temporarily and never uploading either binary.
- Reuse existing EX-02 direct PE-field and byte-region helpers to record both **raw SHA-256** values, section/header/debug observations, differing byte ranges and their first-file categories without normalizing or claiming a root cause. Record GCC/linker/package versions and runner image metadata in a third JSON within the **existing MinGW oracle artifact**.
- Add four synthetic regressions for identical bytes, COFF/debug timestamp fields, section differences and trailing data, executed on Windows and Ubuntu. No parser, v1 manifest, compiler dependencies, new CI job or executable behavior changes. Cross-run reproducibility, independent third-party corpus rights and CPU/RAM caps remain open.

## [Unreleased] — GNU MinGW-w64 PE32+ DLL corpus probe (P1.5)

- Add a GNU MinGW-w64-linked **AMD64 PE32+ DLL** static probe on Ubuntu using the already tracked C source, complementing existing GNU x64 EXE and native MSVC/Clang-cl x86 DLLs. The generated DLL is never executed, committed or distributed.
- Reuse the existing pinned `pefile==2024.8.26` DLL oracle with explicit machine/magic/architecture checks and full ordered section, named import/export and file-hash agreement. Refuse ordinal-only imports/exports in this scoped evidence. Record source and PE SHA-256, observed compiler/linker version lines and CI revision.
- Keep the established `rel-mingw-x64-oracle-ubuntu` artifact, now containing both EXE and DLL JSON evidence; all other artifact names and CI job counts unchanged. No new dependency, parser change, fixture binary, contract revision or source-license decision.
- This adds one **controlled compiler/linker and file-type combination**, not licensed third-party diversity, CPU/RSS enforcement or hostile-file safety.

## [Unreleased] — Full named PE32 DLL oracle comparisons (P1.5)

- Close a concrete **test-oracle detection gap** in the existing static-only MSVC/Clang-cl x86 DLL coverage: previous assertions checked only a set of section names and the presence of one export/import. Reports with incorrect section file offsets or silently omitted other named imports/exports could pass.
- Require complete ordered section fields and canonical named import/export lists from independent pinned `pefile` to agree with the v1 manifest. Refuse ordinal-only entries outside this scoped oracle's representation rather than suppressing them.
- Add five portable positive/negative test methods to the existing Ubuntu/Windows `pefile` CI steps. Reuse current source-built non-executed DLLs; no change to parser Rust code, dependency set, fixture bytes, license policy, workflow job count or public `binary-manifest v1.0.0` contract.
- This increases evidence integrity on **two controlled x86 DLLs**, not the variety/licensing of external PE samples, hostile-file safety, or behavior coverage.

## [Unreleased] — Structured PE independent oracle completeness (P1.5)

- Strengthen the existing controlled Windows MSVC/Clang-cl structured PE oracle: compare **the entire ordered section table (names, raw offsets/sizes and virtual addresses)** and **all observed named imports/exports** in REL's manifest with the independent `pefile` extraction, rather than accepting only the presence of `.rsrc`, `.reloc` and two exports.
- Add portable negative regressions proving that omitted sections, changed section metadata, missing or injected imports/exports and extraction warnings are rejected. Reuse the existing independent-oracle CI setup on Windows and Ubuntu; no new CI jobs, PE fixtures or downloaded binaries.
- This is stronger evidence for two source-built, non-executed controlled probes, **not** broader representativeness, behavioral coverage or malicious-input isolation. No public `binary-manifest v1.0.0` change, licensing decision or production Rust parser change.

## [Unreleased] — EX-02 cross-compiler evidence consistency

- Reject contradictory per-symbol import/export changes around the 6 fully observed MSVC/Clang-cl A/B squares in the existing 8-build EX-02 corpus. The earlier per-pair count and within-compiler triangle checks were insufficient to detect a balanced inconsistency confined to one cross-compiler pair.
- Add explicit negative and positive synthetic regressions and keep existing valid test reports internally coherent. This is a necessary logical evidence check, not an independent PE oracle, proof of authenticity or completion of #15.
- Preserve raw SHA-256, all original fixtures, public `binary-manifest v1.0.0`, Rust binaries and dependencies. No new CI jobs or schema changes.

## [Unreleased] — Reject undecodable PE section names (P1.5 candidate)

- Reproduce a concrete malformed PE32 section-name case with a test-only branch CI failure: the existing `rel-pe` extraction replaced an invalid UTF-8 section name with `<invalid>` and returned no warning, despite losing the original header-name evidence.
- Reject that observation as `PeError::Parse` instead of emitting a successful warning-free manifest. Test both unchanged PE32/PE32+ fixture derivatives in memory; existing golden fixtures, hashes and permissions are unaffected.
- Conservative compatibility impact: a PE with an undecodable header-name byte sequence is now refused, rather than presented as fully inspected. No new dependency, PE execution, `binary-manifest v1.0.0` schema change or claims about exhaustive hostile-input protection.

## [Unreleased] — EX-02 transitive evidence consistency

- Reject logically contradictory import/export set deltas across fully observed within-toolchain A/B/C triangles in the eight-build EX-02 evidence comparator. Pairwise balanced cardinalities alone cannot guarantee mutually compatible claims.
- Add negative regression for an impossible balanced v1/v3 change and positive regression for a consistent change and reversal; preserve legacy pairwise checks, existing PE oracles and all raw SHA evidence.
- This checks necessary consistency of JSON evidence, **not** independent authenticity, binary semantics, PE-parser security, or completion of issue #15. No change to binary-manifest v1.0.0, Rust crates, fixture bytes, or CI matrix.

## [Unreleased] — EX-02 near-output-cap resource observations (verified PR #129)

- Extend the existing measured `rel-diff` resource profile with one deterministic high-cardinality **accepted** report strictly greater than 15 Mio and at most 16 Mio, 8192 distinct synthetic imports on each side, while preserving the 16 Mio per-input limit.
- Record actual report byte count and SHA-256 for all profile scenarios; reject output byte drift among same-input repetitions, add small deterministic negative unit regressions and run them in existing Windows/Ubuntu CI. This measures an accepted near-cap case rather than duplicating the already tested overflow path.
- No parser/CLI/schema/fixture changes, no extra dependency, no PE execution, and no general allocation/RSS security claim. In #129 the canonical checkpoint was refreshed through #128; the follow-up documentation pass records #129 independently.
- **Verified:** exact-head [CI #39515866730](https://github.com/ELITEAYOTO/REL/actions/runs/39515866730) and exact-main [CI #39516270775](https://github.com/ELITEAYOTO/REL/actions/runs/39516270775) succeeded Windows/Ubuntu. The accepted 16,040,894-byte report, SHA-256 and measured wall/RSS (four original CI artifacts) are in [EX02_RESOURCE_BASELINE](docs/EX02_RESOURCE_BASELINE.md) and [issue #68](https://github.com/ELITEAYOTO/REL/issues/68#issuecomment-6304298115). #68 remains open.

## [Unreleased] — opt-in empty cgroup child creation feasibility (verified PR #128)

- Extend the existing cross-platform cgroup-v2 capability probe with an opt-in `--check-empty-child`: attempt an unpredictable `rel-empty-<random>` directory solely beneath the caller's canonical non-root cgroup, inspect its empty `cgroup.procs`, and `rmdir` it. Refuse ambiguous/root membership or noncanonical paths; report permission denial as observed, and fail CI if an owned temporary group cannot be removed.
- Existing default invocation remains **read-only**. Never move a PID, start a binary under a cgroup, set `memory.max`/`cpu.max`, enable parent controllers or modify the watchdog. A successful empty-child test does NOT verify delegation or resource isolation. Add deterministic safety and failure-path tests on Windows/Ubuntu, with final-head and post-merge gates.
- Update canonical CURRENT_STATE through independently verified #127. Issue #9 remains OPEN.

## [Unreleased] — cgroup v2 read-only capability baseline (verified PR #127)

- Add standard-library read-only Linux cgroup v2 mount/controller preflight, with cross-platform fake-input/negative regressions and output in existing Windows/Ubuntu CI logs. Explicitly report `candidate_unverified` rather than conflating mount availability with delegated process isolation.
- This probe never writes cgroupfs, starts a target, changes the watchdog, enables controllers, migrates a PID, or modifies public parser/schema/fixtures. Linux cgroup delegation, `memory.max`, `cpu.max`, `cgroup.kill` behavior and runner permissions still require active controlled validation in a suitable delegated environment; #9 stays open.
- Refresh canonical checkpoint through the verified #126 merge and CI.

## [Unreleased] — controlled errors for Linux descendant RSS sampling (verified PR #126)

- Fail explicitly as `WorkerFailed` on inaccessible/vanished tree enumeration or inaccessible descendant RSS rather than letting raw psutil exceptions bypass the watchdog's documented error path; still skip a descendant that vanishes after successful enumeration.
- Add deterministic negative psutil mocks and a controlled Linux worker with injected observation refusal, checking clean failure and existing cleanup. Reconcile canonical CURRENT_STATE through verified #125; the public parser, original binary fixtures, manifest v1.0.0, Windows Job Objects, and native Linux limits do not change.
- This does **not** improve the sampled RSS bound into a cgroup or hostile-process security boundary, and the umbrella P1.5 issue #9 remains open.

## [Unreleased] — opt-in Linux sampled descendant-tree RSS observation (verified #125)

- Expose `--max-sampled-tree-rss-mib` (Linux only, disabled by default) in the existing opt-in watchdog. Sum the direct supervised analyzer and currently discovered descendant RSS snapshots; reject the observed limit and use existing cleanup. Preserve direct-child sampling, kernel per-process RLIMIT and Windows Job Object policies.
- Regression demonstrates the previous direct-child-only blind spot with a 96 MiB controlled child behind a small parent, then verifies opt-in rejection and the real PE64 static-inspection smoke. Windows rejects the Linux-only flag before launch.
- This is best-effort memory **sampling**, not kernel-enforced process-tree RAM isolation. No dependencies, PE fixtures, Rust parser, CLI manifest, or public binary-manifest v1.0.0 changes. No #9 closure or hostile-input safety claim.

## [Unreleased] — opt-in Windows job-wide user CPU-time limit (pending exact-head CI)

- Extend the existing suspended-start Windows Job Object supervisor with an optional `--max-job-cpu-seconds 1..300` switch; allow CPU-only and combined CPU+job-memory limits, retaining existing default behavior. This is native cumulative **user-mode** CPU time for associated job processes, not Linux RLIMIT_CPU, wall time, or all-kernel CPU accounting.
- Add a controlled busy-child native termination regression, successful CPU-only/combined tests, cross-platform invalid-flag checks and real static PE64 smoke with both flags. Existing Linux process group/RLIMIT_* behavior, fixtures, parser, dependencies, JSON v1.0.0 contract and default CLI remain unchanged.
- The Windows native check is periodic and the supervisor cannot uniquely infer a CPU-limit breach from an exit code. This is not a full hostile-input sandbox or issue #9 closure. Results require successful final PR-head and separate post-merge Windows/Ubuntu CI before considering it shipped.

## [Unreleased] — CI first-party Node.js 24 action upgrade (pending exact-head validation)

- Move the three existing first-party GitHub Actions in `ci.yml`, `fuzz.yml` and manual `fuzz-long.yml` to the verified official `v6` release commit SHAs, whose `action.yml` declares `node24`; preserve permissions, trigger behavior, artifact names and CLI commands. Respond to the concrete Node.js 20 deprecation warning seen in hosted-runner CI.
- Add a small standard-library CI regression guard for GitHub-owned action pins, checking all three workflows and negative variants before the full suite; record official refs, minimum runner version and limitations in the canonical CI pin policy. Refresh `CURRENT_STATE.md` through the already verified #122 post-merge main run.
- This is *not* a declaration of hermetic reproducibility, audited supply-chain security, an upgrade of Python/Rust dependencies, or successful full CI prior to verification. No PE fixture, runtime parser, schema or fuzz budget changes.

## [Unreleased] — deterministic TLS callback seeds in bounded libFuzzer corpus (pending CI)

- Reuse the existing source-verified PE32/PE32+ TLS callback constructor through one private support module; preserve identical oracle outputs and pin the generated byte hashes verified in #121.
- In the bounded libFuzzer workflow, verify the original three tracked seeds and deterministically add two new TLS-bearing PE inputs to the ignored working corpus. Assert generated source/hash provenance in standard-library tests on both OS and record the added seeds in the existing fuzz metadata.
- Do not commit derived PE binaries, change the parser or public manifest, claim new fuzz coverage without the actual campaign log, or close #8/#9. Controlled synthetic seeds do not establish a representative legally cleared corpus.

## [Unreleased] — PE32/PE32+ static TLS callback-table oracle (pending validation)

- Construct source-hash-verified in-memory PE32 and PE32+ TLS directories with raw data, index VA and a two-entry, null-terminated callback-VA table; use pinned independent `pefile` structural assertions and check `rel-inspect`'s unchanged public metadata alongside one unmapped callback-table-pointer mutation.
- Run only static inspection on Windows/Ubuntu CI; preserve original fixtures and SHA-256. Pending exact-head CI; no TLS semantic output, parser correction, external redistribution license, hostile-input safety claim or completion of issues #8/#9.

## [Unreleased] — strict F001 TLS mutation regression oracle

- Strengthen the existing 1,104 F001 truncation and 1,104 single-byte XOR mutation checks to reject both unwinds escaping `rel-pe` and `PeError::DependencyPanic` returned after a caught Goblin panic. Mutation validity may change, so ordinary parse errors or valid parses remain acceptable.
- Reconcile the dated `CURRENT_STATE.md` handoff through #118. This changes no parser code, retained fixture bytes, dependency, public schema or resource limit; it is not a hostile-input safety guarantee.

## [Unreleased] — internal PE import/export pointer regressions

- Exercise 96 in-memory boundary mutations of export function/name/ordinal pointers and import descriptor thunk/name pointers on both unchanged, SHA-verified PE32/PE32+ fixtures. Require rejection of an unmappable import DLL-name RVA rather than a clean, incomplete manifest.
- Test-only validation: no runtime parser change, dependency, public manifest schema or fixture binary addition. This does not replace representative corpus validation or worker CPU/RSS ceilings.

## [Unreleased] — targeted PE data-directory mutation regressions

- Extend the deterministic rel-pe mutation gate with 96 single-field RVA/size changes across import, export and TLS directory entries in both unchanged, SHA-256-verified PE32/PE32+ reference fixtures. Fail when goblin panics even if REL catches the unwind as `PeError::DependencyPanic`, aligning with the existing fuzz target.
- Test-only change: no additional corpus binaries, production parser modifications, dependencies, runtime budgets or public manifest changes. Fixed-seed coverage does not prove hostile-input safety; #8 and #9 remain open.

## [Unreleased] — direct-interpreter watchdog test workloads

- Launch controlled Python resource/Job Object test children through the base interpreter, avoiding Windows venv redirectors. Require the reported interpreter PID to equal the created process PID; keep CLI integration in the caller's Python environment.
- Document the reproduced Windows 10/Python 3.11 venv test failures and the direct-process scope. No production supervisor, parser, public schema or resource-budget change.

## 2026-10-20 — Windows direct-process resource accounting

- Add owned creation-handle duplication and final native peak working set / CPU
  to the Python resource profiler, separate from RSS/CPU samples and Linux wait4.
- Add native Windows lifecycle/failure tests and paired-evidence tamper checks;
  Windows CI requires complete native readings. No Rust/public contract change.
- Measurement only; descendants and enforced budgets remain outside this scope.

## [Unreleased] — Linux direct-child high-water memory/CPU accounting

- Record final `wait4` kernel peak RSS and user/system CPU for the Linux `rel-inspect` child, including executions shorter than the 2 ms polling interval. Keep sampled fields and Windows behavior unchanged; native fields are null where unsupported.
- Validate observed per-run kernel fields and aggregates in the existing paired-evidence gate, requiring complete Linux native data in current CI while permitting historical report interpretation without that opt-in. Add short-lived success/nonzero-exit wait4 regressions and negative integrity tests. **No** enforced memory/CPU budget, process-tree sandbox, PE execution, external dependency, or public manifest change.


## [Unreleased] — paired MinGW-w64 resource observations

- Include the existing Ubuntu-built GNU MinGW-w64 x64 PE in **both** CLI timing and sampled RSS/CPU inventories, extending Ubuntu's paired gate from 6 to 7 cases without introducing or executing a new PE fixture. Record GCC/linker versions and tracked C source hash.
- Add missing/invalid compiler provenance and inconsistent toolchain-version regressions. RSS/CPU remain sampled observations, not enforced ceilings. No new dependencies or public manifest changes; #9/#68 and the licensing decision remain open.


## [Unreleased] — distinct GNU MinGW-w64 PE producer coverage

- Reuse the existing controlled Windows C probe and independent Python pefile oracle for an Ubuntu-built GCC/MinGW-w64 x64 PE32+ executable, extending structural comparison to every section's name (including resolved GNU COFF long-name references), offset, size and virtual address, with negative string-table tests on both OS runners.
- Archive static-only MinGW compiler/linker versions, C source and compiled PE SHA-256, and verified metadata as JSON; never execute, load, commit or distribute the generated EXE. This is a cross-toolchain controlled trial, not a cleared representative corpus, deterministic package lock, or a parser CPU/RSS guarantee. Issue #9 and licensing #16 remain open.

## [Unreleased] — nullable manifest v1 contract regression

- Add a Rust unit regression for `binary-manifest v1.0.0` JSON serialization, comparing top-level and section field names against the existing schema's required/declared properties. Explicit `null` for required `arch` and `virtual_address` must survive serialization. The pre-existing independent Python JSON Schema CLI oracle remains the full schema validation gate; no runtime behavior, schema or dependency changes.

## [Unreleased] — bounded fuzz smoke evidence and seed-change triggers

- Retain the bounded PE libFuzzer smoke log, actual run/attempt and commit provenance, compiler version, flags and hashes on successful **and** failed executions; preserve crash artifacts. Shell `pipefail` retains failure semantics.
- Trigger the same fuzz smoke when canonical PE32/PE32+ fixture data, expected digests or shared hash validation change. This is evidence hygiene, not a new fuzz campaign, corpus diversity, automated minimization or a hostile-input guarantee. Issue #8 remains open.

## [Unreleased] — fuzz panic visibility and seed identity

- Correct the `pe_inspect` libFuzzer target to treat `PeError::DependencyPanic` as a **fuzzer failure** instead of silently ignoring it. Ordinary `Unsupported` and `Parse` errors remain accepted malformed-input outcomes; the production parser and its controlled-input warning remain unchanged.
- Verify the two tracked PE32/PE32+ libFuzzer seed copies are byte-identical to SHA-256-checked `fixtures/expected.json` sources, in both fuzz workflows and the ordinary existing corpus unit gate; retain the independently pinned historical F001 crash seed. Tighten the preserved F001 tests to distinguish clean errors from swallowed dependency panics.
- This is a scoped fuzz-detection improvement, **not** new evidence of a previously undiscovered panic, a complete coverage-guided corpus, a hard RSS/CPU limit or hostile-input safety. Issue #8 and #9 stay OPEN.

## [Unreleased] — EX-02 mixed-cardinality resource coverage

- Extend the existing independent `rel-diff` CLI oracle with dense, long and JSON-escaped import/export/section names (~1.1 MiB per controlled input), exact inverse/sorted delta checks, permutation stability, ambiguous-section abstention and duplicate-observation rejection. This adds regression coverage only: no comparator, manifest contract, dependency, CI workflow or resource-limit changes; #68 stays open.

- Extend the existing black-box `rel-diff` output oracle to accept a controlled report over 15 MiB and independently reject a larger serialized report with **zero stdout** under its established 16 MiB limit; input manifests themselves stay below the 16 MiB reader cap.
- Add one third controlled EX-02 profiling scenario with 2,048 imports, exports and section records per manifest, including shared-name metadata changes. Check exact delta counts for all scenarios and continue reporting observed wall time, sampled RSS/CPU and hashed input/provenance in Windows/Linux CI artifacts.
- No parser/CLI changes, public schema modifications, new scripts, libraries or runtime resource guarantees. The historical two-scenario measurements remain unchanged; [#68](https://github.com/ELITEAYOTO/REL/issues/68) remains open for representative data and defensible CPU/RSS acceptance criteria.

## [Unreleased] — script entrypoints versus private helper modules

- Move three **import-only** support modules (`corpus_cases`, `measurement_environment`, `windows_job`) into `scripts/_internal/`. Adjust Python imports and the corpus fixture root, keeping direct CLI/test/CI script paths unchanged. Document purpose, consumer boundaries and historical reference policy in `scripts/README.md`.
- Deliberately defer a broader `scripts/` layout migration until a demonstrated benefit justifies changes to CI invocation paths. No binary, public schema, parser logic, Python dependency or test behavior changes intended.

## [Unreleased] — P1.5 controlled malformed export-declaration campaign

- Extend the existing generated-only PE rejection/profile campaign from 13 to 21 cases with unmapped/zero export RVAs and over-budget function/name counts on both PE32 and PE32+; verify mutation bytes and source RVA mapping independently of Rust preflight.
- Preserve expected diagnostic, nonzero status, zero partial stdout and observed wall/RSS/CPU evidence on Windows and Ubuntu. This remains synthetic preflight-focused coverage, **not** an independently licensed representative PE corpus, import-table semantic validator, arbitrary hostile-binary sandbox or completion of issue #9.

## [Unreleased] — EX-02 numeric subset verification

- Extend the existing independent CLI and Draft 2020-12 JSON Schema oracle across all four `u64`-backed manifest numeric fields, with zero, `u64::MAX`, out-of-range `2^64`, integral-decimal `1.0`, negative integers, nullable RVA and rejection from either input side. No public schema change.
- Correct obsolete governance language: the metadata-only EX-02 pilot is integrated, but full EX-02 acceptance remains open.

## [Unreleased] — P1.5 Linux per-file native spool ceiling

- Add Linux `RLIMIT_FSIZE` to the opt-in supervised analyzer, before exec, using the larger existing spool budget plus one byte and respecting any smaller inherited hard limit. Add Linux-only tests for installed kernel limits and an oversized regular-file write attempted between polling intervals.
- Existing sampled stdout/stderr checks and Windows behavior remain; there is **no aggregate disk quota**, universal process isolation, binary schema change or new dependency. Issue #9 remains OPEN.

## [Unreleased] — repository hygiene guard and stale-status reconciliation

- Add a stdlib-only CI gate for tracked local Markdown file/directory links
  and explicit negative regressions (missing, escaped, case-mismatched paths);
  does not check external sites, anchor semantics or auto-delete anything.
- Update quality guidance on consumers, historical archives and dated live
  checkpoints; correct documented pending-CI claims in current profiling and
  security notes using verified main Windows/Ubuntu run #39354165057.
- No runtime, public manifest schema, third-party dependency or binary change.

## [Unreleased] — 2026-10-20 static PE32 DLL CI regression (scoped integrated)

- Compile two x86 PE32 DLL cases on the Windows runner using MSVC and
  Clang-cl, from a small tracked C source. Run a separate pinned `pefile`
  oracle for PE type, I386 machine, imports, exports, sections and comparison
  against the REL static analyzer's hash and manifest; capture JSON evidence.
- No binaries added to git, no executable/DLL loaded by CI, no license grant
  or claim of externally redistributable representative corpus. Issue #9 and
  source licensing #16 remain open. [PR #92](https://github.com/ELITEAYOTO/REL/pull/92) and [post-merge Windows/Ubuntu CI #39353437460](https://github.com/ELITEAYOTO/REL/actions/runs/39353437460) passed.

## [Unreleased] — 2026-10-20 Linux watchdog descendant cleanup (scoped integrated)

- The optional Linux inspection supervisor now creates a dedicated process session
  and signals its process group on both success and failure, preventing ordinary
  same-group descendants from outliving the inspected analyzer process. Add two
  Linux-only regressions for timeout and successful parent exit, with unchanged
  Windows behavior. This does **not** prevent a descendant from escaping into a
  different process group, enforce aggregate CPU/RSS, or establish a sandbox.
- No changes to the Rust parser, the public `binary-manifest v1.0.0` contract,
  third-party licenses or production default CLI. [PR #91](https://github.com/ELITEAYOTO/REL/pull/91) and [post-merge Windows/Ubuntu CI #39352685559](https://github.com/ELITEAYOTO/REL/actions/runs/39352685559) passed; issue #9 remains open.

## [Unreleased] — 2026-10-20 documentation handoff

- Update the canonical current state, next-chat historical handoff preface,
  AGENTS, ROADMAP and README after [PR #89](https://github.com/ELITEAYOTO/REL/pull/89)
  squash c9d092c and exact [postmerge Windows/Ubuntu CI #39345880829](https://github.com/ELITEAYOTO/REL/actions/runs/39345880829).
  Preserve the 13 controlled negative PE cases / 39 rejections per OS
  and explicit nonrepresentative sampled-resource limitations.
- Correct old claims that EX-02 #62 is still draft, or that fuzz #12 and
  historical TLS F001 #11 remain unresolved. Broader #8/#9/#14/#15
  acceptance gates still OPEN. This is documentation-only, not a new
  parser/security feature.

## [Unreleased] — 2026-10-19

### P1.5 — Controlled malformed PE failure-path resource evidence (issue #9 partial)

- Add a cross-platform, fail-closed negative CLI corpus: 13 locally derived/hash-verified PE32/PE64/F001 cases including an 8 MiB overlay, expected diagnostics and no partial JSON. Capture three separate wall-time/sampled CPU/RSS observations per case with source and analyzer hashes in CI artifacts. These are not kernel memory caps or a legally cleared independent external corpus.


### P1.5 — Reproducible fuzz tooling (issue #12, scoped)

- Generate a separate fuzz workspace lockfile with Cargo, pin libfuzzer-sys 0.4.13 and nightly-2026-10-19 without changing the stable workspace or parser. Verify locked Cargo metadata and detect lockfile drift in CI.
- Provide a manual, bounded 300-second campaign alongside the existing 30-second smoke; retain execution metadata and failure artifacts. [Verification run #39318875380](https://github.com/ELITEAYOTO/REL/actions/runs/39318875380) completed on a `main`-equivalent source tree via a **closed, unmerged trigger-only PR #84**: 2,562,113 executions / 301 seconds, peak RSS 548 MiB, no crash. This is not a manual `workflow_dispatch` run or a general hostile-input safety guarantee.


### EX-02 — Experimental PE manifest metadata diff pilot (PR #62; gate still open)

- Introduce standalone Rust `rel-diff` CLI comparing two controlled PE `binary-manifest v1.0.0` JSON inputs. Record source SHA-256 identities, size/architecture flags, deterministic raw import/export differences and section metadata changes by **unique exact section name**; duplicate names abstain as `ambiguous`, without partial section deltas.
- Add a cautious whole-import-set ASCII DLL-casing hint, preserving original observations and declining on normalization collisions. Reject malformed JSON, incompatible format/schema, wrong SHA shape, extraction warnings, duplicate import/export observations, excessive/non-regular inputs and missing nullable mandatory `arch`/`virtual_address` keys.
- Version the **separate** experimental output contract as `contracts/experimental/manifest-diff.schema.json` (`0.1.0-experimental`) with unknown-field rejection, unique delta arrays and consistent section status; public `binary-manifest v1.0.0` remains unchanged.
- Add Rust CLI/unit regressions and a separate Python oracle, `scripts/test_manifest_diff_cli.py`, which invokes compiled release binaries and validates real outputs against JSON Schema on Windows/Linux. Cover A/A, A/B and B/A, inversion, order invariance, repeatability, collisions, malformed/oversize inputs and a controlled end-to-end `rel-inspect` → `rel-diff` pipeline using the two tracked synthetic PE fixtures.
- Audit-driven EX-02 consolidation: the Unix FIFO/leaf-symlink opening regression is covered by a bounded CLI test ([#63](https://github.com/ELITEAYOTO/REL/issues/63)). The output is now serialized into a **16 MiB bounded buffer** before stdout, with overflow/final-newline unit tests and a black-box regression requiring failure without partial output.
- The independent CLI oracle tests the experimental consumer's `u64` boundary: public JSON Schema `integer` permits nonnegative values the Rust representation rejects; `binary-manifest v1.0.0` has **not** been modified ([#67](https://github.com/ELITEAYOTO/REL/issues/67)).
- Add repeated synthetic-input `rel-diff` resource profiling on both CI platforms with captured runner/toolchain identity and sampled RSS/CPU. These artifacts are **observations, not production limits or representative PE build benchmarks** ([#68](https://github.com/ELITEAYOTO/REL/issues/68)).
- Controlled **source-defined compiled PE A/B corpus**: four C variants (direct imports/exports) built statically as eight Windows PE x64 executables with MSVC and Clang-cl, then 16 A/B comparisons and eight A/A checks. Independent `pefile` oracle verifies direct imports, exports, section metadata and SHA-256 against `rel-inspect` and `rel-diff` outputs, with both comparison directions and JSON Schema validation; CI archives compiler/source/binary provenance. These **16 pairs reuse eight small PE builds**, not 16 independent software releases or a representative real-world corpus. See `docs/EX02_COMPILER_CORPUS.md`.
- Focused hygiene refactor: move comparison unit tests into `tools/rel-diff/src/tests.rs`, reducing `main.rs` from 433 to 269 lines without changing observable CLI behavior.
- Audit #69 reproducibility diagnosis: independently captured and compared two builds of the eight controlled MSVC/Clang-cl PE variants within a Windows CI job. All eight normal builds differed in exactly two bytes each, independently located inside COFF and debug-directory timestamp fields. An isolated `/Brepro` link-mode experiment yielded eight byte-identical PE outputs within a job and the same eight raw SHA-256 values across two CI runs with matching declared source/compiler banners. Add portable byte-range tests, separate replay directories, archived field-level evidence and a strict provenance-aware JSON/ZIP comparison gate restricted to `/Brepro` mode; never mask raw hashes or infer behavior from metadata equivalence. See `docs/EX02_COMPILER_CORPUS.md` and [#69](https://github.com/ELITEAYOTO/REL/issues/69).
- **Limitations:** controlled-input alpha, not an arbitrary-hostile-file sandbox or atomic snapshot. No function matching or behavioral findings; no representative 10–20 authorized build pairs, measured general CPU/RSS baseline, exhaustive JSON Schema equivalence or full EX-02 acceptance. The milestone remains open pending independent validation and review.


### EX-01 — Same-descriptor second-pass input consistency (PR #59 merged; scoped CI verified)

- Harden `rel-observe`'s shared controlled-file reader for all three domains: re-read and compare the bytes through the **same opened file handle**, with one fixed 64 KiB scratch buffer. Reject observed same-size mutations, early EOF, trailing bytes, and pre/post size or modification-time inconsistencies *before* passing any bytes to observation producers. Rust deterministic regression tests cover unchanged multi-chunk input, first/middle/last byte mutation, shortening and growth; existing cross-platform CLI oracles retain report-format regression coverage.
- Only controlled files ≤2 MiB remain in scope. A successful read now entails roughly 2× input reads, not an atomic filesystem snapshot, descriptor-confined ancestor lookup or hostile-file sandbox. No new dependencies and no change to the experimental JSON envelope, deterministic ID or `binary-manifest v1.0.0`. [PR #59](https://github.com/ELITEAYOTO/REL/pull/59) merged as [`d435b15`](https://github.com/ELITEAYOTO/REL/commit/d435b15e3c8dd43b8b846ce376f4468f18555afa); final-head [branch CI #39188698531](https://github.com/ELITEAYOTO/REL/actions/runs/39188698531), [PR CI #39188703138](https://github.com/ELITEAYOTO/REL/actions/runs/39188703138), and [post-merge `main` CI #39188909312](https://github.com/ELITEAYOTO/REL/actions/runs/39188909312) all succeeded Windows/Linux.

### EX-01 — Source-backed evidence verification (PR #57 merged; scoped CI verified)

- Add standalone, opt-in `scripts/verify_observation_evidence.py` to recheck the **existing three** `rel-observe` experimental domains against a separately supplied controlled source binary. Recompute file SHA-256 and size, configuration digest, deterministic run ID, raw source bytes, normalized field values, precise evidence offsets/lengths and complete/partial/unsupported/absent-in-scope semantics.
- Strictly reject unrecognized domains/producers, omitted or extra observations/evidence, malformed or falsified proof methods, wrong fields and spurious diagnostics. New cross-platform end-to-end negative tests mutate source values, offsets, run IDs, statuses and negative claims, plus validate real producer output on controlled PE32/PE64, partial and unsupported cases.
- **Scope limit:** verification proves correspondence with the supplied byte buffer for known predicates; neither SHA-256 nor a deterministic run ID authenticates who produced a report. This is not proof of an atomic file snapshot, arbitrary-hostile-input safety, PE semantic validity or runtime behavior. Existing JSON schema `0.1.0-experimental`, `binary-manifest v1.0.0`, Rust producers and dependencies unchanged. [PR #57](https://github.com/ELITEAYOTO/REL/pull/57) merged at [`6e18d37`](https://github.com/ELITEAYOTO/REL/commit/6e18d373c27571928b1d38b8815701dec0de41f6); final-head [branch CI #39186120971](https://github.com/ELITEAYOTO/REL/actions/runs/39186120971), [PR CI #39186154113](https://github.com/ELITEAYOTO/REL/actions/runs/39186154113) and [post-merge `main` CI #39186361225](https://github.com/ELITEAYOTO/REL/actions/runs/39186361225) all passed Windows/Linux, including the real producer and falsification-rejection oracle.

### EX-01 — Controlled section header record observations (PR #55 merged; CI verified)

- Add `rel-observe section-headers` as a third bounded observation domain `pe.section_headers`. Read the COFF section count and optional-header byte size, then report up to 32 complete, declared 40-byte headers with full raw record hex, cautious normalized fields, per-record SHA-bound file-offset evidence and deterministic domain/config-specific run ID.
- Partial COFF/optional/section-header bytes produce `partial` and `indeterminate` with no fabricated proof; declared counts >32 yield `unsupported`. A zero count is reported `absent_in_scope` with two-byte count evidence only when the declared optional header fits. Rust and independent Python oracles cover both reference formats, exact offsets, truncation, caps, empty declarations and run-ID repeatability on Windows/Linux.
- This validates only the **declared header bytes**. No claim of section payload correctness, RVA mapping validity, full PE parsing, hostile-input isolation or game/runtime capability. Existing DOS/COFF commands and `binary-manifest v1.0.0` remain unchanged. [PR #55](https://github.com/ELITEAYOTO/REL/pull/55) merged at [`c6ca1bb`](https://github.com/ELITEAYOTO/REL/commit/c6ca1bbd57fb0a721736c150338d858a8a081e6d); final-head [branch #39184173861](https://github.com/ELITEAYOTO/REL/actions/runs/39184173861), [PR #39184179438](https://github.com/ELITEAYOTO/REL/actions/runs/39184179438) and [post-merge main #39184367267](https://github.com/ELITEAYOTO/REL/actions/runs/39184367267) all passed Windows/Linux, including the independent 40-byte section-record oracle.

### EX-01 — COFF Machine observation with explicit partial coverage (PR #53 merged, CI verified)

- New experimental `rel-observe coff-machine` CLI subcommand observes the actual two-byte little-endian COFF Machine field at `e_lfanew + 4`, with exact byte-offset evidence from the hashed subject buffer. Only `0x014c` (x86) and `0x8664` (x86_64) receive human-readable mappings; other values remain literal hex.
- Truncation **after the PE signature** results in a scoped `partial` report, an `indeterminate` observation and a machine-readable `COFF_MACHINE_TRUNCATED` diagnostic with no fabricated evidence. Bad MZ/PE signatures and out-of-limit inputs are rejected without a report. Separate deterministic domain/config run IDs, independent Python oracle and Rust golden/negative tests cover controlled PE32/PE32+, unknown machine values and exact one-byte truncation.
- Refactors only the shared `rel-observe` provenance envelope and bounded file reader to serve two independent domains; the original `dos-magic` output/run IDs, `rel-inspect` and `binary-manifest v1.0.0` are intended to remain unchanged. Not a complete PE header validator, architecture compatibility verifier, hostile binary sandbox or decompiler. [PR #53](https://github.com/ELITEAYOTO/REL/pull/53) merged at [`e60e978`](https://github.com/ELITEAYOTO/REL/commit/e60e978fb7f6359122ae817f853b4629b8a34ab2); final-head [push CI #39182119983](https://github.com/ELITEAYOTO/REL/actions/runs/39182119983), [PR CI #39182124339](https://github.com/ELITEAYOTO/REL/actions/runs/39182124339) and [post-merge `main` CI #39182313199](https://github.com/ELITEAYOTO/REL/actions/runs/39182313199) succeeded Windows/Linux, including independent COFF Machine oracle and existing DOS contract tests.

### EX-01 — First real controlled byte-evidence producer (PR #51 merged; scoped CI verified)

- New standalone Rust `rel-observe` CLI with `dos-magic` command, reading bounded real file bytes and producing experimental EX-01 JSON. The two signed observations are **only** `equals.MZ` present and `equals.NE` absent within file bytes [0,2) of minimally signature-checked PE inputs. File SHA-256, size and evidence refer to that same in-memory buffer.
- A documented SHA-256 run-ID preimage binds the input digest, config digest, exact scope and tool version, with no timestamps or machine-local paths. Standalone integration tests validate output through the Python cross-field validator, independently reproduce the run ID, compare PE32/PE32+ reference fixtures, check relocation to another path, and reject truncated, oversized and unsupported inputs.
- **Limits:** this does not provide comprehensive PE validation or parsing, snapshot-safe input acquisition, arbitrary hostile input isolation, imports analysis, negative network-capability conclusions, EX-02 or decompilation. New crate is executable/tested rather than speculative; legacy `rel-inspect` and `binary-manifest v1.0.0` remain unchanged. [PR #51](https://github.com/ELITEAYOTO/REL/pull/51) merged as [`10f38c8`](https://github.com/ELITEAYOTO/REL/commit/10f38c807668a6a7b5afd46c4d1936afc7125109), final-head [branch CI #39179309964](https://github.com/ELITEAYOTO/REL/actions/runs/39179309964), [PR CI #39179314336](https://github.com/ELITEAYOTO/REL/actions/runs/39179314336), and [post-merge `main` CI #39179499279](https://github.com/ELITEAYOTO/REL/actions/runs/39179499279) all passed Windows/Linux, including observed real-producer integration assertions.

### EX-01 — Experimental standalone observation contract (PR #49 merged, CI verified)

- Add `contracts/experimental/observation-envelope.schema.json` with explicit subject hash, producer/backend versions, deterministic run ID, precisely named coverage domain, scoped positive/negative/indeterminate observations, typed evidence, and diagnostics. No changes to `binary-manifest` v1.0.0 or the original Rust workspace.
- Add `scripts/validate_observation_envelope.py`, validating JSON Schema plus cross-field consistency (file-offset bounds, evidence subject equality/references, duplicate IDs, negative claims only for complete scope, diagnostics for incomplete extraction). Five controlled golden reports use the repository's **synthetic PE32 fixture** and demonstrate `present`, `absent_in_scope`, `partial`, `failed`, and `unsupported`. Add invalid-case and v1-isolation tests to both Windows/Linux CI.
- **Important:** this first experimental contract increment does not provide an extractor, validate the truth of any claim merely by JSON structure, implement a PE manifest-to-evidence migration, or finish EX-01. Full P1.5-A resource/corpus hardening remains open. [PR #49](https://github.com/ELITEAYOTO/REL/pull/49) merged as [`bbbec20`](https://github.com/ELITEAYOTO/REL/commit/bbbec203409c478462b6fd8398640f868ee9c3c7); final-head [push CI #39176068549](https://github.com/ELITEAYOTO/REL/actions/runs/39176068549), [PR CI #39176105548](https://github.com/ELITEAYOTO/REL/actions/runs/39176105548), and [post-merge `main` CI #39176279141](https://github.com/ELITEAYOTO/REL/actions/runs/39176279141) all succeeded on Windows and Linux. Contract-only; no producer or comprehensive source truth validation.

### P1.5-A — Entire declared PE data-directory slot consistency (PR #47 merged; CI verified)

- Reject a PE32/PE32+ `NumberOfRvaAndSizes` larger than the number of complete 8-byte data-directory records physically represented by `SizeOfOptionalHeader`. Previously REL checked only the first two when declared, allowing inconsistent higher counts into the backend.
- Add both-architecture exact boundary/rejection tests and a public `rel_pe::inspect` regression. Preserve zero-count handling, valid fixtures, existing error class, `binary-manifest` v1.0.0, and dependency pins.
- This conservative alpha rule is **not** complete PE validation, an import-thunk bound, or a parser CPU/RSS/sandbox guarantee. [PR #47](https://github.com/ELITEAYOTO/REL/pull/47) merged as [`f26b34d`](https://github.com/ELITEAYOTO/REL/commit/f26b34d557e5bd892a7855bc253a6b07880c9709). [Final PR CI #39173751519](https://github.com/ELITEAYOTO/REL/actions/runs/39173751519), [bounded PE libFuzzer #39173751518](https://github.com/ELITEAYOTO/REL/actions/runs/39173751518) and [post-merge main CI #39173973900](https://github.com/ELITEAYOTO/REL/actions/runs/39173973900) all succeeded; Windows tests for PE32/PE32+ boundary and public API were observed as `ok`. Broader compatibility evidence on licensed binaries remains necessary.

### P1.5-A — Windows 128-bit opened-handle identity check (PR #45 merged, CI verified)

- Query `GetFileInformationByHandleEx(FileIdInfo)` on the already-opened guarded Windows input handle and a second guarded open of the same path; reject mismatched volume+128-bit identifiers or missing/unsupported identities. Only the controlled-input reader changes; no new dependency, parser change or `binary-manifest v1.0.0` change.
- Three deterministic Windows regressions: two handles to the same file and normal CLI read, distinct same-length/same-mtime files, and two handles via a hard link (one underlying file). All use real handles, not guessed filesystem IDs.
- Important: this is a **post-open observation**, not a comparison to the earlier path `symlink_metadata`, an atomic Windows path walk or a coherent filesystem snapshot. Win32 read-sharing already blocks ordinary writers, while privileged/redirector races may evade these checks. Unsupported/zero identifiers now fail closed (potential compatibility change); two file opens and two OS identity queries add overhead. [PR #45](https://github.com/ELITEAYOTO/REL/pull/45) merged as [`d1102f7`](https://github.com/ELITEAYOTO/REL/commit/d1102f7def2c86801f9a6d3688a214fb312c82e3). Final-head [push CI #39171652919](https://github.com/ELITEAYOTO/REL/actions/runs/39171652919), [PR CI #39171656519](https://github.com/ELITEAYOTO/REL/actions/runs/39171656519), and [post-merge main CI #39171804456](https://github.com/ELITEAYOTO/REL/actions/runs/39171804456) passed Windows and Linux. All three new Windows identity tests were observed as `ok` in PR CI logs.

### P1.5-A — Windows observable ancestor reparse-point guard (PR #42 merged, CI verified)

- Before the initial leaf preflight and again immediately after acquiring its guarded handle, inspect every Windows parent path with `symlink_metadata` and reject directories bearing `FILE_ATTRIBUTE_REPARSE_POINT`, including junctions. Ordinary nested paths still work; the final-component guard and `FILE_SHARE_READ` behavior remain.
- Three focused Windows regressions cover a normal nested file, a real `mklink /J` ancestor junction and a deterministic junction substitution after initial file metadata. The default locked workspace test stage executes these as regular Rust unit tests and fails if junction creation is unavailable.
- **No atomicity claim:** these are repeated path lookups rather than descriptor-relative Windows opens. Concurrent attackers can swap/restore ancestors or substitute ordinary directories; network/device namespace semantics and hard links are not covered. Rejecting pre-existing parent reparse points intentionally tightens compatibility. No parser, dependency, resource cap or `binary-manifest v1.0.0` change. [PR #42](https://github.com/ELITEAYOTO/REL/pull/42) merged at [`144657c`](https://github.com/ELITEAYOTO/REL/commit/144657c2428039aff2a24680a12ac8f6fffd8c59). Final-head [PR CI #39167525417](https://github.com/ELITEAYOTO/REL/actions/runs/39167525417), [branch CI #39167522146](https://github.com/ELITEAYOTO/REL/actions/runs/39167522146) and [post-merge main CI #39167703067](https://github.com/ELITEAYOTO/REL/actions/runs/39167703067) all succeeded on Windows/Linux. The Windows test log confirms all three new junction regressions executed and passed.

### P1.5-A — Unix no-follow ancestor path traversal (PR #40 merged; CI verified)

- Replace the Unix leaf-only open with descriptor-relative `openat` for each ancestor and the leaf, applying `O_NOFOLLOW` to both. This rejects an ancestor symlink at its own open point, while keeping the original inode gate, 512 MiB actual-read budget, bounded second pass and static-only PE inspection.
- Add Unix regressions for nested regular files, ancestor symlink rejection and a deterministic parent substitution after path preflight. Keep Windows reparse/sharing logic and `binary-manifest v1.0.0` unchanged.
- Compatibility tradeoff: input paths passing through ancestor symlinks or unreadable-but-searchable directories may now fail on Unix. No trusted-root confinement, immutable snapshot, network filesystem guarantee or hostile-input sandbox. [Final branch CI #39165731998](https://github.com/ELITEAYOTO/REL/actions/runs/39165731998), [PR CI #39165747222](https://github.com/ELITEAYOTO/REL/actions/runs/39165747222) and [post-merge main CI #39165928503](https://github.com/ELITEAYOTO/REL/actions/runs/39165928503) passed on Windows and Linux; PR #40 merged at `86cba02`.

### P1.5-A — Unix opened-file identity verification (PR #39 merged; CI verified)

- Add an additional Unix-only `(st_dev, st_ino)` check comparing the preflight path metadata with the metadata from the *already-opened input handle*. Reject detectable regular-file replacement during the path-check/open interval before reading bytes; both observations must identify the same inode.
- Test equal-length, equal-modification-time regular-file replacement; retain existing bounded double-read, Windows sharing/reparse guards, and unmodified `binary-manifest v1.0.0`.
- This check does **not** guarantee consistent bytes under in-place mutations, secure ancestor resolution, a full snapshot, or hostile-filesystem isolation. [Final PR CI #39165266295](https://github.com/ELITEAYOTO/REL/actions/runs/39165266295), [branch CI #39165262356](https://github.com/ELITEAYOTO/REL/actions/runs/39165262356) and [post-merge main CI #39165446361](https://github.com/ELITEAYOTO/REL/actions/runs/39165446361) passed on Windows and Linux; PR #39 merged at `a2bb013`.

### P1.5-A — Second-pass input-byte consistency check (PR CI verified)

- After the existing capped first read (at most 512 MiB), re-read exactly the same length using the **same opened input descriptor** in bounded 64 KiB chunks; reject mismatched bytes or premature EOF before parsing. Recheck descriptor size/mtime afterward. No new parser/binary-manifest v1.0.0 changes and no extra full-sized input buffer.
- Add deterministic same-size-content replacement, multiple-chunk, second-pass truncation and empty-file regressions. All four new Rust tests passed on Windows and Linux in [Windows/Linux CI #39163640989](https://github.com/ELITEAYOTO/REL/actions/runs/39163640989) and [CI #39163645354](https://github.com/ELITEAYOTO/REL/actions/runs/39163645354); an initial format-only failure was corrected before those runs. This **detects some concurrent modifications, not all**; doubles input-read I/O in the worst case and does not produce an atomic snapshot, sandbox, RAM/CPU ceiling or path-race safety.



### P1.5-A — Independent measurement campaign comparison pilot (PR CI verified)

- New offline `scripts/compare_measurement_campaigns.py` reads four already produced timing/resource JSON files (two campaigns), revalidates each job's paired evidence, excludes only run ID/attempt from hardware-context equality, requires known **distinct** run identities and identical CPU/runner/toolchain, exact REL executable SHA, PE corpus and sampling policy. Mismatches produce `not_comparable`, explicit blockers, **no numeric comparisons** and CLI exit status 2.
- Only compatible evidence yields descriptive per-case median timing differences/ratios from the original five samples. No RSS/CPU cross-run ratios, statistical or performance assertions, or modification to `binary-manifest v1.0.0`. Ten controlled positive/abstention regressions passed [Windows/Linux CI #39162247353](https://github.com/ELITEAYOTO/REL/actions/runs/39162247353) and [CI #39162250970](https://github.com/ELITEAYOTO/REL/actions/runs/39162250970) on Windows/Linux. Real fixed-machine multi-run evidence remains open.



### P1.5-A — Paired measurement host/toolchain fingerprint (candidate; CI pending)

- Add `scripts/measurement_environment.py`, a shared low-volatility fingerprint of the CI run identity, reported CPU model and logical/physical/affinity counts, reported total host RAM, OS/kernel, Python, psutil, rustc/cargo versions and exact REL executable SHA-256. Both reports record this context before measuring cases.
- The independent paired-evidence gate rejects missing/invalid context, mismatched runner/run attempt/CPU/compiler or analyzer fingerprints, even when the Git SHA and corpus match. Adds 6 hardware/context tests and 4 new negative evidence regressions. CI pins psutil before all tests/benchmarks.
- These fields are observations, not an attested hardware identity, pinned image/toolchain, cgroup memory quota, stable benchmark baseline, process-tree limit or evidence of safe hostile-input isolation. No native binary-manifest v1.0.0 change.



### P1.5-A — Paired CLI/resource measurement evidence gate (PR CI verified)

- New independent `scripts/check_measurement_evidence.py` matches the existing timing and sampled RSS/CPU reports by case ID, exact input SHA-256 and size, source/licensing metadata, runner OS/machine and commit; rejects inconsistent sample counts, nonfinite/negative metrics, corrupt aggregate medians/p95 and sampled maxima.
- Emits `rel-measurement-evidence-v1` observations with benchmark wall-spread, RSS/CPU sampling coverage and explicit missing-sample flags, uploaded as a separate per-OS CI artifact. Windows expects 11 cases, Linux 6; fail closed if cases silently disappear.
- Add cross-platform negative/unit regressions for corrupted evidence and missing samples (12 new tests) with actual paired artifact uploads verified by [Windows/Linux CI #39158995252](https://github.com/ELITEAYOTO/REL/actions/runs/39158995252) and [CI #39158999274](https://github.com/ELITEAYOTO/REL/actions/runs/39158999274), **without declaring an RSS peak, CPU total, stable cross-run baseline or hard performance threshold**. Existing P1.5-A measured inputs and binary-manifest v1.0.0 remain unchanged.



### P1.5-A — Source-built structured PE resource/relocation cases (PR CI verified)

- Add a controlled C exported-pointer and RC RCDATA source pair; build ephemeral Windows PE32+ x64 variants with MSVC and Clang-cl using `/DYNAMICBASE /FIXED:NO`.
- Independently validate RC data bytes, resource directory ID, native DIR64 base relocations, sections and original REL binary-manifest v1.0.0 size/hash/exports without executing the samples.
- Add two distinct Windows scenarios to both benchmark and resource profiler (9 -> 11), recording separate C and RC SHA-256 fingerprints plus compiler provenance and unresolved redistribution status. Independent resource/relocation oracles and Python corpus tests passed [Windows/Linux CI #39157915184](https://github.com/ELITEAYOTO/REL/actions/runs/39157915184) and [CI #39157910924](https://github.com/ELITEAYOTO/REL/actions/runs/39157910924). Six Linux synthetic scenarios remain unchanged. No parser/API/schema changes or claims of structural semantic extraction.



### P1.5-A — Optional CI-built Clang-cl x64 PE case (PR CI verified)

- Build the same tracked C PE probe with runner-installed LLVM Clang-cl in addition to MSVC, via the Windows SDK. Compare imports, named exports and PE32+ architecture independently through pinned pefile; no inspected PE is executed.
- Record a ninth Windows corpus case in both measurement harnesses, its checked C source SHA-256, binary SHA-256 and the observed Clang version string. Fail if the compiler, compiled PE or version record is absent. Linux remains at six cases.
- The independent oracles, source-hash/version checks, resource profiles and benchmarks passed [Windows/Linux CI #39156574382](https://github.com/ELITEAYOTO/REL/actions/runs/39156574382) and [CI #39156578707](https://github.com/ELITEAYOTO/REL/actions/runs/39156578707) on Windows/Linux. This measures a second compiler **frontend** but may share the Microsoft linker and SDK. The hosted compiler/toolchain remains unpinned, rights to redistribute generated binaries are not established, and no JSON binary-manifest v1.0.0 changes occur.



### P1.5-A — CI-built MSVC x64 PE source probe (PR CI verified)

- Add a tracked small C PE probe compiled with runner MSVC on Windows. The produced EXE remains an ignored local artifact and is never executed by tests.
- Independent pinned pefile oracle verifies native sections, imports and exported symbol against REL's static JSON manifest, size and SHA-256. Integrate the probe as an eighth Windows case for both existing resource profiling and benchmarking; Linux inventory remains six cases.
- The independent Windows oracle explicitly matched GetTickCount64 and the named export; [Windows/Linux CI #39155346166](https://github.com/ELITEAYOTO/REL/actions/runs/39155346166) and [CI #39155351313](https://github.com/ELITEAYOTO/REL/actions/runs/39155351313) passed the Windows/Linux matrix, benchmarks and resource artifacts. Preserve the source hash and explicitly unresolved binary redistribution rights. This does not establish a diverse legal third-party corpus, reproduce the compiler binary byte-for-byte, or change binary-manifest v1.0.0.



### P1.5-A — Controlled PE measurement corpus metadata (PR CI verified)

- Shared deterministic, SHA-256-validated PE32 and PE64 seed/overlay inventory for benchmarking and RSS/CPU profiling; add case IDs, derivation details and explicit unverified redistribution status to observations.
- Both tools now include six controlled PE cases per OS (two original 2 KiB synthetic fixtures, 1/4 MiB overlay per architecture), plus a locally built Windows REL EXE in Windows CI. CI tests reject tampered fixtures and validate generated overlay bytes.
- The PE32/PE64 case inventory and both profiling tools passed [Windows/Linux CI #39153900290](https://github.com/ELITEAYOTO/REL/actions/runs/39153900290) and the second Windows/Linux run, with artifact uploads. No third-party binaries or license assertions; no binary-manifest v1.0.0, parser, memory policy or safety guarantee changes. An independently licensed, representative PE corpus remains open; see [scope](docs/security/P15A_CORPUS_PROVENANCE.md).



### P1.5-A — Linux per-process native CPU-time limit (PR CI verified)

- Add opt-in Linux-only `--max-cpu-seconds` to the Python watchdog, with RLIMIT_CPU soft=N and hard=N+1 installed alongside optional RLIMIT_AS before exec.
- Add Linux tests for effective limits and kernel SIGXCPU termination of a CPU-bound child, argument validation/Windows rejection, and real REL PE64 manifest smoke under both CPU and virtual-address-space ceilings.
- [Windows/Linux CI #39152737826](https://github.com/ELITEAYOTO/REL/actions/runs/39152737826) passed the Linux RLIMIT_CPU/manifest regressions and Windows unsupported-option checks. Earlier CI attempts failed on diagnostic-message compatibility, corrected without bypassing the native limit. No new dependencies, Rust/PE-parser or binary-manifest v1.0.0 changes. This is a per-process cumulative CPU-time limit, **not** descendant-wide accounting, a wall-clock limit or hostile-process sandbox.



### P1.5-A — Windows native Job Object opt-in (PR CI verified)

- New independent `scripts/windows_job.py` helper: suspended Windows process creation, attach to `JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job, verify membership, resume main thread, and fail closed if setup fails.
- New optional `--max-job-memory-mib` flag for the Python watchdog on Windows, range 128–8192 MiB. Existing default, native Linux `RLIMIT_AS`, Rust parser, CLI and manifest v1.0.0 unchanged.
- Native Windows tests for successful job startup, denied oversized allocation, and kill-on-close descendant cleanup, plus Linux option refusal, passed [Windows/Linux PR CI #39151722498](https://github.com/ELITEAYOTO/REL/actions/runs/39151722498); Windows log showed 17 tests, four expected platform skips. No sandbox, CPU-time bound, RSS guarantee or adversarial process containment.


### P1.5-A — Optional Linux RLIMIT_AS native address-space cap (scoped PR CI verified)

- Add an opt-in Linux-only `--max-address-space-mib` flag to the existing Python supervised runner; install a kernel soft/hard RLIMIT_AS ceiling in the child before exec.
- Add Linux tests for actual inherited limits and allocation rejection, plus PE64 manifest smoke under a 2048 MiB address-space ceiling. Windows behavior and binary-manifest v1.0.0 unchanged.
- Linux native-limit regressions and existing Windows/Linux checks passed [Windows/Linux PR CI #39149771201](https://github.com/ELITEAYOTO/REL/actions/runs/39149771201) on the implementation commit. RLIMIT_AS caps *virtual address space*, not RSS/aggregate RAM or CPU time. No descendant containment, Windows Job Objects, general OS sandbox or disk-output quota.



### P1.5-A — Opt-in bounded direct-child watchdog (PR CI verified)

- Added scripts/run_bounded_inspection.py to run only rel-inspect analyze as a child with 30 s default wall-time termination, a 512 MiB *sampled* RSS threshold and output release only after successful completion.
- Added scripts/test_bounded_inspection.py to test wall timeout, observed RAM breach, failed child, stdout bounds and real PE64 manifest compatibility on Windows and Linux. Pinned psutil 7.0.0 is already used by the existing CI profiler.
- Windows/Linux [CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060) passed dedicated watchdog tests, Rust gates, Release and CLI smoke/oracle. No Rust API, parser or JSON schema change. No OS hard memory cap, cumulative CPU enforcement, descendant control or hostile-input sandbox. See docs/security/P15A_SUPERVISOR_V0.md.


### P1.5-A — Windows input read-sharing (PR CI verified)

- Open Windows candidate files with `FILE_SHARE_READ` only, keeping the final-component reparse guard and descriptor-based bounded acquisition.
- Add tests for simultaneous readers, rejecting concurrent writers, refusing REL input open while a writer already owns the file, and reopening a writer after reader close.
- Windows-only compatibility impact: some live files become unavailable while another writer is active. No new dependency, public manifest v1.0.0 change, OS sandbox, coherent snapshot or CPU/RSS hard limit. [Windows/Linux CI #39146872882](https://github.com/ELITEAYOTO/REL/actions/runs/39146872882) passed the Windows/Linux matrix; Windows regression logs confirm the reader/writer conflict scenarios were executed and passed.



### P1.5-A — Windows final-component reparse-point opening (PR CI verified)

- Windows CLI opens the final input path component without following reparse points, rejects reparse attributes from the opened descriptor and preserves the 512 MiB cap.
- Adds Windows regular-file, deterministic symlink-swap (privilege-dependent) and directory-substitution tests; no new dependency, no schema v1.0.0 change.
- No ancestor junction/path protection, coherent snapshot, Windows redirector guarantee or CPU/RSS isolation. [CI Windows/Linux #39146000935](https://github.com/ELITEAYOTO/REL/actions/runs/39146000935) passed formatting, Clippy, locked tests, Release, smoke and Windows PE oracle. The dedicated Windows `--nocapture` step printed `PASS Windows final-component symlink was created and refused`; broader filesystem compatibility remains unverified. [Bounded input policy](docs/security/P15A_BOUNDED_INPUT.md).


### P1.5-A — Unix no-follow descriptor open (PR CI verified)

- Unix CLI input acquisition requests `O_NOFOLLOW | O_NONBLOCK` when opening the candidate path; exact Unix `libc` dependency is recorded in Cargo.lock.
- Add deterministic final-component symlink swap regression and a Linux FIFO nonblocking-open test; preserve Windows behavior and manifest v1.0.0.
- Still unprotected: ancestor path replacement, Windows reparse-point races, same-size concurrent writes, parser CPU/RSS and hostile-file execution boundaries. [Windows/Linux CI #39109205165](https://github.com/ELITEAYOTO/REL/actions/runs/39109205165) succeeded (fmt, Clippy, full tests, releases, CLI smoke, Windows PE oracle). See [input notes](docs/security/P15A_BOUNDED_INPUT.md).


### P1.5-A — PE raw section range preflight (PR CI verified)

- Validate non-empty section raw data ranges stay inside input bytes before invoking goblin, using checked slice bounds and the existing <=96 section policy.
- Preserve virtual-only zero-length raw sections, existing APIs/JSON v1.0.0, and avoid new dependencies or allocations.
- PE32/PE32+ malformed/boundary and public inspect API regressions passed [Windows/Linux CI #39108469504](https://github.com/ELITEAYOTO/REL/actions/runs/39108469504); bounded [libFuzzer #39108469495](https://github.com/ELITEAYOTO/REL/actions/runs/39108469495) passed 686,003 executions in 31 seconds with fuzzer-reported 561 MiB peak RSS on that runner. Compatibility with unusual PE layouts and global parser CPU/RAM safety remain open.


### P1.5-A — Atomic report publication (PR CI verified)

- Stage bounded complete JSON in a same-directory temporary file, sync its contents, then publish with hard-link no-replace semantics; clean temporary names on normal errors.
- Add unit and CLI smoke regressions for complete bytes, collisions and cleanup. No change to schema v1.0.0 or stdout.
- [Windows/Linux CI #39107936412](https://github.com/ELITEAYOTO/REL/actions/runs/39107936412) passed (format, Clippy, tests, release, smoke, oracle/profiling). No security claim for hostile directories, hard-link aliases, crash durability or parser resource limits. See [scope](docs/security/P15A_ATOMIC_REPORT.md).


### P1.5-A — Directory declaration and export count budgets (verified, narrow scope)

- Added an allocation-free internal submodule under `rel-pe/src/preflight/` for PE import/export directory declarations and export count fields.
- Alpha policy: directory declarations up to 1 MiB and export function/name counts up to 65,536, with bounds-checked export header RVA mapping.
- Does **not** cap total imports/exports allocated by the backend, CPU, RSS, or hostile-file process lifetime.
- Preserves public JSON v1.0.0 and CLI usage. Compatibility on unusual PE layout remains unverified pending wider corpus.
- [PR #21](https://github.com/ELITEAYOTO/REL/pull/21), [Windows/Linux CI #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688): format, Clippy, tests including public inspection API, release CLI, PE oracle and resource profiler passed. [LibFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686): 586,015 executions in 31 seconds, no detected crash. [Limitations](docs/security/P15A_DIRECTORY_BUDGETS.md) remain explicit.

### P1.5-A — PE structural header preflight (verified on Windows/Linux and fuzz smoke)

- Added isolated, allocation-free `crates/rel-pe/src/preflight.rs` before invoking the existing goblin parser.
- Checks DOS NT pointer (≤1 MiB), NT/COFF signature and boundaries, 1–96 sections, optional header (2–4096 bytes, PE32/PE32+) and full section-header table bounds.
- Added golden, malformed and threshold tests including public-API negative checks; no new dependency or JSON v1 contract change.
- Limits are conservative alpha policy; unusual valid PE images might be rejected. This is **not** an RSS/CPU budget, full PE verifier, or sandbox.
- [PR #20](https://github.com/ELITEAYOTO/REL/pull/20) passed [Windows/Linux CI #39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717) (format, Clippy, tests, Release CLI, Windows independent PE oracle) and [libFuzzer #39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726): 642,364 executions in 31 seconds with no observed crash. [Limits](docs/security/P15A_PE_PREFLIGHT.md) remain explicit.

### P1.5-A — Cross-platform RSS and CPU observations (verified)

- Added an independent Python profiler `scripts/profile_resources.py`, using `psutil==7.0.0` on Windows and Ubuntu.
- Records observed child-process RSS, sampled CPU time and wall time against controlled PE64 overlay sizes; also REL's own executable on Windows.
- Stores environment and individual samples as per-platform GitHub Actions artifacts. **Sampling underestimates true peaks and enforces no RAM/CPU limits.**
- **Verified:** [PR #19](https://github.com/ELITEAYOTO/REL/pull/19), [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706) passed on Windows/Ubuntu; resource reports saved as per-run artifacts.
- Full memory/CPU budgets and representative PE benchmarks remain P1.5-A work.

### P1.5-A — JSON output budget (verified)

- Added focused `tools/rel-inspect/src/report.rs`, a bounded pretty-JSON encoder for the existing binary manifest.
- Initial alpha limit: **16 MiB** of JSON bytes; failure occurs before file/stdout output, without silently truncating a valid report.
- Preserved manifest JSON v1.0.0 and normal formatting; precise boundary/equivalence unit tests added.
- The bound **does not cover** parser memory/RSS/CPU or disk-write failures; [scope and limitations](docs/security/P15A_BOUNDED_OUTPUT.md).
- **Verified:** [PR #18](https://github.com/ELITEAYOTO/REL/pull/18), [CI #39104382262](https://github.com/ELITEAYOTO/REL/actions/runs/39104382262) succeeded on Ubuntu and Windows: rustfmt, Clippy, unit/integration tests, release build, CLI smoke and independent Windows PE oracle.

### P1.5-A — Bounded file acquisition (validated on controlled inputs)

- Extracted input acquisition into `tools/rel-inspect/src/input.rs`; parser/JSON output contract unchanged.
- Added preflight file-type policy, a single opened descriptor, a strict actual-read bound, and detection of observable size/timestamp changes.
- Added deterministic unit cases for growth/truncation/size limits, plus CLI smoke checks for directories and symlinks where available.
- **Important:** this does not eliminate pre-open path races, same-size concurrent writes, RAM/CPU exhaustion or process isolation risks; [limitations](docs/security/P15A_BOUNDED_INPUT.md).
- **Verified** [PR #17](https://github.com/ELITEAYOTO/REL/pull/17): [CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604) succeeded on Ubuntu and Windows with formatting, Clippy, unit/integration tests, release build, smoke and independent Windows PE oracle.

### Strategy decision — RFC-0001 / ADR-0013

- Accepted a **full reverse-engineering platform** mission, with Evidence & Evolution as its method for reproducible, explainable, bounded conclusions. This is a product decision, not a claim of novel decompilation or shipped diff.
- Recorded explicit P1.5-A hardening, EX-01 minimal experimental evidence envelope, EX-02 PE metadata-only diff pilot **before P2 Ghidra**, then P3 function matching.
- Added ADR-0013, experimental specs, validation gates and an alpha threat model; existing source crates and manifest v1.0.0 remain unchanged.
- **Not implemented:** EX-01, EX-02, Ghidra adapter, function matching, behavior lab or GUI. Source license remains undecided.


### P1.5 — Fuzzing and verified TLS regression resolution (bounded)

- Introduced a separate nightly libFuzzer workspace, using unmodified synthetic PE32/PE32+ seeds.
- **F001 discovered:** [fuzz run 39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574) failed with an out-of-bounds TLS index panic inside `goblin 0.9.3`. Original 1,104-byte input saved unchanged and SHA-256 documented.
- A first `catch_unwind` mitigation was **insufficient under libFuzzer's panic strategy**, as demonstrated by the second failed run; this is recorded, not concealed.
- Updated existing parser dependency to **pinned goblin 0.10.7**, with regenerated root `Cargo.lock` and evidence-based ADR-0012.
- **Verified:** [fuzz run 39101228893](https://github.com/ELITEAYOTO/REL/actions/runs/39101228893) succeeded: 688,395 instrumented executions over 31 seconds, no detected crash; [standard CI 39101228912](https://github.com/ELITEAYOTO/REL/actions/runs/39101228912) green on Windows and Ubuntu, including saved F001 regression.
- No claim of comprehensive parser safety. Extended fuzzing, toolchain pinning, sandbox isolation and larger PE corpus remain outstanding.

### P1.5 — Verified increments, hardening still in progress

- **[PR #4](https://github.com/ELITEAYOTO/REL/pull/4)** — Deterministic PE32/PE32+ negative-input regression: 512 seeded mutations per synthetic fixture, plus fixed-interval truncations. Linux and Windows green in [run 39098578436](https://github.com/ELITEAYOTO/REL/actions/runs/39098578436). This is not coverage-guided fuzzing.
- **[PR #5](https://github.com/ELITEAYOTO/REL/pull/5)** — CLI timing harness and stored Windows/Linux JSON observations for 2 KiB, 1 MiB and 4 MiB synthetic overlay inputs; [integrated run 39098808184](https://github.com/ELITEAYOTO/REL/actions/runs/39098808184) green. Timings are descriptive, not regression targets or isolated parse CPU benchmarks.
- **[PR #6](https://github.com/ELITEAYOTO/REL/pull/6)** — Windows Release EXE self-inspection checked against pinned `pefile==2024.8.26` for section layout, imported DLLs and file identity; [run 39098961562](https://github.com/ELITEAYOTO/REL/actions/runs/39098961562) green on both platforms.

### P1 — Previously verified

- Modular Rust workspace with `rel-contracts`, `rel-pe` and `rel-inspect`.
- Static PE32/PE32+ section/import/export inspection and versioned JSON manifest.
- Golden synthetic fixtures, invalid-input tests and cross-platform executable smoke.
- [PR #1](https://github.com/ELITEAYOTO/REL/pull/1), [CI 39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395).
- Tracked `Cargo.lock` and strict `--locked` CI from [PR #3](https://github.com/ELITEAYOTO/REL/pull/3), [run 39097322823](https://github.com/ELITEAYOTO/REL/actions/runs/39097322823).

### Unfinished — do not mark P1.5 complete

- Coverage-guided fuzzing, minimized crash cases, security testing.
- Diverse legally redistributable PE reference samples from other toolchains.
- Resource-limit hardening, cross-platform path/symlink coverage, dependency review and memory benchmarks.
- Ghidra adapter, version matcher, classifier, runtime behavior lab and desktop UI have not been implemented.
