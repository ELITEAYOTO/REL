# Changelog

## [Unreleased] — 2026-10-18

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
