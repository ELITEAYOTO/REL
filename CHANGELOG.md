# Changelog

## [Unreleased] — 2026-10-18

### P1.5-A — Optional CI-built Clang-cl x64 PE case (PR candidate, CI pending)

- Build the same tracked C PE probe with runner-installed LLVM Clang-cl in addition to MSVC, via the Windows SDK. Compare imports, named exports and PE32+ architecture independently through pinned pefile; no inspected PE is executed.
- Record a ninth Windows corpus case in both measurement harnesses, its checked C source SHA-256, binary SHA-256 and the observed Clang version string. Fail if the compiler, compiled PE or version record is absent. Linux remains at six cases.
- This measures a second compiler **frontend** but may share the Microsoft linker and SDK. The hosted compiler/toolchain remains unpinned, rights to redistribute generated binaries are not established, and no JSON binary-manifest v1.0.0 changes occur.



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
