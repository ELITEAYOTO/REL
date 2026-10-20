# Reverse Engineering Lab (REL)

A **modular, reproducible, offline-first reverse-engineering platform** for authorized binary analysis and cross-version evolution. Its adopted **Evidence & Evolution** strategy emphasizes explainable, bounded, reproducible findings, while preserving deep reverse engineering as a long-term capability.

**Strategic decision:** [RFC-0001](docs/rfc/RFC-0001-EVIDENCE-EVOLUTION.md), accepted with [ADR-0013](docs/adr/ADR-0013-vision-evidence-evolution.md). [Milestone gates](docs/governance/STRATEGY_AND_GATES.md).

**Current status (2026-10-20 dated checkpoint): P1 alpha, selected P1.5 hardening, limited EX-01 producers, and experimental EX-02 metadata-only pilot are integrated. A GNU MinGW-w64 x64 PE32+ compiler-built static oracle was added in [PR #107](https://github.com/ELITEAYOTO/REL/pull/107), and exact new-main [Windows/Ubuntu CI #39371988276](https://github.com/ELITEAYOTO/REL/actions/runs/39371988276) passed. The MinGW PE also participates in paired Linux resource observations ([PR #109](https://github.com/ELITEAYOTO/REL/pull/109); [main CI #39373817606](https://github.com/ELITEAYOTO/REL/actions/runs/39373817606) passed). This is one controlled new compiler/linker case, **not** a legally cleared representative corpus or hostile-file sandbox. Full P1.5, EX-01 and EX-02 gates remain OPEN. Consult [CURRENT_STATE.md](docs/governance/CURRENT_STATE.md) and verify live GitHub.** The original [CI run](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395) passed on Ubuntu and Windows. P1.5 evidence is recorded in [CHANGELOG](CHANGELOG.md). See [P1 evidence](docs/P1_VALIDATION.md).

## Experimental EX-01 observation contract (prototype only)

An independent `contracts/experimental/observation-envelope.schema.json` and validation script now describe *scoped observations* with explicit coverage/uncertainty and bounded file-offset evidence. To validate a controlled example after installing the existing CI `jsonschema>=4,<5` dependency:

```sh
python scripts/validate_observation_envelope.py fixtures/experimental/observation/present.json
python scripts/test_observation_envelope.py
```

These hand-authored examples demonstrate contract semantics on an owned synthetic fixture. An additional, independent **controlled-source Rust producer** now emits real reports for only `pe.dos_magic`:

```sh
cargo run --locked -p rel-observe -- dos-magic fixtures/pe32-basic.exe
```

It computes actual file SHA-256 and two-byte evidence and uses an explicitly documented deterministic run ID; see [producer details](tools/rel-observe/README.md). An additional experimental `coff-machine` command can read the two-byte COFF Machine field using the actual `e_lfanew` offset and return `partial`/`indeterminate` for a truncated field, rather than invent an architecture. A separate `section-headers` command now reads up to 32 **declared 40-byte section-header records** from controlled inputs and records exact file-offset proofs; incomplete records abstain rather than forming a partial table of invented conclusions. A new **source-backed verifier** can check a saved experimental report independently against the controlled source file:

```sh
python scripts/verify_observation_evidence.py --input fixtures/pe32-basic.exe --report path/to/observation.json
```

It recalculates subject SHA-256, producer/config/run-ID consistency, byte offsets, raw/normalized values and scope/diagnostics for the three supported domains, rejecting report tampering. This verifies agreement with supplied bytes, **not report authenticity**, trusted provenance, atomic file acquisition, or executable behavior. See [verifier scope](tools/rel-observe/README.md). The original `rel-inspect` still emits only `binary-manifest v1.0.0`. **EX-01 remains experimental and incomplete**, and no absence of runtime/game/network capabilities can be inferred from a two-byte signature. See [scope](docs/specs/OBSERVATION_ENVELOPE_DRAFT.md).

## Existing modules

| Crate | Responsibilities |
| --- | --- |
| `rel-contracts` | Stable, serializable manifest data model |
| `rel-pe` | Static PE32/PE32+ parsing: sections, imports, exports |
| `rel-inspect` | Standalone CLI: file limit, SHA-256, report output |
| `rel-observe` | Experimental standalone DOS signature evidence producer on controlled PE inputs |

The parser never executes an imported EXE/DLL. Other features (decompilation, matching, knowledge graph, AI classifier, execution/emulation, desktop UI) are **not implemented**.

## Run

Requirements: Rust 1.85.1 (see `rust-toolchain.toml`), Cargo, Python 3 with `jsonschema` for smoke tests.

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo build --locked --release -p rel-inspect
python -m pip install "jsonschema>=4,<5"
python scripts/smoke_cli.py --binary target/release/rel-inspect
```

On Windows, replace the smoke binary with `target/release/rel-inspect.exe`.

```bash
rel-inspect analyze sample.exe --output report.json
rel-inspect --version
```

Omit `--output` to emit JSON to stdout. Existing report paths are rejected rather than overwritten. Output contract: `contracts/schemas/binary-manifest.schema.json` (v1.0.0).

## Optional bounded analyzer runner (P1.5-A experimental)

For controlled authorized PE inputs, the independent Python watchdog can launch the REL CLI as one supervised child (requires psutil==7.0.0):

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect --input fixtures/pe64-basic.exe

Use rel-inspect.exe on Windows. On Linux only, you may additionally pass `--max-address-space-mib 2048 --max-cpu-seconds 10` to install kernel-enforced per-process **virtual address-space** and **CPU-time** ceilings in the child before `exec`. This is different from a resident RAM/RSS ceiling and is disabled by default. The watchdog retains an opt-in wall-time kill and **sampled** direct-child RSS threshold. Linux can also opt into `--max-sampled-tree-rss-mib 512`, which sums observed RSS of the analyzer and discoverable live descendants during each poll. This is NOT a native memory ceiling: shared pages may be counted more than once, short-lived children may be missed, and reparented or detached descendants can escape observation. On Windows only, `--max-job-memory-mib 512` can opt into a native Job Object committed-memory budget, and `--max-job-cpu-seconds 10` can opt into a job-wide **user-mode** CPU-time budget (combined or CPU-only), with the analyzer suspended until assignment, and kill-on-close for associated descendants. These controls do not replace the standard CLI or provide a **cross-platform, process-tree-wide** CPU-time limit, a resident RAM ceiling or a security sandbox. Read [scope, failure modes and reproducibility](docs/security/P15A_SUPERVISOR_V0.md).

## Principles frozen for contributors and AI assistants

Read [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md), [frozen decisions](docs/governance/DECISIONS_FIGEES.md), [code quality](docs/governance/CODE_QUALITY.md) and [roadmap](ROADMAP.md) before changes.

- One repository, **independently testable tools/crates**, one-way dependencies.
- Rust for native analysis/core; Python for future adapters; Java/C++/C# only upon demonstrated need.
- CLI-first; JSON contracts and evidence before a desktop frontend.
- Architectural changes require an ADR and reproducible evidence, not aesthetics.
- Never label untested functionality as complete; keep unsupported facts isolated.
- Imported executables are **not executed implicitly**; runtime research is opt-in, sandboxed and authorized.

## Alpha input policy (P1.5-A bounded reader verified)

On Unix, [PR #39](https://github.com/ELITEAYOTO/REL/pull/39) adds a descriptor identity check and [PR #40](https://github.com/ELITEAYOTO/REL/pull/40) rejects symlinked ancestors through descriptor-relative path opening; both passed final and post-merge Windows/Linux CI. The latter may reject symlinked or execute-only ancestor paths. Windows currently guards the final reparse point and ordinary writer opens, **not** ancestor junctions; neither platform guarantees an atomic snapshot or hostile-filesystem isolation.

The standalone CLI uses a focused input-reading module with an actual-read cap of 512 MiB and rejects symlinks/non-regular paths. A second bounded pass over the same opened descriptor can detect additional same-size modifications at the cost of another file read. It **still cannot guarantee a coherent atomic snapshot** if a file is modified while read. See [bounded input security notes](docs/security/P15A_BOUNDED_INPUT.md). This is **not** a general sandbox or overall RAM/CPU budget. The reader's unit and CLI integration gates passed [Windows/Linux CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604).

### Windows parent reparse points (P1.5-A, scoped CI-verified)

A narrow Windows input-path check rejects observable ancestor reparse points, such as directory junctions, before and just after acquiring the input handle. This is **not race-free**; it does not prevent ordinary directory swaps or make paths an atomic snapshot. Previously supported inputs behind a junction may now be rejected. The unchanged leaf reparse and read-sharing policies still apply. See [bounded input notes](docs/security/P15A_BOUNDED_INPUT.md). [PR #42](https://github.com/ELITEAYOTO/REL/pull/42) and [post-merge Windows/Linux CI #39167703067](https://github.com/ELITEAYOTO/REL/actions/runs/39167703067) are verified in their limited scope.

## Windows opened-handle identity (P1.5-A, verified in scoped CI)

As defense in depth, the Windows controlled-input CLI also compares the volume+128-bit file identities of its guarded read descriptor and a second guarded opening of the requested path. This can reject detectable target differences after the first open; it is not proof of atomic path resolution, a snapshot, or arbitrary hostile-filesystem safety. Unsupported file ID providers now fail closed. [PR #45](https://github.com/ELITEAYOTO/REL/pull/45) passed Windows/Linux final-head and [post-merge CI #39171804456](https://github.com/ELITEAYOTO/REL/actions/runs/39171804456). See [bounded input notes](docs/security/P15A_BOUNDED_INPUT.md).

## Alpha JSON output policy (P1.5-A, verified on Windows/Linux)

The standalone CLI now has a **provisional 16 MiB JSON report budget** enforced while serializing. Reports exceeding that limit are rejected before the CLI opens an output file or writes stdout. The report v1.0.0 schema and normal output format are unchanged. The [Windows/Linux CI #39104382262](https://github.com/ELITEAYOTO/REL/actions/runs/39104382262) passed with the new report serializer; the limit remains provisional pending representative measurements. This budget does **not** cap parser allocations, memory usage or CPU time. See [bounded JSON report notes](docs/security/P15A_BOUNDED_OUTPUT.md).

## Provenance des mesures par machine (P1.5-A candidate)

The paired benchmark/profile observations now also record an explicit reported host and toolchain context and exact release analyzer SHA-256. A canonical fingerprint prevents combining reports from different GitHub jobs or binaries while retaining missing RSS/CPU sample flags. This improves **same-job evidence traceability**, not cross-run performance comparability or hardware attestation. See [P1.5 measurement notes](docs/P15_RESOURCE_PROFILING.md).

## Comparing independent measurement campaigns (P1.5-A pilot)

The offline [campaign-comparison tool](docs/P15_CROSS_RUN_COMPARISON.md) can check two complete timing/RSS report pairs collected in different GitHub runs, rejecting mismatched hardware/toolchain/REL binaries, input hashes or sampling policies. It produces **descriptive** median timings only when the evidence is compatible, and otherwise refuses to display numeric ratios. This is not a controlled performance benchmark or a production CPU/RAM budget.

## Paired benchmark/resource evidence quality (P1.5-A PR CI verified)

Windows and Linux CI also validate that both JSON measurement tools observed the same input cases and file hashes, and verify their sampled statistics without inventing missing RAM/CPU values. An additional `rel-measurement-evidence.json` artifact describes the internal consistency and sampling coverage. See [measurement scope](docs/P15_RESOURCE_PROFILING.md). This does **not** establish a production performance threshold or security isolation.

## Controlled measurement corpus (P1.5-A resource/relocation candidate)

The resource profiler and CLI benchmark share a [hash-verified PE32/PE64 case inventory](docs/security/P15A_CORPUS_PROVENANCE.md) with two tracked synthetic fixtures, deterministic overlays, and the locally compiled REL EXE on Windows. Windows CI also builds controlled source-defined MSVC/Clang-cl x64 executables and structured `.rsrc`/`.reloc` probes, verified independently with pinned `pefile`. A separate [PE32 x86 DLL CI oracle](docs/security/P15A_CORPUS_PROVENANCE.md) checks two ephemeral locally built DLLs. Neither imported input nor these test binaries are executed or loaded for analysis, and no generated compiler binaries are committed. These are controlled static layout checks, **not** comprehensive resource/relocation decoding, pinned build reproducibility, a licensed third-party corpus, or proof of safe hostile-input handling. **Redistribution rights remain unverified** and the repository still has no adopted source license ([issue #16](https://github.com/ELITEAYOTO/REL/issues/16)); the broader [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) is OPEN.

## P1.5-A resource measurements (Windows/Linux verified)

A separate [resource profiler](docs/P15_RESOURCE_PROFILING.md) records observed child-process RSS, CPU time and wall time on synthetic PE samples and on REL's compiled Windows EXE. The profiler uses a 30-second test timeout but **does not impose a production runtime limit**. Sampling cannot establish actual peak memory. [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706) passed on Windows/Ubuntu; per-platform JSON observation artifacts were uploaded.

## PE header preflight (P1.5-A, validated on controlled samples)

Before handing an authorized PE to the third-party parser, `rel-pe` now validates minimal header offsets, section count (1–96), optional-header declaration (2–4096 bytes, PE32/PE32+) and the bounds of the section-header table, without allocating. These are conservative alpha compatibility limits, **not** general parsing safety or resource isolation. See [preflight policy and limitations](docs/security/P15A_PE_PREFLIGHT.md); The narrow gate passed [Windows/Linux CI #39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717) and [libFuzzer #39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726). Header budgets do **not** constrain downstream parser CPU, allocations or RSS.

## Declared directory budgets (P1.5-A, verified on controlled inputs)

The PE alpha preflight also checks declared import/export directory sizes (each at most 1 MiB) and the announced number of exported symbols (65,536 per count field). These checks happen before `goblin`, but they **do not limit all parser CPU/RAM** and may reject unusual legitimate PEs. See [directory budget policy](docs/security/P15A_DIRECTORY_BUDGETS.md). [CI Windows/Linux #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688) and [libFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686) passed. The alpha limits are narrow and do **not** establish overall parser CPU/RAM safety.

## Project maturity / risks

- Two synthetic fixtures are insufficient to infer quality on complex modern Windows binaries.
- Stable Rust dependencies and the separate dated fuzz-nightly/lock are pinned; one 300-second campaign completed without observed crash and the controlled malformed-PE resource campaign is green. Additional diverse fuzzing, representative licensed PE corpus and hard CPU/RAM/disk/process-tree containment remain unfinished P1.5 work ([#8](https://github.com/ELITEAYOTO/REL/issues/8), [#9](https://github.com/ELITEAYOTO/REL/issues/9)).
- `goblin` is a provisional parser adapter, not a permanent lock-in; switching requires measured reasons and an ADR.
- No source license selected: do not assume redistribution rights for third-party code/binaries.

See [changelog](CHANGELOG.md), [roadmap](ROADMAP.md), **[current-state / next-chat entry point](docs/governance/CURRENT_STATE.md)** and the [historical handoff archive](docs/governance/HANDOFF_NEXT_CHAT.md).

## Current development direction (snapshot 2026-10-19; verify GitHub)

EX-01 has **limited experimental observation producers and source verification** already integrated in `main`, not a universal complete-coverage analysis engine. EX-02 has an **experimental metadata-only PE manifest comparison pilot integrated on `main` via [PR #62](https://github.com/ELITEAYOTO/REL/pull/62)**, independently versioned from the public v1 manifest and **not** the complete EX-02 acceptance gate. Later P2 Ghidra adaptation and P3 function matching are planned, not implemented. `binary-manifest v1.0.0` remains unchanged. Consult [CURRENT_STATE](docs/governance/CURRENT_STATE.md) for the latest known checkpoint and verify live PR heads/CI rather than trusting this dated summary.

Read [EX-01 spec](docs/specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02 spec](docs/specs/METADATA_DIFF_PILOT.md), and [alpha threat model](docs/security/THREAT_MODEL_ALPHA.md). The repo is public but no source license is selected yet.
