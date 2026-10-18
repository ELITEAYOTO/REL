# Reverse Engineering Lab (REL)

A **modular, reproducible, offline-first reverse-engineering platform** for authorized binary analysis and cross-version evolution. Its adopted **Evidence & Evolution** strategy emphasizes explainable, bounded, reproducible findings, while preserving deep reverse engineering as a long-term capability.

**Strategic decision:** [RFC-0001](docs/rfc/RFC-0001-EVIDENCE-EVOLUTION.md), accepted with [ADR-0013](docs/adr/ADR-0013-vision-evidence-evolution.md). [Milestone gates](docs/governance/STRATEGY_AND_GATES.md).

**Current status (2026-10-18): P1 alpha validated; P1.5 partial hardening verified (mutation regression, cross-platform CLI timings, independent Windows PE oracle, and bounded libFuzzer smoke after upgrading goblin). Not production-hardened.** The original [CI run](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395) passed on Ubuntu and Windows. P1.5 evidence is recorded in [CHANGELOG](CHANGELOG.md). See [P1 evidence](docs/P1_VALIDATION.md).

## Existing modules

| Crate | Responsibilities |
| --- | --- |
| `rel-contracts` | Stable, serializable manifest data model |
| `rel-pe` | Static PE32/PE32+ parsing: sections, imports, exports |
| `rel-inspect` | Standalone CLI: file limit, SHA-256, report output |

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

Use rel-inspect.exe on Windows. On Linux only, you may additionally pass `--max-address-space-mib 2048 --max-cpu-seconds 10` to install kernel-enforced per-process **virtual address-space** and **CPU-time** ceilings in the child before `exec`. This is different from a resident RAM/RSS ceiling and is disabled by default. The watchdog retains an opt-in wall-time kill and **sampled** RSS threshold. On Windows only, `--max-job-memory-mib 512` can opt into a native Job Object committed-memory budget, with the analyzer suspended until assignment, and kill-on-close for associated descendants. These controls do not replace the standard CLI or provide a **cross-platform, process-tree-wide** CPU-time limit, a resident RAM ceiling or a security sandbox. Read [scope, failure modes and reproducibility](docs/security/P15A_SUPERVISOR_V0.md).

## Principles frozen for contributors and AI assistants

Read [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md), [frozen decisions](docs/governance/DECISIONS_FIGEES.md), [code quality](docs/governance/CODE_QUALITY.md) and [roadmap](ROADMAP.md) before changes.

- One repository, **independently testable tools/crates**, one-way dependencies.
- Rust for native analysis/core; Python for future adapters; Java/C++/C# only upon demonstrated need.
- CLI-first; JSON contracts and evidence before a desktop frontend.
- Architectural changes require an ADR and reproducible evidence, not aesthetics.
- Never label untested functionality as complete; keep unsupported facts isolated.
- Imported executables are **not executed implicitly**; runtime research is opt-in, sandboxed and authorized.

## Alpha input policy (P1.5-A bounded reader verified)

The standalone CLI now uses a focused input-reading module with an actual-read cap of 512 MiB and rejects symlinks/non-regular paths; it still cannot guarantee a coherent snapshot if a file is modified while read. See [bounded input security notes](docs/security/P15A_BOUNDED_INPUT.md). This is **not** a general sandbox or overall RAM/CPU budget. The reader's unit and CLI integration gates passed [Windows/Linux CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604).

## Alpha JSON output policy (P1.5-A, verified on Windows/Linux)

The standalone CLI now has a **provisional 16 MiB JSON report budget** enforced while serializing. Reports exceeding that limit are rejected before the CLI opens an output file or writes stdout. The report v1.0.0 schema and normal output format are unchanged. The [Windows/Linux CI #39104382262](https://github.com/ELITEAYOTO/REL/actions/runs/39104382262) passed with the new report serializer; the limit remains provisional pending representative measurements. This budget does **not** cap parser allocations, memory usage or CPU time. See [bounded JSON report notes](docs/security/P15A_BOUNDED_OUTPUT.md).

## Paired benchmark/resource evidence quality (P1.5-A candidate)

Windows and Linux CI also validate that both JSON measurement tools observed the same input cases and file hashes, and verify their sampled statistics without inventing missing RAM/CPU values. An additional `rel-measurement-evidence.json` artifact describes the internal consistency and sampling coverage. See [measurement scope](docs/P15_RESOURCE_PROFILING.md). This does **not** establish a production performance threshold or security isolation.

## Controlled measurement corpus (P1.5-A resource/relocation candidate)

The resource profiler and CLI benchmark share a [hash-verified PE32/PE64 scenario inventory](docs/security/P15A_CORPUS_PROVENANCE.md): two tracked synthetic fixtures, deterministic zero-filled overlays and the locally compiled REL EXE on Windows. A controlled C source is compiled with MSVC and, in the candidate PR, also Clang-cl on Windows. Generated executables are **never executed**; the LLVM version is recorded for traceability. A further controlled Windows candidate compiles tracked `structured_probe.c` and `structured_probe.rc` to exercise `.rsrc` RCDATA and `.reloc` base relocations, independently verified by `pefile`; REL currently reports section metadata, **not** resource or relocation semantics. Output distinguishes scenario identifiers and source hashes from runtime measurements. **Redistribution rights are not established**, and this is not a diverse third-party or cross-compiler corpus. The repository still has no selected source license; see [issue #16](https://github.com/ELITEAYOTO/REL/issues/16).

## P1.5-A resource measurements (Windows/Linux verified)

A separate [resource profiler](docs/P15_RESOURCE_PROFILING.md) records observed child-process RSS, CPU time and wall time on synthetic PE samples and on REL's compiled Windows EXE. The profiler uses a 30-second test timeout but **does not impose a production runtime limit**. Sampling cannot establish actual peak memory. [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706) passed on Windows/Ubuntu; per-platform JSON observation artifacts were uploaded.

## PE header preflight (P1.5-A, validated on controlled samples)

Before handing an authorized PE to the third-party parser, `rel-pe` now validates minimal header offsets, section count (1–96), optional-header declaration (2–4096 bytes, PE32/PE32+) and the bounds of the section-header table, without allocating. These are conservative alpha compatibility limits, **not** general parsing safety or resource isolation. See [preflight policy and limitations](docs/security/P15A_PE_PREFLIGHT.md); The narrow gate passed [Windows/Linux CI #39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717) and [libFuzzer #39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726). Header budgets do **not** constrain downstream parser CPU, allocations or RSS.

## Declared directory budgets (P1.5-A, verified on controlled inputs)

The PE alpha preflight also checks declared import/export directory sizes (each at most 1 MiB) and the announced number of exported symbols (65,536 per count field). These checks happen before `goblin`, but they **do not limit all parser CPU/RAM** and may reject unusual legitimate PEs. See [directory budget policy](docs/security/P15A_DIRECTORY_BUDGETS.md). [CI Windows/Linux #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688) and [libFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686) passed. The alpha limits are narrow and do **not** establish overall parser CPU/RAM safety.

## Project maturity / risks

- Two synthetic fixtures are insufficient to infer quality on complex modern Windows binaries.
- Stable Rust dependencies are pinned in `Cargo.lock` and a bounded libFuzzer run has succeeded; extended fuzzing, representative corpus, CPU/RAM budgets, fuzz-specific toolchain pinning and process isolation remain unfinished P1.5 work.
- `goblin` is a provisional parser adapter, not a permanent lock-in; switching requires measured reasons and an ADR.
- No source license selected: do not assume redistribution rights for third-party code/binaries.

See [changelog](CHANGELOG.md), [roadmap](ROADMAP.md) and [future-chat handoff](docs/governance/HANDOFF_NEXT_CHAT.md).

## Next validated direction (not yet implemented)

After critical P1.5 resource/path hardening on **controlled inputs**, EX-01 will explore a small independent contract for provenance/coverage/diagnostics, and EX-02 will test a **metadata-only** Rust PE manifest diff before P2 Ghidra. P3 still means function matching, not import-list comparison. No changes to `binary-manifest` v1.0.0.

Read [EX-01 spec](docs/specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02 spec](docs/specs/METADATA_DIFF_PILOT.md), and [alpha threat model](docs/security/THREAT_MODEL_ALPHA.md). The repo is public but no source license is selected yet.
