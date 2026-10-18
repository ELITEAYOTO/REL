# Reverse Engineering Lab (REL)

A **modular, reproducible, offline-first** research suite for analyzing binaries that users are authorized to inspect, with future comparison across software versions.

**Current status (2026-10-18): P1 alpha validated on a two-file synthetic PE32/PE32+ corpus. Not production-hardened.** The dedicated [CI run](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395) passed on Ubuntu and Windows; [PR #1](https://github.com/ELITEAYOTO/REL/pull/1) was merged. See [P1 evidence](docs/P1_VALIDATION.md).

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

## Principles frozen for contributors and AI assistants

Read [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md), [frozen decisions](docs/governance/DECISIONS_FIGEES.md), [code quality](docs/governance/CODE_QUALITY.md) and [roadmap](ROADMAP.md) before changes.

- One repository, **independently testable tools/crates**, one-way dependencies.
- Rust for native analysis/core; Python for future adapters; Java/C++/C# only upon demonstrated need.
- CLI-first; JSON contracts and evidence before a desktop frontend.
- Architectural changes require an ADR and reproducible evidence, not aesthetics.
- Never label untested functionality as complete; keep unsupported facts isolated.
- Imported executables are **not executed implicitly**; runtime research is opt-in, sandboxed and authorized.

## Project maturity / risks

- Two synthetic fixtures are insufficient to infer quality on complex modern Windows binaries.
- Dependency resolution is pinned by committed `Cargo.lock`. Fuzzing, property testing, PE edge-case coverage and performance measurements remain P1.5 work.
- `goblin` is a provisional parser adapter, not a permanent lock-in; switching requires measured reasons and an ADR.
- No source license selected: do not assume redistribution rights for third-party code/binaries.

See [changelog](CHANGELOG.md), [roadmap](ROADMAP.md) and [future-chat handoff](docs/governance/HANDOFF_NEXT_CHAT.md).
