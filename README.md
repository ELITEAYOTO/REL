# Reverse Engineering Lab (REL)

A modular, reproducible, offline-first research suite for **authorized static binary analysis** and future cross-version comparison.

**Stage:** P1 — PE Binary Inspector, not yet accepted. See [roadmap](ROADMAP.md), [change history](CHANGELOG.md) and [agent contract](AGENTS.md).

## Current modules

| Crate | Responsibility |
| --- | --- |
| `rel-contracts` | JSON-friendly, parser-independent metadata types |
| `rel-pe` | Parse PE32/PE32+ headers, sections, imported/exported symbols without executing input |
| `rel-inspect` | Standalone command-line entry point; SHA-256 and JSON manifest |

The libraries do **not** import the CLI. Future tools integrate via versioned contracts; Ghidra, version matching, AI and runtime experiments are **not implemented** yet.

## Try it

Requires Rust 1.85.1, Cargo and Python 3 with `jsonschema` for the CLI smoke test.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --release -p rel-inspect
python -m pip install "jsonschema>=4,<5"
python scripts/smoke_cli.py --binary target/release/rel-inspect
```

On Windows, use `target/release/rel-inspect.exe` for the smoke test.

```bash
rel-inspect analyze file.exe --output report.json
rel-inspect --version
```

Omit `--output` to write JSON to standard output. Existing reports cannot be overwritten. Importing a file **never runs it**.

## Quality policy

- Keep `rel-contracts`, `rel-pe` and `rel-inspect` independently testable.
- Do not introduce a decompiler or emulator into P1.
- Rust module review at 350 lines; exception required at 500 lines of handwritten code. These are review thresholds, not automatic split orders.
- Significant architectural changes need an ADR, a test plan and migration notes.
- Never claim an analysis is verified without evidence and a recorded version.
- See [P1 acceptance criteria](docs/P1_VALIDATION.md).

## Safety and licensing

The tool never launches imported binaries. Do not use this work to bypass protections or instrument online games without authorization. No third-party proprietary binaries are included. A project license has not yet been selected; no third-party license is implied.
