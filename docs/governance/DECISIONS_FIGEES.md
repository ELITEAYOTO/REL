# REL — Frozen design baseline

Status: ACCEPTED, 2026-10-18. This is a project-specific decision log, not a claim of universal optimality.

| ID | Baseline | Rationale / change policy |
| --- | --- | --- |
| D1 | Cargo workspace monorepo, independent crates/CLIs | Cohesion and independent validation; ADR required to change |
| D2 | Rust for owned native core/parsers/matchers | Safety/performance/tooling; Python for Ghidra and experimentation |
| D3 | TypeScript/Tauri UI deferred | Avoid GUI coupling until CLI contracts are stable |
| D4 | P1 static PE only | Never execute an EXE merely to analyze it |
| D5 | Versioned JSON/JSONL schemas at module boundaries | Independently verifiable interchange and historic compatibility |
| D6 | Parser backend replaceable behind `rel-pe` | Compare `goblin` and alternatives empirically, not aesthetically |
| D7 | No speculative reimplementations of Ghidra, BinDiff or BSim | Wrap and benchmark existing tools first |
| D8 | Evidence + uncertainty + negative tests mandatory | Claims must be supported; unknown is a valid outcome |
| D9 | Targeted refactors only | See `CODE_QUALITY.md` for thresholds and exceptions |
| D10 | Future runtime research opt-in and isolated | Authorization and safety before execution |
| D11 | No cloud service required for V1 | Offline-first, optional future integrations via ADR |

Architecture modifications: identify actual problem -> gather measurements -> compare alternatives -> ADR -> compatibility and migration plan -> tests -> CHANGELOG. A later chat must **not silently reset these decisions**.

The baseline does not prohibit evolution: it requires justification and traceability.
