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

## Accepted product direction and sequencing — ADR-0013, 18 October 2026

- **D12:** REL remains a general-purpose, powerful reverse-engineering research platform. Evidence & Evolution (explainable longitudinal comparisons, reproducible observations) is a proposed differentiator, not a constraint to compliance scanning.
- **D13:** Critical P1.5-A input/resource hardening precedes EX-01 experimental evidence/coverage and EX-02 PE manifest metadata diff, which are **deliberately scheduled before P2 Ghidra**. P3 retains meaning: deep function matching.
- **D14:** manifest v1.0.0 immutable absent separate compatibility ADR; hypotheses, partial/failed extraction and missing imports cannot be presented as proven absence of behavior.
- **D15:** do not create speculative modules, UI, graph database or AI engine before testing a concrete need. Use existing stable module boundaries.
- **D16:** selecting a redistributable source LICENSE requires dedicated review; repository visibility alone does not grant an open-source license.

Reference decision: [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [gates](STRATEGY_AND_GATES.md) and [RFC-0001](../rfc/RFC-0001-EVIDENCE-EVOLUTION.md). These are **adopted design decisions**, not completed software features. Revisions require a new ADR supported by tests and trade-offs, never a new assistant's styling preference.
