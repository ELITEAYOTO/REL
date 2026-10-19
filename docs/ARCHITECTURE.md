# Architecture P1

- `rel-contracts`: serializable, parser-independent manifest types.
- `rel-pe`: reads untrusted PE bytes statically; no execution.
- `rel-inspect`: single-purpose CLI and input/output safety gates.
- Contract format: JSON, versioned as `1.0.0`.
- No dependency from a library crate on the CLI; dependency graph is one-way.
- Future Ghidra integration is a separate process/module with its own tests.
- Future behavior testing must be opt-in, isolated and on authorized targets.
- Refactoring is evidence-led; breaking interfaces require ADR, migration plan and tests.

## Adopted target direction — ADR-0013 (not yet implemented)

P1 runtime modules are `rel-contracts`, `rel-pe`, and `rel-inspect`; EX-01 adds the **separate, experimental** `rel-observe` producer rather than coupling its output into the existing P1 CLI. REL is a general reverse-engineering research platform targeting explainable change-tracking and provenance for **authorized** binary software.

Next experiments **EX-01** (independent experimental observation/coverage contract) and **EX-02** (Rust metadata-only manifest diff) follow critical P1.5-A hardening and precede **P2 external Python Ghidra adapter**. P3 stays deep function matching. A hypothetical `rel-diff` must depend on stable contract data, not on `rel-pe` internals or a bundled Ghidra. No empty module shells just to realize diagrams.

Gates [ADR-0013](adr/ADR-0013-vision-evidence-evolution.md), [strategy](governance/STRATEGY_AND_GATES.md), [EX-01](specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02](specs/METADATA_DIFF_PILOT.md) and [threat model](security/THREAT_MODEL_ALPHA.md). Preserve JSON manifest v1.0.0; use a new ADR for any breaking schema/API change.
