# REL architecture — P1 alpha and experimental pilots

- `rel-contracts`: serializable, parser-independent manifest types.
- `rel-pe`: reads untrusted PE bytes statically; no execution.
- `rel-inspect`: single-purpose CLI and input/output safety gates.
- Contract format: JSON, versioned as `1.0.0`.
- No dependency from a library crate on the CLI; dependency graph is one-way.
- Future Ghidra integration is a separate process/module with its own tests.
- Future behavior testing must be opt-in, isolated and on authorized targets.
- Refactoring is evidence-led; breaking interfaces require ADR, migration plan and tests.

## Adopted target direction — ADR-0013 (partially implemented)

P1 runtime modules are `rel-contracts`, `rel-pe`, and `rel-inspect`. The independently versioned **EX-01 pilot** includes `rel-observe` producers for limited DOS signature, COFF machine and section-header evidence; it does not modify the P1 manifest. The **EX-02 pilot** `rel-diff` is an existing standalone Rust CLI that consumes v1 manifest JSON as data and emits a separate experimental metadata-diff report. Its crate has no `rel-pe` or bundled Ghidra dependency. Neither pilot's full acceptance gate is complete.

ADR-0013 sequences critical P1.5-A hardening, EX-01 and EX-02 experiments before **P2 external Python Ghidra adapter**; P3 remains deep function matching. P2/P3 are **not implemented**. REL remains a general reverse-engineering platform for authorized analysis and explainable evolution, not a manifest-only product. No empty module shells just to realize diagrams.

Gates [ADR-0013](adr/ADR-0013-vision-evidence-evolution.md), [strategy](governance/STRATEGY_AND_GATES.md), [EX-01](specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02](specs/METADATA_DIFF_PILOT.md) and [threat model](security/THREAT_MODEL_ALPHA.md). Preserve JSON manifest v1.0.0; use a new ADR for any breaking schema/API change.
