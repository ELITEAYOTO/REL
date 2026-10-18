# REL roadmap

- [x] P0 — research, scoped design and architecture decisions.
- [ ] P1 — PE Binary Inspector: code, reference fixtures and CI submitted; PASS requires verified Linux and Windows CI, schema checks and failure-case review.
- [ ] P1.5 — fuzzing, broader malformed PE corpus, benchmarking, reproducible Cargo.lock and legal/license review.
- [ ] P2 — independently test Ghidra headless adapter.
- [ ] P3 — version matcher compared against ground-truth source changes.
- [ ] P4 — persistent evidence/provenance store.
- [ ] P5 — calibrated function classifier with an explicit UNKNOWN result.
- [ ] P6 — opt-in behavior lab for isolated, authorized test targets.
- [ ] P7 — desktop UI only after stable CLI integration.
- [ ] P8 — portability, packaging and release hardening.

Architecture principle: independent crates and CLI tools, stable JSON contracts, no monolithic refactor. Changes to stack or contract require an ADR.
