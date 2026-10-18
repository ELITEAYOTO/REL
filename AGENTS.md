# REL agent contract

1. Read README.md, ROADMAP.md, CHANGELOG.md and docs/ARCHITECTURE.md before editing.
2. Core architecture: independent Rust crates, CLI-first, contracts-first. Never introduce implicit execution of imported files.
3. Do not replace the stack or reorganize crates without a dedicated Architecture Decision Record (ADR) and tests.
4. One responsibility per module. Keep public APIs stable and testable.
5. Refactor review thresholds (handwritten): Rust module 350 LOC warning, 500 LOC exception threshold; functions 50 LOC review, 80 LOC exception threshold. These are review triggers, not forced splits.
6. New externally observable behavior requires tests and README/CHANGELOG updates.
7. Do not claim validation without recorded CI result. Do not claim decompilation, network classification or dynamic emulation in P1.
8. No bypass of game anti-cheat or unauthorized execution/instrumentation.
