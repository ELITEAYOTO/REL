# Changelog

## [Unreleased] - 2026-10-18

### P1.5 — in progress
- Added deterministic, seeded malformed-input mutation regression tests for `rel-pe` (512 mutations and fixed-interval truncations per PE32/PE64 fixture).
- Added separate methodology and limitations documentation in `docs/P15_MUTATION_TESTING.md`.
- **Not yet verified**: full CI on the associated PR; coverage-guided fuzzing and representative real-world binaries are still outstanding.

### P1 (verified)
- Modular Rust workspace and PE32/PE32+ static inspector.
- Synthetic fixtures, parser tests and CLI JSON Schema validation.
- [PR #1](https://github.com/ELITEAYOTO/REL/pull/1): [CI 39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395) green on Ubuntu and Windows.
- [PR #3](https://github.com/ELITEAYOTO/REL/pull/3): [CI 39097322823](https://github.com/ELITEAYOTO/REL/actions/runs/39097322823) green with locked dependency resolution.

### Not implemented
- Ghidra adapter, binary diff, classifier, behavior simulation and desktop interface.
