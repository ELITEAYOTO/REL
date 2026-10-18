# ADR-0012 — Experiment with goblin 0.10.7 after F001

Status: **experimental upgrade in PR #10 — not validated** (2026-10-18)

## Evidence
- libFuzzer confirmed an unhandled panic in goblin 0.9.3 TLS input handling: [CI #39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574).
- The first mitigation using `catch_unwind` did not prevent the fuzz process from aborting: see CI logs in PR #10.
- The upstream [goblin changelog](https://docs.rs/crate/goblin/0.10.7/source/CHANGELOG.md) lists PE TLS out-of-bounds fixes in 0.10.0 (PR #448) and a TLS raw-data parser correction in 0.10.1 (PR #473).

## Proposed scoped modification
Upgrade the **existing** parser adapter's pinned dependency from `goblin 0.9.3` to `goblin 0.10.7`. Do not change public REL contracts, the module boundaries or the CLI.

## Acceptance
- Rebuild `Cargo.lock` with verified versions and enforce locked CI on Linux and Windows.
- Confirm F001 original bytes are rejected without process termination on both platforms.
- Run instrumented libFuzzer for a bounded trial on the exact same synthetic corpus.
- Check existing PE32/PE32+ sections/imports/exports and Windows PE oracle for regressions.
- Keep F001 open until verified; fuzz success is not proof of general memory safety.

## Fallback and rollback
Revert only the dependency+lockfile if API breakage, incompatible behavior or new crashes occur, then evaluate a focused input pre-validation or a genuinely isolated parser process.

The dependency upgrade is motivated by **observed test failure**, not an arbitrary refactor.
