# F001 — Malformed PE TLS panic in goblin 0.9.3

**Status:** Historical failure verified; the saved reproducer is handled by REL with pinned goblin 0.10.7 in tested configurations. Upstream/root-cause tracking continues under [issue #11](https://github.com/ELITEAYOTO/REL/issues/11).

## Original reproduction (source of truth)

- [Fuzz run 39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574) exited in failure with a panic from `goblin-0.9.3/src/pe/tls.rs:228:35`.
- Panic message: `range start index 383194904 out of range for slice of length 1104`.
- Original crash artifact: Actions artifact ID `12125854899` (run 39100602574).
- Original input: **1104 bytes**, SHA-256 `f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e`.
- Preserved byte-for-byte at `fixtures/regressions/goblin-0.9.3-tls-oob.bin`; verified Git blob `ab7b5e918bce1b89fa1acb2fc65236b6597a981c`.
- Permanent regression test: `crates/rel-pe/tests/fuzz_tls_regression.rs` plus CLI negative check.

## Investigated mitigations

1. A `std::panic::catch_unwind` boundary around `goblin::pe::PE::parse` converts **unwinding** parser panics to `PeError::DependencyPanic` in normal Rust builds. This alone did **not** prevent the sanitizer fuzz process from aborting.
2. Upstream goblin changelog documents TLS integer overflow/OOB fixes in **0.10.0** (#448) and raw-data correction in **0.10.1** (#473).
3. REL upgraded the existing adapter (no API contract change) to pinned `goblin 0.10.7` with a regenerated `Cargo.lock`. See [ADR-0012](../adr/ADR-0012-goblin-tls-upgrade.md).
4. [Fuzz CI 39101228893](https://github.com/ELITEAYOTO/REL/actions/runs/39101228893) succeeded after 688,395 cases; [standard CI 39101228912](https://github.com/ELITEAYOTO/REL/actions/runs/39101228912) passed on Windows and Ubuntu.

## What this does not prove

- Absence of other input-triggered goblin bugs, crashes, hangs or exploitability.
- Effectiveness of `catch_unwind` against aborting panic strategies, memory unsafety, OOM, or subprocess failures.
- Correctness of PE semantics on arbitrary binaries. The original seed is deliberately malformed.

Follow-up: minimize F001 if useful, pin the fuzz-specific toolchain and lock, extend coverage-guided runs, and add separate process-level isolation for truly hostile binaries.
