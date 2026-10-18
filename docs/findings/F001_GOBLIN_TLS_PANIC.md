# F001 — Unwinding dependency panic on malformed PE TLS directory

**Status:** Confirmed in prior job; REL mitigation pending new CI. **Dependency:** goblin 0.9.3, under `goblin = "0.9"` in Cargo.toml. **Scope:** intentionally malformed synthetic PE, not a real-world executable.

## Direct evidence

- First coverage-guided run: https://github.com/ELITEAYOTO/REL/actions/runs/39100602574 (failure).
- Fuzzer reported a Rust panic in `goblin-0.9.3/src/pe/tls.rs:228:35`: `range start index 383194904 out of range for slice of length 1104`.
- Original crashing input: GitHub Actions artifact `rel-pe-fuzz-artifacts-6039fd910f821381aa93e33a8578bc05e22b2022`, artifact ID `12125854899`.
- Original input: 1104 bytes; SHA-256 `f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e`.
- Preserved unmodified in `fixtures/regressions/goblin-0.9.3-tls-oob.bin`, Git blob `ab7b5e918bce1b89fa1acb2fc65236b6597a981c`.
- Regression: `crates/rel-pe/tests/fuzz_tls_regression.rs`.

## Containment (not root-cause fix)

REL's `rel-pe::inspect` now calls `goblin::pe::PE::parse` at an explicit `std::panic::catch_unwind` boundary and maps *unwinding* dependency panics to `PeError::DependencyPanic`. The calling CLI will return an error instead of allowing such an unwind to propagate. The Rust panic hook can still print a diagnostic.

This is **not a security boundary** and cannot contain aborting panics, process termination, arbitrary native memory corruption or out-of-memory termination. Future hostile-input processing requires subprocess isolation and resource limits. The underlying `goblin` bug remains until an upstream version is confirmed fixed or the offending field is validated pre-parse.

## Follow-up

1. Re-run the exact saved reproducer through the library tests and CLI; verify `Err`, no propagated panic.
2. Re-run bounded libFuzzer; preserve any distinct crash artifacts.
3. Check upstream goblin fixes/advisories and test upgrades against the full existing corpus before deciding an ADR.
4. Minimize the failing input with `cargo fuzz tmin`, if reproducible on a dedicated environment; preserve the original bytes for provenance.
5. Build proper input isolation (not just catch_unwind) before handling hostile files.

**Do not mark the underlying third-party panic resolved merely because REL returns an error.**
