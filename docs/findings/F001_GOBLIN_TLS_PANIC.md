# F001 — Malformed PE TLS panic in goblin 0.9.3

**Status:** Historical failure verified; the saved reproducer is handled by REL with pinned goblin 0.10.7 in tested configurations. Upstream/root-cause tracking continues under [issue #11](https://github.com/ELITEAYOTO/REL/issues/11).

## Original reproduction (source of truth)

- [Fuzz run 39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574) exited in failure with a panic from `goblin-0.9.3/src/pe/tls.rs:228:35`.
- Panic message: `range start index 383194904 out of range for slice of length 1104`.
- Original crash artifact: Actions artifact ID `12125854899` (run 39100602574).
- Original input: **1104 bytes**, SHA-256 `f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e`.
- Preserved byte-for-byte at `fixtures/regressions/goblin-0.9.3-tls-oob.bin`; verified Git blob `ab7b5e918bce1b89fa1acb2fc65236b6597a981c`.
- Permanent regression test: `crates/rel-pe/tests/fuzz_tls_regression.rs` plus CLI negative check.
- The coverage-guided seed corpus now also contains the **same byte-for-byte Git blob** as `fuzz/corpus/pe_inspect/f001-goblin-tls-oob.bin`, with a pre-run CI SHA-256 check. This supplements, rather than replaces, the deterministic regression.

## Investigated mitigations

1. A `std::panic::catch_unwind` boundary around `goblin::pe::PE::parse` converts **unwinding** parser panics to `PeError::DependencyPanic` in normal Rust builds. This alone did **not** prevent the sanitizer fuzz process from aborting.
2. Upstream goblin changelog documents TLS integer overflow/OOB fixes in **0.10.0** (#448) and raw-data correction in **0.10.1** (#473).
3. REL upgraded the existing adapter (no API contract change) to pinned `goblin 0.10.7` with a regenerated `Cargo.lock`. See [ADR-0012](../adr/ADR-0012-goblin-tls-upgrade.md).
4. [Fuzz CI 39101228893](https://github.com/ELITEAYOTO/REL/actions/runs/39101228893) succeeded after 688,395 cases; [standard CI 39101228912](https://github.com/ELITEAYOTO/REL/actions/runs/39101228912) passed on Windows and Ubuntu.

## Upstream bounds failure and patch trace (2026-10-19)

The reported F001 panic is at **`goblin 0.9.3/src/pe/tls.rs:228`**.
Reviewing [that exact source](https://github.com/m4b/goblin/blob/v0.9.3/src/pe/tls.rs#L218-L229)
confirms the TLS raw-data parser used `&bytes[offset..offset + size as usize]`
without validating `offset <= bytes.len()` or the sum's bounds.
The F001 panic's large starting index and 1104-byte input are **consistent
with this unchecked slicing defect**. This source/path correspondence
is strong evidence of the crash mechanism, but it is not a separate
byte-for-byte upstream reproduction with the old crate.

- [Goblin PR #448](https://github.com/m4b/goblin/pull/448) (merged):
  replaces unchecked addition with `checked_add` and explicitly validates
  both `offset` and its computed end against the input length.
- [Goblin PR #473](https://github.com/m4b/goblin/pull/473) (merged):
  later replaces the TLS raw-data slice with a bounded
  `pread_with(...).ok()` lookup returning `None` when the region is
  unavailable. This alters malformed TLS handling; it is **not**
  evidence that all PE invalid-input paths are memory safe.
- [ADR-0012](../adr/ADR-0012-goblin-tls-upgrade.md) records REL's
  narrower verified dependency upgrade to pinned `goblin 0.10.7`.
  The original F001 Rust test must still reject the original file,
  independently of any code path taken by `catch_unwind`.

The deterministic regression now also checks **all 1,104 strict
truncations** and **all 1,104 single-byte XOR-0xff corruptions** of the
preserved F001 sample without allowing a propagated panic. Those mutation
cases only require the parser to return; they do **not** require each
variant to be rejected, and they do not replace the 30-second libFuzzer
smoke or the separately recorded 300-second campaign. Fixture bytes,
public schemas and production parser remain unchanged.

**Still open for issue #11:** independently execute/minimize the original
failure under the old 0.9.3 parser with an appropriately isolated
process, if worth the complexity, and complete a focused upstream
regression provenance review. Do not introduce the vulnerable old crate
into REL's production dependency graph or infer broad security guarantees.

## Independent old-version replay and bounded minimization (2026-10-19)

To complete source-level root-cause investigation without reintroducing the
vulnerable crate into REL, an isolated GitHub Actions experiment compiled
**goblin = 0.9.3** in a **separate Cargo project under the Ubuntu runner's
temporary directory**. It read the historical 1104-byte F001 as bytes and
called the old PE parser. It **did not execute the imported PE**. The exact
F001 SHA-256 was checked before replay. Individual probe processes had
Linux virtual-address-space 1 GiB / CPU 2s limits and a parent timeout
of 3s; these are scoped Linux controls, not a security sandbox.

- [Evidence run #39338392072](https://github.com/ELITEAYOTO/REL/actions/runs/39338392072)
  **completed/success**, with the panic reproduced at
  `goblin-0.9.3/src/pe/tls.rs:228:35`.
- The observed panic was **`range end index 517412631 out of range for
  slice of length 1104`**, whereas the 2026-10-18 original fuzz run
  reported **`range start index 383194904`**. This is the same unchecked
  TLS slice source location and fault class, **not an identical index
  diagnostic**. The first strict-index experiment
  [#39338140557](https://github.com/ELITEAYOTO/REL/actions/runs/39338140557)
  therefore failed as designed; the acceptance predicate was corrected
  to preserve the **same old source line and observed end-index subtype**.
- A bounded delta deletion search (1501 probe invocations, 0 timeouts,
  3.171 seconds of trial work) reduced the sample from **1104 to 1048
  bytes**, SHA-256
  `687718a1765dd0ef0322879c4e5f89bf3ae6920cbf6b7c464ff4571ef17fcbed`.
  The last candidate was replayed successfully against the old parser
  at the same line and end-index type. **The 1500-mutation budget was
  exhausted, so this is a reduced witness, not a proof of global minimum.**
- The unchanged original remains at
  `fixtures/regressions/goblin-0.9.3-tls-oob.bin`. The **separate reduced
  witness** is now retained at
  `fixtures/regressions/goblin-0.9.3-tls-oob-minimized.bin`, and the
  normal `rel-pe` test suite checks the new sample is rejected without
  propagated unwinding under pinned Goblin 0.10.7.
- The [original/reduced panic transcripts, candidate and transient Cargo
  provenance](https://github.com/ELITEAYOTO/REL/actions/runs/39338392072/artifacts/12227477489)
  were archived from the isolated experiment.
  [Test PR #87](https://github.com/ELITEAYOTO/REL/pull/87) was explicitly
  **closed without merge**; production `Cargo.toml`, `Cargo.lock`
  and parser implementation remain free of Goblin 0.9.3.

**Interpretation:** a direct old-library slice bounds bug, with linked
upstream fixes and observed safe rejection by the REL production adapter
in the tested configurations. This does **not** prove all Goblin 0.10.7
input parsing is panic-free, nor provide hard process isolation.

## What this does not prove

- Absence of other input-triggered goblin bugs, crashes, hangs or exploitability.
- Effectiveness of `catch_unwind` against aborting panic strategies, memory unsafety, OOM, or subprocess failures.
- Correctness of PE semantics on arbitrary binaries. The original seed is deliberately malformed.

Follow-up: minimize F001 if useful, pin the fuzz-specific toolchain and lock, extend coverage-guided runs, and add separate process-level isolation for truly hostile binaries.
