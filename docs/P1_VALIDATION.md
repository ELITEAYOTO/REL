# P1 — Verified acceptance and scope

## Verified on 2026-10-18

- **Pull request:** [#1](https://github.com/ELITEAYOTO/REL/pull/1)
- **Merged commit:** `58ddb71d25c3d9698ee6acbb5446c9b5cc1b497a`
- **CI run:** [39096882395](https://github.com/ELITEAYOTO/REL/actions/runs/39096882395)
- **Runners:** Ubuntu and Windows; both jobs completed SUCCESS.
- **Checks:** Rust formatting, Clippy with denied warnings, 6 Rust tests (2 original + 4 integration), optimized compilation, JSON Schema-backed executable smoke test.

## Test evidence

- `fixtures/pe32-basic.exe` and `fixtures/pe64-basic.exe` are reproducible synthetic test inputs.
- `fixtures/expected.json` records SHA-256, sizes, architecture, section names, imports, and exports.
- `crates/rel-pe/tests/fixture_pe.rs` tests successful PE parsing and rejects invalid/truncated samples.
- `scripts/smoke_cli.py` executes the **compiled REL CLI**, not the imported fixtures. It checks parsed output, JSON schema and non-overwrite behavior.
- `contracts/schemas/binary-manifest.schema.json` is the authoritative P1 output contract.

## Boundaries

- No native executable is run by the inspector; static parsing only.
- The corpus contains **two crafted examples**, not a representative suite of modern PE variations.
- Fuzzing, advanced malformed PE coverage, runtime/memory profiling, reproducible lockfile and packaging remain P1.5.
- No implication that all malicious inputs are safe, or that gameplay/network behavior is inferred.
- Claims of platform compatibility extend only to the tested CI environments, not end-user installers.
