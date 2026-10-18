# P1.5-A — Bounded JSON report serialization

**Status:** implementation in PR, Windows/Linux CI pending. This is a small resource guard, **not** global memory management.

## Motivation

Previously `rel-inspect` called `serde_json::to_vec_pretty`, allocating a complete JSON response without any independent report-size budget. A small binary can in principle yield a large metadata report. The existing **512 MiB input cap** is not a cap on generated JSON, parser allocations or peak process RSS.

## Implementation boundary

- New `tools/rel-inspect/src/report.rs` is the *only* new module. `rel-pe`, `rel-contracts` and the published binary manifest schema v1.0.0 remain unchanged.
- The CLI now serializes into a `Write` implementation enforcing **16 MiB maximum for JSON bytes**. The writer rejects a chunk before adding any bytes that would exceed the cap.
- The writer reserves memory fallibly with `try_reserve` before appending; a failed reservation is returned as an I/O/serialization error rather than an intentional panic.
- The complete JSON document is rendered into the bounded buffer **before opening the output report file or writing stdout**. A size-limit failure therefore does not leave a partially serialized report.
- The CLI still uses `create_new`, preserving the existing refusal to overwrite a report or input file.
- Plain stdout mode appends a newline **outside** the 16 MiB JSON budget. Documented cap pertains to the JSON document, not final stdout byte count.

## Testable gates

- Report bytes are **byte-for-byte equivalent** to the former pretty JSON encoding on our known schema.
- Exactly at the limit: accepted. One byte below the serialized length: rejected.
- Oversized diagnostic warning: rejected. The writer does not append beyond its cap.
- Existing PE32/PE64 CLI smoke, JSON Schema, Windows self-oracle, Cargo tests, Clippy and formatting pass in CI on the PR.
- Record CI run IDs and update the changelog before marking this increment verified.

## Scope limitations / still unresolved

- **16 MiB is a provisional conservative alpha policy, not a performance-derived optimum.** Real corpus measurements may justify changing this limit through a documented compatibility decision.
- Parsing and populating Rust `Vec<String>` sections/imports/exports already occurs before JSON serialization; this new bound does **not** constrain their allocations, the source file buffer, hashing, total process RSS or CPU time.
- The serializer still allocates a buffer up to 16 MiB; it does **not** stream output directly to a file, intentionally preventing partial reports on report-cap errors.
- Disk-write failures after `create_new` can still leave a partial file. True transactional report publication requires a separate atomic-write design.
- A reported output limit error is not a statement about malicious file safety or a secure sandbox.
- No CLI flag changes are made; the limit is a documented alpha constant shared by both stdout and file output.

See [threat model](THREAT_MODEL_ALPHA.md), [input reader](P15A_BOUNDED_INPUT.md), [ROADMAP](../../ROADMAP.md) and [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).
