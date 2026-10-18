# P1.5-A — Declared PE directory and export-count budgets

**Status:** experimental alpha checks — CI evidence pending. This is a scoped preflight, not full PE validation or a process memory limit.

## Threat and purpose

A structurally valid NT/COFF header can advertise expensive or inconsistent data-directory counts. Previously, the [header preflight](P15A_PE_PREFLIGHT.md) checked the section table only, then delegated all import/export metadata to `goblin 0.10.7`. REL now rejects certain extreme declarations **before** invoking the backend. This limits a specific class of potentially costly inputs without parsing or executing the inspected program.

## Scope and conservative alpha thresholds

| Data | Alpha policy | What it actually bounds |
| --- | --- | --- |
| Export data directory declaration | Up to **1 MiB** reported size | A declared header field; does not bound all export strings or their allocated data |
| Import data directory declaration | Up to **1 MiB** reported size | A declared header field; does not walk or cap imported functions/thunks |
| Export `NumberOfFunctions` | Maximum **65,536** | Count announced in the 40-byte export directory header |
| Export `NumberOfNames` | Maximum **65,536** | Count announced in the same export header |
| Export directory RVA | Its 40-byte export header must map into a complete raw section region | Prevents reading an invalid export-header location in the preflight itself |
| PE32/PE32+ optional header | Inspect only the first two data-directory records when declared, and require enough optional-header bytes to cover them | Avoids out-of-bounds reads when counts are inconsistent |

The import and export *directory size fields* may be inaccurate: `goblin` does not promise to honor them as memory/CPU budgets. These thresholds are additional early rejection checks, **not** proof of bounded allocations or complexity.

## Implementation

- `crates/rel-pe/src/preflight/directories.rs` performs slice and checked-offset reads; no allocation and no filesystem access.
- Existing `preflight::validate` invokes the directory check after validating the PE section-header table.
- Export RVA-to-file-offset mapping uses the first matching section's `VirtualAddress`, `SizeOfRawData` and `PointerToRawData`; if the 40-byte directory header cannot be mapped, this alpha policy rejects the file.
- Main `rel_pe::inspect`, CLI parameters, imported/exported JSON strings, JSON Schema v1.0.0 and dependency versions are unchanged.
- Golden PE32/PE32+, malformed export/import declarations, wrong RVA, count boundaries and missing optional-directory records have unit tests. CI also runs the existing Windows executable reference oracle and Linux fuzz smoke.

## Compatibility and residual risk

This intentionally rejects some possible, unusually laid-out PEs (export tables stored outside section raw data, large export counts, oversized directory-size declarations, overlapping section cases). These are **policy limitations**, not universal PE-format invalidity. They must be evaluated against redistributable real-world binaries before increasing platform-compatibility claims.

This does **not** enforce a parser RSS/CPU/time budget, cap all generated strings, validate import thunks, or guarantee that malformed PE input is harmless. `catch_unwind` is not sandboxing; neither are directory header checks. Hostile binaries require a separate worker/OS limits and deeper directory testing.

## Evidence gates

1. `cargo fmt`, Clippy, all tests, build and CLI smoke pass on Windows/Ubuntu.
2. Real Windows Release `rel-inspect.exe` is still accepted and agrees with the independent pefile oracle.
3. Original F001 regression remains error-only; Linux instrumented libFuzzer smoke passes on these new checks.
4. Record run IDs and relevant counts before checking off the roadmap item.
5. Leave [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) open: true CPU/RSS limits, robust parser sandboxing and broader licensed corpus remain outstanding.

See [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [security model](THREAT_MODEL_ALPHA.md) and [preflight stage 1](P15A_PE_PREFLIGHT.md).
