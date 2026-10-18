# P1.5-A — Conservative structural PE preflight

**Status:** header preflight verified in [PR #20](https://github.com/ELITEAYOTO/REL/pull/20), [CI #39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717) (Ubuntu/Windows) and [libFuzzer #39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726). **P1.5-A remains incomplete.** This is **not** a parser sandbox.

## Goal

Check minimal Portable Executable structural bounds *before* invoking the third-party parser (`goblin = 0.10.7`). This is an independent `rel-pe` internal module, not another PE parser or new crate. It runs in O(1) operations and does not allocate.

## Tested alpha policy (provisional)

| Data | Policy / validation | Reason and limitation |
| --- | --- | --- |
| DOS `e_lfanew` (little-endian u32 at 0x3c) | Must exist and be ≤ **1 MiB** | Reject implausibly distant NT header for alpha corpus; PE variants with large DOS stubs may be rejected |
| NT header | `PE\\0\\0` signature + complete 20-byte COFF header | Reject truncated/wrong offsets |
| COFF NumberOfSections | **1–96** | Bounded section-header work; zero-section/over-96 files unsupported by alpha policy |
| SizeOfOptionalHeader | **2–4096 bytes** with `0x10b` (PE32) or `0x20b` (PE32+) magic | Reject oversized declarations, truncated header and unsupported optional-header types |
| Section table | `NumberOfSections × 40` bytes must fit entirely in input following declared optional header | Reject out-of-range table without reading it |

All slice regions use checked offset/length arithmetic. The `inspect` entry point validates these conditions before invoking goblin and returns a `PeError::Parse` for disallowed structure. Unrecognized file signatures retain the existing `PeError::Unsupported` result.

## Contract and compatibility

- **No** changes to the public JSON `binary-manifest` v1.0.0 or the CLI arguments/output.
- No new dependencies, network activity, file execution, new crate or major refactor.
- The alpha-policy limits can reject some technically parseable, unusual or nonstandard PE files. Documented limits require reevaluation against a diverse licensed corpus before claiming broad support.
- The file input size limit of 512 MiB and output JSON limit of 16 MiB remain independent.

## Verified evidence

- [Standard CI #39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717): Ubuntu and Windows SUCCESS, including PE32/PE32+, public-API limits, previously saved F001, schema and native Windows executable oracle.
- [Instrumented libFuzzer #39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726): SUCCESS; 642,364 executions in 31 seconds and 492 MiB tool-reported peak RSS on the hosted Ubuntu job. These are job-specific observations, **not** general parser safety guarantees.
- Header field/layout definitions and the Windows 96-section loader limit: [Microsoft PE/COFF format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). The NT-offset and optional-header size caps are REL alpha policy rather than universal file-format requirements.

## Verification scope

Unit tests in `crates/rel-pe/src/preflight.rs` exercise PE32 and PE32+ golden fixtures, truncated DOS/NT/COFF/optional/section-table regions, bad magic, too many/no sections, and declared optional-header size boundaries. Integration tests exercise both limits via the public `rel_pe::inspect` API.

Validation gates: Rust fmt/Clippy/test/release CLI on Windows and Ubuntu; independent Windows PE oracle (REL Release EXE); synthetic fixtures and original F001 input regression; instrumented libFuzzer gate on Linux. Record exact run IDs and any regressions before merging.

## What preflight cannot do

- It does **not** guarantee correctness of PE import/export directories, TLS, certificate table or file section *contents*. It checks only top-level header layout and the section *header table*, not all raw section offsets.
- A valid header can describe enormous/malformed/recursive data directories. Allocations inside goblin and after parsing are **not** bounded by these checks.
- This is not a strict CPU, RSS, output or runtime limit, and does not catch all panics/aborts. `catch_unwind` remains a limited fallback, not isolation.
- REL still operates on controlled-authorized alpha test inputs; do not treat it as safe for arbitrary malicious PE files.

Further work: resource budgets covering imports/exports and allocations, real-world corpus validation, hostile-input worker isolation, controlled parsing timeouts, no-follow opens, and same-size file-change races.

See [threat model](THREAT_MODEL_ALPHA.md), [ROADMAP](../../ROADMAP.md), [F001 finding](../findings/F001_GOBLIN_TLS_PANIC.md), and [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).


## Candidate follow-up: section raw-byte range validation (PR CI pending)

Before invoking goblin, the section-table preflight now checks that every section with `SizeOfRawData > 0` has a `PointerToRawData + SizeOfRawData` range wholly contained in the input. Checked indexing rejects overflows and out-of-file ranges. Zero-sized raw sections remain accepted irrespective of raw pointer (virtual-only sections). No raw section bytes are copied or read by this gate; complexity is O(sections), capped at 96 by the existing alpha policy.

Added unit boundary cases (both PE32 and PE32+, just-past-EOF, enormous declarations, exact EOF, zero-sized) plus the public `rel_pe::inspect` error regression. Validation on real Windows and Linux PE binaries, fuzz and `--locked` CI is **pending**. This is not a complete specification of PE section semantics: overlapping/noncanonical/virtual ranges and section permissions remain unexamined. Legitimate unusual PEs with short raw data may now be rejected; quantify compatibility against the licensed corpus before expanding claims. No CPU/RSS cap, process sandbox or manifest v1 change is implied.
