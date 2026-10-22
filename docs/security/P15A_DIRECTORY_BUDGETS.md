# P1.5-A — Declared PE directory and export-count budgets

**Status:** verified in [PR #21](https://github.com/ELITEAYOTO/REL/pull/21), [Windows/Linux CI #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688) and [libFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686). This is a scoped preflight, not full PE validation or a process memory limit.

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

## Verified CI evidence

- [Windows/Linux standard CI #39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688): SUCCESS, including public API regression, PE32/PE32+ fixtures, F001, release CLI and Windows independent PE oracle.
- [Linux instrumented libFuzzer #39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686): SUCCESS, 586,015 executions in 31 seconds, tool-reported peak RSS 524 MiB. These are tool/runner-specific observations, not a hard memory bound.
- The directory thresholds are **REL alpha policy**, not claims about PE format universals or Windows loader constraints.

## Evidence gates

1. `cargo fmt`, Clippy, all tests, build and CLI smoke pass on Windows/Ubuntu.
2. Real Windows Release `rel-inspect.exe` is still accepted and agrees with the independent pefile oracle.
3. Original F001 regression remains error-only; Linux instrumented libFuzzer smoke passes on these new checks.
4. Record run IDs and relevant counts before checking off the roadmap item.
5. Leave [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) open: true CPU/RSS limits, robust parser sandboxing and broader licensed corpus remain outstanding.

See [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [security model](THREAT_MODEL_ALPHA.md) and [preflight stage 1](P15A_PE_PREFLIGHT.md).

## Additional verified check: complete declared-directory record coverage (PR #47)

A `NumberOfRvaAndSizes` declaration can claim more entries than physically
fit into `SizeOfOptionalHeader`. The original preflight checked only the
availability of export/import slots; a malformed PE declaring, for example,
17 records in space for 16 could pass that specific guard. This candidate
requires **every advertised 8-byte directory entry** to fit fully in the
optional header, for PE32 and PE32+, before calling `goblin`. Count zero
remains supported. This is an allocation-free integer comparison reusing
the existing error for a truncated declaration.

Regression tests exercise an advertised count one above the computed slot
capacity, the exact capacity boundary, both golden PE formats and the public
`rel_pe::inspect` error. No new dependency, parser allocation or
`binary-manifest` v1.0.0 change. It may reject unconventional binaries that
advertise more records than they contain; this is an explicit conservative
alpha policy. **It does not cap import thunk traversal or parser CPU/RSS,
prove PE validity, or safely isolate hostile input.** [PR #47](https://github.com/ELITEAYOTO/REL/pull/47) merged with [final Windows/Linux PR CI #39173751519](https://github.com/ELITEAYOTO/REL/actions/runs/39173751519), [bounded PE fuzz CI #39173751518](https://github.com/ELITEAYOTO/REL/actions/runs/39173751518) and [post-merge main CI #39173973900](https://github.com/ELITEAYOTO/REL/actions/runs/39173973900) all successful. These checks verify only the stated cases, not parser RSS/CPU or security against arbitrary hostile PE inputs.

## Deterministic directory-field regression extension (2026-10-20)

The existing `crates/rel-pe/tests/mutation_regression.rs` exercises 96
**single-field mutations** across tracked synthetic PE32 and PE32+ seeds:
the RVA and size of export, import and TLS data-directory slots, each at
0, 1, 39, 40, 0x2100, 1 MiB, 1 MiB + 1 and `u32::MAX`. The same test
suite already performs fixed-seed truncations and pseudo-random byte flips.
It now explicitly treats `PeError::DependencyPanic` as a failure even when
`rel_pe::inspect` catches the underlying panic and returns an error value,
matching the existing libFuzzer harness's detection policy.

The source fixtures are **unchanged** and verified by the existing
`python scripts/test_corpus_cases.py` gate and
`fixtures/expected.json`: PE32 SHA-256
`86a3634db5fbdd88527a8d7316a7133d2ec27edd05be1dcaa81bf574bfbe765b`,
PE32+ SHA-256
`cc752bedec1980049513e259964adb8ae0a9b6dbd83070cd887d435fd2b3b5f9`.
Mutants live in memory only; no new PE files are committed, loaded or
executed. The test detects backend panics, not whether every mutated
directory is semantically correct. It neither adds a TLS preflight limit
nor establishes coverage-guided fuzz depth, CPU/RSS budgets or sandbox
safety. Issues #8 and #9 remain open.

## Internal import/export pointer mutation regression (2026-10-20)

The existing in-memory regression suite separately mutates six **internal**
directory pointers, not the top-level data-directory RVA/size fields:
export `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`;
import descriptor `OriginalFirstThunk`, `Name`, and `FirstThunk`. Two verified
synthetic PE fixtures × six pointers × eight values give **96 single-field
mutations**. Values include zero, short/out-of-section offsets, both sides of
the `.rdata` raw-section boundary and near-`u32::MAX` offsets. Each result must
avoid native unwind **and** `PeError::DependencyPanic`, without pretending
every mutated image is semantically valid.

A separate negative assertion checks that a required import descriptor DLL
name RVA set to `u32::MAX` returns `PeError::Parse`, rather than accepting a
manifest that silently reports incomplete imports. The test asserts the
source fixtures' expected directory and field positions before mutation,
while the source SHA-256s remain pinned in `fixtures/expected.json` and
checked by the existing corpus-provenance CI. No new fixture binaries are
added, executed or loaded; mutations exist only in test memory.

This is a narrow static-input gate, not complete import-table validation,
proof of completeness for arbitrary files, or a CPU/RSS sandbox.
Issues #8 and #9 remain open.

## Nonempty import directory at RVA zero — focused preflight regression (2026-10-21)

The P1.5 preflight previously verified the size cap for the second PE data
directory (imports), but did not reject a **nonzero size with zero RVA**.
A test-only branch on the existing PE32 and PE32+ 2 KiB source fixtures
demonstrated that `preflight::directories::validate` returned `Ok(())`
for those inconsistent declarations. The new structural guard refuses
the inconsistent pair before Goblin extraction; an explicitly absent
pair (RVA=0, size=0) remains accepted by preflight. The conservative
rule may reject unusual files that previously parsed; external corpus
compatibility remains unmeasured.

The public `rel-pe::inspect` and local preflight tests require a clean
`PeError::Parse` on the two in-memory negative samples, not a panic or
an apparently complete import list. This does **not** verify all import
descriptors, delayed imports, coherent filesystem snapshots, CPU/RSS
bounds or arbitrary hostile-PE safety. No PE image is executed, no
sample is committed or redistributed, and `binary-manifest v1.0.0`
remains unchanged. See issue #9 for exact-head CI evidence after integration.

## First import descriptor completeness (narrow P1.5 regression)

A test-only branch showed that a non-null first import descriptor with its
`Name` or `FirstThunk` RVA set to zero could produce an accepted manifest
rather than a clean error: the current backend stops parsing at a descriptor
that fails its required-field check. REL's preflight now inspects the **first**
descriptor only when the declared import RVA can be mapped to a raw section,
and rejects a non-null descriptor lacking either field. An all-zero
terminator remains valid at that layer. PE32/PE32+ in-memory regressions
check this behavior, without modifying or distributing PE fixtures.

This deliberately **does not** scan every import descriptor, check bound or
delay imports, require unusual header-only RVA layouts to be mappable, or
establish a full import coverage proof. Unmappable descriptors are still
delegated to the backend; the entire parser is not sandboxed and CPU/RAM
budgets remain unresolved. `binary-manifest v1.0.0` remains unchanged.
See [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) for CI evidence.

## Declared-span import descriptor checks (P1.5 regression)

[PR #164](https://github.com/ELITEAYOTO/REL/pull/164) extends the first-descriptor
preflight to all **whole descriptor records within the declared import-directory
byte span**, stopping at an all-zero terminator. A fail-first public API test
duplicates the existing valid first descriptor as a second entry in the two
unchanged 2-KiB PE32/PE32+ fixtures, then independently zeros its required
`Name` and `FirstThunk` fields. The former implementation silently accepted
the malformed second descriptor on PE32. A valid duplicated descriptor
remains parseable with the same deduplicated import names.

This is a bounded, allocation-free check on the *advertised* directory
records only, not a complete import-table proof. The preflight still defers
raw-unmappable/header-only layouts and any entries past the claimed size
to Goblin, and does not validate import thunks, bound/delay imports or
all PE semantics. A potentially dishonest `Size` is not made trustworthy
by scanning it. No generated PE is executed, fixture bytes and manifest
v1 remain unchanged. See [issue #9](https://github.com/ELITEAYOTO/REL/issues/9)
for validation and residual risks.

## Underdeclared import-directory Size: bounded continuation (P1.5)

The [PR #164](https://github.com/ELITEAYOTO/REL/pull/164) guard
originally stopped scanning at the PE-advertised import-directory `Size`.
A new **test-only** PE32/PE32+ case duplicates the valid descriptor in
memory, reduces `Size` from 40 to 20 bytes, and corrupts the second
descriptor's `Name` or `FirstThunk`. The positive control confirms that
the valid duplicate remains accepted. The prior production code accepts the
malformed second descriptor with incomplete import observations (fail-first
CI is recorded in [issue #9](https://github.com/ELITEAYOTO/REL/issues/9)).

The preflight now follows contiguous **raw-mappable** 20-byte descriptors
until a zero terminator, or the existing 1 MiB alpha scan budget measured
in complete records (52,428). A non-null descriptor missing required fields
produces a clean parse error even when it lies outside the claimed Size.
Reaching the scan cap without a terminator produces an explicit error.
An unmappable RVA still falls back to Goblin rather than rejecting a
possibly unconventional PE layout; a zero-size declaration is not scanned.

The cap bounds **this preflight traversal only**. It does not impose a
global parser CPU/RSS/process-tree budget, validate thunk or delayed/bound
imports, repair dishonest directory records, or prove all arbitrary PE
imports are complete. A legitimate PE with unusually many import records
could be rejected under this conservative alpha policy. Fixture bytes,
`binary-manifest v1.0.0`, dependencies and source redistribution
rights remain unchanged.

## Unmappable import RVA is not scan-budget exhaustion (P1.5, #166)

The bounded import-descriptor preflight introduced in #165 used `break`
for a descriptor whose RVA could not be mapped to a raw section, and
then returned the error reserved for consuming **all** 52,428 complete
records without a zero terminator. This incorrectly reported an alpha
scan-cap breach before that cap was reached, contrary to its documented
backend-delegation policy.

A test-only in-memory regression based on unchanged PE32 and PE32+
fixtures exercises (1) an unmappable initial import RVA, and (2) a
mapped valid first descriptor whose following descriptor leaves the
section's reduced raw range. The preflight must defer these cases by
returning `Ok(())` and leave final validity to Goblin. The real
exhaustion path remains a separate explicit error. No claim is made
that a malformed PE becomes valid, that Goblin accepts every such
layout, or that the 1 MiB scan is a global CPU/RSS/security boundary.
No fixture bytes, v1 manifest, dependency or worker policy changes.

## Nonzero import RVA with Size zero (P1.5, #167 integrated)

The import directory has two independently supplied fields: an RVA and
a declared Size. The third-party PE backend can still enumerate ordinary
imports if the **RVA is nonzero and Size is zero**. REL's previous
preflight skipped all such descriptors, allowing a malformed non-null
entry with a missing `Name` or `FirstThunk` to silently truncate the
v1 import observations. The fail-first PE32 test on source-only in-memory
mutations is recorded in [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).

The bounded descriptor scan now applies whenever the RVA is nonzero,
regardless of Size; the fully absent (RVA=0, Size=0) pair remains exempt.
This is a **narrow consistency gate**, not a claim that the size field is
truthful or that all imports are complete. Raw-unmappable entries still
defer to Goblin per #166, and the existing 52,428-record alpha budget
remains the same. No fixture, dependency, manifest schema or worker policy
is changed. [PR #167](https://github.com/ELITEAYOTO/REL/pull/167) was merged
at `7769ec37eebb5b656b1bb644526b1ba5c834fa3a`, with independent
[postmerge Windows/Ubuntu CI #39701091132](https://github.com/ELITEAYOTO/REL/actions/runs/39701091132)
completed successfully (15 standard artifacts). The complete red/green
record and limits are retained in [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).

## Sequential raw import records across section boundaries (P1.5, PR #169)

The existing bounded preflight previously remapped each successive 20-byte import descriptor RVA to a section raw range. Goblin instead maps the **initial** import RVA once, then consumes consecutive 20-byte **file-offset** records. A controlled PE32/PE32+ derivative declares a smaller first raw section and a second, contiguous byte-level import descriptor outside its raw mapping; an adjacent section still maps DLL names, lookup tables and exports. The valid positive case parses, while a PE32 malformed second `Name=0` was accepted with potentially incomplete imports (fail-first test-only SHA `f5b0823878abb98e40c4b02efd0c496e2c94c533`, Ubuntu CI #39704144191).

The integrated #169 correction scans Goblin's same consecutive file bytes after a **mappable first** descriptor, within the existing 52,428-record bound; the initial RVA that cannot be mapped remains delegated for compatibility. A premature file end remains the strict backend's responsibility, not evidence of scan exhaustion. Positive and negative PE32/PE32+ regressions are in the same unchanged-fixture-derived test. Final PR Windows/Ubuntu CI #39704450435 and bounded fuzz #39704450419 passed; distinct post-merge push validation remains separate. This is not validation of every PE import layout, thunk traversal, process CPU/RAM, or source-binary rights; issue #9 stays open.


## Initial import descriptor straddling the raw section (P1.5, PR #170)

A further in-memory PE32/PE32+ probe uses the #169 split-section positive control, but reduces the first section's raw span to **16 bytes** at the initial 20-byte import record. Goblin's section/file-alignment mapping can still locate the first byte and read the full contiguous descriptor. The old preflight required all 20 bytes to fit that section's declared raw size; it delegated this still-readable record without inspecting `Name`/`FirstThunk`, potentially accepting missing imports without warning. Test-only SHA `9fa341ac1275c11c604b8d2cac23d31ca0ed9695`, Ubuntu fail-first CI #39707078470, proves the PE32 `Name=0` case after the valid positive control.

The narrow adjustment requires mapping **one raw byte** at the first RVA, then validates full descriptors using bounded contiguous file-offset reads as already done after #169. Truly unmappable initial RVAs retain backend delegation; section declarations or all possible unusual PE layouts are not generally validated. Positive and negative tests for PE32/PE32+ are derived from the existing unchanged fixtures; separate unit tests isolate the check. This changes no public manifest, dependency or memory/CPU limit and does not amount to a complete sandbox. Record exact final-head Windows/Ubuntu/fuzz and distinct post-merge evidence before claiming full release integration.
