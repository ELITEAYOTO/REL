# rel-observe — controlled EX-01 observation producer

This is a **real but deliberately narrow** experimental Rust producer.
It reads actual file bytes, reports a SHA-256 identity, and compares the
first two DOS signature bytes against `MZ` (present) and `NE`
(absent **only within the two-byte domain**). It is **not a decompiler
or complete PE parser**. It does not infer game/runtime/network behavior.

## Usage

```sh
cargo run --locked -p rel-observe -- dos-magic fixtures/pe32-basic.exe
cargo run --locked -p rel-observe -- dos-magic fixtures/pe64-basic.exe
cargo run --locked -p rel-observe -- coff-machine fixtures/pe32-basic.exe
cargo run --locked -p rel-observe -- coff-machine fixtures/pe64-basic.exe
```

JSON is sent to standard output. Errors go to standard error with a
nonzero exit code; the CLI does not write files or overwrite reports.

## Contract and identity

Output uses `0.1.0-experimental` from
`contracts/experimental/observation-envelope.schema.json`, **not**
`binary-manifest v1.0.0`. The source hash and two-byte evidence are derived
from the same bounded input buffer.

The configuration hash is SHA-256 over the literal UTF-8 string
`rel-observe:dos-magic:v1;limit=2097152;require-mz-and-pe-signatures`.
The reproducible run ID is SHA-256 of the ordered concatenation:

1. `REL-EX01-RUN-v1\0` (ASCII);
2. 32 raw bytes of SHA-256(input);
3. 32 raw bytes of SHA-256(configuration string);
4. `pe.dos_magic\0` (ASCII);
5. UTF-8 producer version (`CARGO_PKG_VERSION`).

No file path, host data, or timestamp affects this ID.
Two byte-identical controlled files with the same tool and configuration
produce byte-identical JSON. Different file bytes yield distinct hashes.

## Control boundaries

Only local controlled inputs are intended. Current limit is **2 MiB**;
oversized, short, non-`MZ`, missing minimal `PE\\0\\0` signature, directories
and observable final-component symlinks are rejected without JSON output.
Minimal signature checks do not establish overall PE validity.
Files could be changed by concurrent writers between stat/open/read;
ancestor paths are not descriptor-confined, and this is **not a sandbox**.
For hostile files use a separately justified OS isolation boundary.
Input binaries are never executed.

Run `python scripts/test_observe_cli.py --binary target/release/rel-observe`
(on Windows use `rel-observe.exe`) to verify actual output against the
independent Python contract validator and fixture bytes. Overall EX-01 is
still incomplete; only the `pe.dos_magic` domain has a real producer.


## Experimental COFF Machine observation (PR #53 merged; scoped CI verified)

`coff-machine` reads a second, independent domain `pe.coff_machine`.
It uses `e_lfanew` (DOS offset `0x3c`) to locate the four-byte
`PE\\0\\0` signature and then observes the **two bytes**
at `e_lfanew + 4`, interpreted as a little-endian unsigned 16-bit
`Machine` field. Evidence is file-offset typed and bound to the
subject's SHA-256. It normalizes only `0x014c` as `x86` and
`0x8664` as `x86_64`; unknown codes stay in hex (no invented family).

If the PE signature is present but fewer than two machine bytes remain,
the report has scope `partial`, observation `indeterminate`, no
decisive evidence, and diagnostic `COFF_MACHINE_TRUNCATED`. Missing
MZ / e_lfanew / PE signatures are refused with a nonzero exit code,
rather than falsely implying a verified negative.

The COFF configuration string for the independent SHA-256 run ID is
`rel-observe:coff-machine:v1;limit=2097152;require-mz-and-pe-signatures`.
The run ID uses the same documented binary preimage structure as
`dos-magic`, substituting this config and `pe.coff_machine\\0`
for the old domain. Different domains have different run IDs,
including on identical file bytes.

These two bytes do **not** establish general PE validity,
compatibility, or executable behavior. The reader remains controlled
input only, not snapshot-safe or an arbitrary hostile-binary sandbox.
Validate through `python scripts/test_coff_machine_cli.py --binary
target/release/rel-observe` (or `.exe` on Windows). [PR #53](https://github.com/ELITEAYOTO/REL/pull/53) and [main CI #39182313199](https://github.com/ELITEAYOTO/REL/actions/runs/39182313199) passed on Windows/Linux.

## Experimental section-header observation (PR #55 merged; scoped CI verified)

```sh
cargo run --locked -p rel-observe -- section-headers fixtures/pe32-basic.exe
```

The independent `pe.section_headers` domain locates the 20-byte COFF
header after the minimal MZ / PE signatures. It reads `NumberOfSections`
at `e_lfanew + 6` and `SizeOfOptionalHeader` at `e_lfanew + 20`.
The declared section header table begins at
`e_lfanew + 24 + SizeOfOptionalHeader`, with 40 bytes per record.
Only up to 32 records are supported. Every observation contains the
original 40 bytes as hex and a conservative normalized representation
of name **bytes** (hex), virtual size/RVA, file raw-size/pointer and flags;
each record has exact file-offset evidence bound to the input SHA-256.

Incomplete COFF/header table data produce `partial`, `indeterminate`,
no decisive evidence and warning diagnostics. More than 32 declared
sections produce `unsupported` without guessing the first 32.
A zero-count declaration with a complete optional-header span yields
`absent_in_scope` anchored to the two COFF count bytes. The domain
does not validate whether raw pointers, RVA ranges, relocations, or
execution permissions actually resolve, and is **not** a PE sandbox.

Run ID uses the documented preimage from the DOS command with
configuration string
`rel-observe:section-headers:v1;limit=2097152;max=32;record=40`
and domain `pe.section_headers\0`. The independent cross-platform
oracle `scripts/test_section_headers_cli.py` recomputes all values. [PR #55](https://github.com/ELITEAYOTO/REL/pull/55) and [post-merge Windows/Linux CI #39184367267](https://github.com/ELITEAYOTO/REL/actions/runs/39184367267) passed in this narrow scope.

## Independent source-backed evidence verifier (PR #57 merged, scoped CI verified)

```sh
python scripts/verify_observation_evidence.py \
  --input fixtures/pe32-basic.exe --report saved-ex01-report.json
```

This **separate Python checker** accepts an existing `0.1.0-experimental`
report and the exact controlled PE file that is claimed to be its
subject. It first validates the JSON contract, then independently
recomputes the SHA-256 and byte length, expected tool configuration
and run ID, exact source offsets/lengths and all claimed observation
values for the three known domains (`pe.dos_magic`, `pe.coff_machine`,
`pe.section_headers`). It rechecks abstention and diagnostics for
partial COFF/section headers and excessive declared section counts.

The checker fails closed on an unknown domain or producer, extra/missing
observations or evidence, a changed normalized value, shifted offset,
incorrect absence claim or inconsistent run ID. It does not make
unsupported claims about section payloads or executable behavior.

**Trust boundary:** the verifier only establishes report/byte agreement
on a caller-supplied controlled file. A malicious party able to supply
both report and matching file can construct consistent false provenance.
Hashes are not signatures. Neither report nor file has a trusted
publisher identity, filesystem snapshot, source-supply-chain guarantee,
or arbitrary-hostile-input sandbox. The verification input is limited
to 2 MiB and is never executed. This is not a universal PE validator. [PR #57](https://github.com/ELITEAYOTO/REL/pull/57) and [post-merge main CI #39186361225](https://github.com/ELITEAYOTO/REL/actions/runs/39186361225) passed Windows/Linux with deliberately falsified report tests.
