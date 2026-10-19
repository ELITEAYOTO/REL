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
