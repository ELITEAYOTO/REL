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
