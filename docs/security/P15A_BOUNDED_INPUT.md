# P1.5-A — Bounded input acquisition

**Status: bounded-input increment VERIFIED on controlled tests (PR #17, CI #39103698604); P1.5-A remains INCOMPLETE.**  
Scope: `tools/rel-inspect/src/input.rs` only. The PE parser, CLI JSON contract v1.0.0 and dependency versions are unchanged.

## The original issue

Previously, the CLI performed a path-based `fs::metadata` followed by `fs::read`. A file could grow or be replaced between those operations; the pre-check did not bound the actual read. This also meant a path could refer to a non-regular file after inspection.

## The new input policy

1. Use `symlink_metadata` to reject symlinks, directories, devices, named pipes and other non-regular paths before opening in the **alpha controlled-input mode**.
2. Open the candidate **once**, then read `File::metadata` from that open descriptor.
3. Apply the existing 512 MiB input limit to the opened descriptor's declared size.
4. Read through `Read::take(MAX_SIZE + 1)` so a file that grows cannot bypass the limit. Reject an overflow; never parse truncated data as a complete file.
5. Read metadata again from the **same descriptor**, rejecting detectable changes in size or modification timestamp; check actual read length.
6. Only after successful acquisition pass owned bytes to `rel-pe` and compute the SHA-256. Imported binaries are never executed.

## Tests

- Reads a regular file with identical bytes.
- Rejects directories and symbolic links (symlink unit test on Unix; CLI smoke also probes symlink on Windows when creation is supported).
- Rejects file size above a test-only small limit.
- Rejects deterministic growth or truncation **after** a captured size snapshot.
- Existing CLI corpus, F001 regression, PE oracle, stable Rust tests, Clippy and fuzz CI remain separate gates.

## Security limits that remain **open**

- The `symlink_metadata` preflight and `File::open` are not atomic. A malicious writer can swap a path between them; links to special files and blocking opens remain a risk. We do **not** claim race-free no-follow semantics or a sandbox. Atomic no-follow opens require an OS-specific design and tests.
- Descriptor reuse avoids path replacement **during reading** but the file contents themselves can change concurrently. Matching size and modified timestamp is **not a coherent snapshot guarantee** (timestamp granularity, same-length writes). A robust snapshot requires a proven copy/lock/snapshot strategy and documented OS semantics.
- The 512 MiB limit bounds raw input bytes read, **not** peak RSS of parsing/allocations, CPU time, output volume or IO latency. `Read::take` does not cap wall-clock time.
- `catch_unwind` is not a security boundary, and adding this reader does not authorize arbitrary hostile input. Process isolation and OS budgets remain P1.5 work.
- Symbolic links are deliberately rejected for this alpha release; this may change only through a deliberate compatibility/security decision.

## Verified CI evidence

[GitHub Actions 39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604) passed on both Ubuntu and Windows, including the new Rust input reader tests, existing PE fixtures, F001 regression, CLI smoke tests and Windows PE oracle. This confirms only the specified tests on those systems, not immunity to concurrent adversarial file replacement.

## Future gates

Measure resource use on complex legally redistributable PE files, design atomic no-follow opens / worker isolation for Linux and Windows, test concurrent same-size overwrites, and enforce meaningful RAM/CPU/output budgets before promoting to a hostile-file workflow.

Related [threat model](THREAT_MODEL_ALPHA.md), [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) and [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).


## Unix final-component no-follow candidate (pending new PR CI)

The CLI now uses \`OpenOptionsExt::custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)\` on Unix to open the input once, instead of an unguarded \`File::open\` after a pre-open path check. \`O_NOFOLLOW\` prevents a swap to a **final-component symlink** from being followed at open time; \`O_NONBLOCK\` prevents a swapped FIFO from hanging in \`open\`. The existing descriptor-based regular-file check, 512 MiB byte cap, and modification checks remain. A Unix-only direct-open unit test models a deterministic path replacement with a symlink; a Linux test constructs a FIFO with \`mkfifo\` and checks nonblocking open and refusal by the higher-level input policy.

Scope and non-goals:
- Only the final path component gets atomic no-follow protection on Unix. Ancestor components can still be symlinks or be replaced; there is no directory-descriptor walk, \`openat2\` resolution policy or general path sandbox.
- \`O_NONBLOCK\` helps for FIFO opening, **not** a general I/O timeout or protection against device reads; non-regular descriptors are still rejected after open.
- On Windows, the previous \`File::open\` plus preflight policy remains unchanged. Reparse-point atomicity requires a separate platform-specific implementation and tests.
- A regular file can still be rewritten concurrently without a detectable size/mtime difference. No coherent snapshot, forced CPU/RSS bound or hostile-input authorization is implied.
- \`libc = 0.2.191\` is added as an exact direct dependency on Unix only; it was already present in the tracked lockfile, and \`Cargo.lock\` adds it to the CLI dependency list.

**Validation is pending** on PR Windows/Linux CI and should not be claimed until the final head and post-merge checks pass.
