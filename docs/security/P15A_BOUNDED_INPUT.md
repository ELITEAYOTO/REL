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


## Unix final-component no-follow (PR CI verified, P1.5-A still open)

The CLI now uses `OpenOptionsExt::custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)` on Unix to open the input once, instead of an unguarded `File::open` after a pre-open path check. `O_NOFOLLOW` prevents a swap to a **final-component symlink** from being followed at open time; `O_NONBLOCK` prevents a swapped FIFO from hanging in `open`. The existing descriptor-based regular-file check, 512 MiB byte cap, and modification checks remain. A Unix-only direct-open unit test models a deterministic path replacement with a symlink; a Linux test constructs a FIFO with `mkfifo` and checks nonblocking open and refusal by the higher-level input policy.

Scope and non-goals:
- Only the final path component gets atomic no-follow protection on Unix. Ancestor components can still be symlinks or be replaced; there is no directory-descriptor walk, `openat2` resolution policy or general path sandbox.
- `O_NONBLOCK` helps for FIFO opening, **not** a general I/O timeout or protection against device reads; non-regular descriptors are still rejected after open.
- On Windows, the previous `File::open` plus preflight policy remains unchanged. Reparse-point atomicity requires a separate platform-specific implementation and tests.
- A regular file can still be rewritten concurrently without a detectable size/mtime difference. No coherent snapshot, forced CPU/RSS bound or hostile-input authorization is implied.
- `libc = "=0.2.191"` is added as an exact direct dependency on Unix only; it was already present in the tracked lockfile, and `Cargo.lock` adds it to the CLI dependency list.

**Validated for controlled cases:** [PR #24 Windows/Linux CI #39109205165](https://github.com/ELITEAYOTO/REL/actions/runs/39109205165) succeeded on the implementation and documentation candidate. Post-merge `main` run must be checked separately. These checks do not demonstrate protection against hostile path trees, Windows reparse-point races, concurrent content changes, or arbitrary device I/O.

## Windows final-component reparse-point guard (PR CI verified)

The Windows CLI path now calls `OpenOptionsExt::custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)` (`0x00200000`). The final path component is opened as a reparse point rather than followed. After successful opening, `File::metadata()` is queried on the **opened handle**, and the descriptor is refused if its `MetadataExt::file_attributes()` contains `FILE_ATTRIBUTE_REPARSE_POINT` (`0x00000400`). This happens before handing the handle to the existing regular-file and 512 MiB bounded reader.

References: [Microsoft CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [Windows reparse-point operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations).

Proposed regression cases: Windows regular file opens unchanged; deterministic path swap to a final-component symbolic link is rejected if symlink creation is permitted on the CI runner; an ordinary directory substituted into the path is not accepted. Windows symlink creation may require Developer Mode or privilege. The test may log `SKIP` on local machines lacking permission, but **fails on GitHub Actions Windows** if it cannot create the link. A Windows-only CI step reruns the specific regression with `--nocapture` so that a real `PASS` line is visible; no successful CI can silently skip this critical gate. The existing compiled Windows CLI smoke/pefile oracle must also pass.

**Scope:** only the final path component, not ancestor symlinks/junctions, network filesystem/redirector behavior, changes to reparse tags after open, path-hardlink aliases or concurrent file writes. Any final reparse point is deliberately unsupported in this controlled-input alpha policy, including cloud-placeholder files, which can reduce compatibility. This is not arbitrary-hostile-filesystem safety, a snapshot, a sandbox or a CPU/RAM limit. No additional dependency is needed; the public manifest v1.0.0 is unchanged. The scoped implementation and tests passed [CI Windows/Linux #39146000935](https://github.com/ELITEAYOTO/REL/actions/runs/39146000935) on both platforms. The dedicated Windows test used `--nocapture` and printed `PASS Windows final-component symlink was created and refused` (not a skip). Confirm post-merge `main` CI separately; this remains a narrow alpha mitigation, not broad path security.

## Windows read-sharing guard (PR CI verified; P1.5-A still incomplete)

The Windows input descriptor additionally requests `OpenOptionsExt::share_mode(FILE_SHARE_READ)` (`0x1`), replacing Rust's default Windows read/write/delete sharing. This is combined with the already-verified leaf reparse-point guard and the existing descriptor-based regular-file checks. While REL owns this read handle, normal Win32 opens requesting write or delete access should fail with a sharing conflict; REL permits other read-only opens. An existing incompatible writer should prevent REL from opening the input. The restriction ends as soon as REL closes the descriptor, after the bounded read.

- Windows-only unit regressions check coexistence of readers, refusal of a newly opened writer, successful writer after the reader is dropped, and refusal of REL input opening when a writer is already active.
- This is deliberately conservative and can reject live, writable input files that the prior CLI could read. The alpha workflow favors controlled files; do not silently claim that no compatibility is affected.
- Win32 file sharing is **not a frozen snapshot or sandbox**: a malicious process with an existing memory mapping/privileged handle, filesystem driver, raw disk I/O, remote redirector or administrator privileges can still change data; platform filesystems can vary. The input reader's original 512 MiB byte cap, size/mtime detection and hashing still apply. Unix behavior is unchanged.
- Microsoft documents sharing conflicts in [Creating and Opening Files](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files); Rust's stable `OpenOptionsExt::share_mode` API controls `dwShareMode` without new dependencies.

**Verified in narrow scope:** [Windows/Linux CI #39146872882](https://github.com/ELITEAYOTO/REL/actions/runs/39146872882) passed format, lint, locked tests, release, CLI smoke, Windows native PE oracle and resource profiling. Windows logs explicitly confirm `windows_reader_allows_other_readers_but_blocks_new_writer` and `windows_reader_refuses_preexisting_writer` both passed. Confirm post-merge main CI separately. The JSON manifest v1.0.0 is unchanged; this does not enforce parser CPU/RSS budgets.
