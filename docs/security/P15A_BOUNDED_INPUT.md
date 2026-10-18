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

## Bounded second-pass byte verification (PR CI verified)

The existing bounded reader retains the first copy of up to 512 MiB in memory and **rewinds the same opened regular-file descriptor** to read that exact byte range again in 64 KiB scratch chunks. Any mismatch or premature EOF is rejected as `InvalidData` **before the PE parser receives input**. The reader then repeats the descriptor-based size and modification-time comparison. This requires no second full-size allocation, does not open a new path, and preserves the existing Unix final-component `O_NOFOLLOW` / non-blocking and Windows reparse/read-sharing semantics.

Deterministic unit tests exercise (1) a second pass after a same-size content replacement, without assuming mtime precision, (2) matching input across several 64 KiB chunks, (3) a truncated second pass, and (4) empty regular files. Existing growth/truncation, symlink, FIFO and native Windows file-sharing tests continue to run. A normal successful binary-manifest v1.0.0 is byte-for-byte unchanged.

**Security and compatibility limits:** This is a *best-effort consistency check*, **not an atomic snapshot**. A concurrent writer might mutate bytes between either read, restore them before comparison, or modify previously verified regions. Unix writers are not blocked; Windows read-sharing is narrower but does not stop existing privileged or memory-mapped writers. Files may also change immediately after the descriptor closes. A second full read increases input I/O and time (up to another 512 MiB, excluding OS cache effects) and can amplify costs on slow/network filesystems. No hard wall-time/CPU/RSS guarantee, ancestor-path protection, hostile-input sandbox, or arbitrary-filesystem guarantee follows. This increment intentionally keeps the entire PE handling pipeline **static-only**; it does not execute the PE.

Four focused Rust regressions plus formatting, linting, locked workspace tests, native Windows PE oracle, CLI smoke and performance-report quality suites passed [Windows/Linux CI #39163640989](https://github.com/ELITEAYOTO/REL/actions/runs/39163640989) and [CI #39163645354](https://github.com/ELITEAYOTO/REL/actions/runs/39163645354) on both OSes. The first CI attempts failed solely on `cargo fmt` formatting for a new test; no functional check was weakened. Verify final PR-head and post-merge main CI separately. Keep [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) open.

## Unix regular-file replacement identity check (PR #39 merged, CI verified)

The input reader compares the Unix `(st_dev, st_ino)` pair from the initial path `symlink_metadata` to the metadata of the *opened descriptor* before reading. This rejects an observable replacement of a regular file with another inode between the preflight and the guarded `open`, even when size and modification timestamp match. A regression constructs a same-length, same-mtime replacement and checks that this identity check abstains. The check does not introduce another path lookup after opening, does not change the JSON v1.0.0 contract and leaves Windows behavior unchanged.

**Limits:** this is not atomic path resolution or a directory-tree sandbox. Ancestor directory components may still be redirected to a different object with the same underlying file identity (e.g. hard links), and a malicious writer may mutate the *same inode* concurrently. Identity can be changed by privileged or unusual filesystem behavior, and the read still is not an atomic snapshot. The Windows leaf reparse/read-sharing policy remains as documented above; this candidate does not claim Windows regular-file replacement identity verification. PR #39 merged as [`a2bb013`](https://github.com/ELITEAYOTO/REL/commit/a2bb013a9d1c20d7c6de50853f93ce6f3b61d907); final Windows/Linux CI [#39165266295](https://github.com/ELITEAYOTO/REL/actions/runs/39165266295) and post-merge [`main` #39165446361](https://github.com/ELITEAYOTO/REL/actions/runs/39165446361) succeeded.

## Unix descriptor-relative ancestor no-follow (PR #40 merged, CI verified)

Rather than reopening the entire caller-provided input path after a non-atomic preflight, Unix input acquisition now traverses individual path components using `openat` relative to *live directory descriptors*. Every ancestor uses `O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`; the leaf uses `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`. A symbolic link in an ancestor or the final component is not followed at the time that component is opened. The existing regular-file type check, pre-open Unix `(dev, ino)` comparison, bounded first read and 64 KiB second-pass comparison remain unchanged. Windows retains its separate leaf reparse-point and restrictive sharing policy.

Regressions cover ordinary nested directories, an existing ancestor symlink and a deterministic ancestor replacement with a symlink after the path preflight; they require no racing thread. This **tightens the controlled-input policy**: an input reached through any ancestor symlink now fails on Unix, and opening ancestors as read-only directories may also deny otherwise searchable execute-only directories. This is an explicit compatibility tradeoff to avoid following mutable ancestor symlinks in the alpha mode.

**Residual risks:** this is not `openat2(RESOLVE_BENEATH)`, `chroot`, an authorized-root boundary, a filesystem snapshot or a general sandbox. Parent `..` components are intentionally accepted, hard links may alias the same file, directory renames/mount changes and writers modifying an already-open inode still need a broader threat model. Non-POSIX/network filesystem behavior and Windows ancestors remain outside these guarantees. The file must never be executed. PR #40 merged as [`86cba02`](https://github.com/ELITEAYOTO/REL/commit/86cba02d64ffa0ace6290615fc7135d46875df12); final Windows/Linux CI [#39165747222](https://github.com/ELITEAYOTO/REL/actions/runs/39165747222) and post-merge [`main` #39165928503](https://github.com/ELITEAYOTO/REL/actions/runs/39165928503) succeeded. P1.5-A remains open.

## Windows ancestor reparse-point detection (candidate, CI pending)

The Windows alpha CLI now checks each **parent path component** with `symlink_metadata` for `FILE_ATTRIBUTE_REPARSE_POINT` and directory type, once *before* the leaf preflight and again *immediately after* the final file descriptor is opened. Ordinary paths are permitted. Observable reparse-point parents (directory junctions, directory symlinks and other tagged directories) are rejected rather than followed. The existing leaf `FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_SHARE_READ`, bounded reads and manifest contract remain untouched. Windows CI must really create and reject a `mklink /J` junction; a separate regression models a replacement after initial leaf stat.

**Important limitation:** each parent query is a separate path lookup. Unlike Unix's descriptor-relative `openat` walk, this is **not atomic or race-free** and cannot promise that the handle was opened through the same ancestry that was checked. A malicious actor can replace or restore a parent between observations, swap regular directories, or exploit hard-link aliases, unusual redirectors, mount/device paths or privileged behavior. Rejecting ancestor reparse points changes compatibility with junction-backed or redirected directories. No general Win32 sandbox, trusted-root confinement, coherent snapshot or blanket hostile-binary guarantee is provided. This mitigation can only be reported as detection of *observable* ancestor reparse points, not prevention of all traversal races. Record Windows/Linux final CI before declaring it validated. See [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).
