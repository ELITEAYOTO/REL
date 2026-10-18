# P1.5-A — Atomic publication of complete CLI report files

**Status: candidate implementation pending Windows/Linux CI.** This does not make PE parsing or filesystem path resolution secure.

## Problem and boundary

The 16 MiB JSON writer constructs a complete bounded buffer before writing, but direct `create_new` followed by `write_all` could leave a partial destination after an I/O failure. This increment changes only file-output publication. stdout still writes directly and may be partial on pipe errors. The v1.0.0 manifest and its byte representation are unchanged.

## Method

1. Serialize and bound the entire JSON in memory before touching the target.
2. Create a unique same-directory temporary file using `create_new`; on Unix request mode 0600.
3. Write the complete report and call `File::sync_all` before making the destination visible.
4. Use `fs::hard_link` to publish an additional filename. Hard-link creation fails if a destination already exists, including a symlink; unlike rename this will not silently overwrite.
5. Remove the temporary name. A best-effort RAII cleanup runs on error.

A failed write or sync before linking does not create a partial **destination**. The temporary file may remain if deletion fails or the process terminates unexpectedly. If cleanup after linking fails, the destination is already complete and the command reports an error, leaving an extra temporary hard link.

## Compatibility and limitations

- Requires the filesystem to support hard links and both paths to be in the same filesystem. Unsupported environments fail closed, rather than falling back to non-atomic copying.
- This is a **single-file namespace publication** technique, not atomic path resolution. The parent directory could be concurrently replaced or modified; special Windows path and reparse-point edge cases are not proven safe.
- `sync_all` on the temporary file does not itself establish **crash durability** of directory entries. Directory fsync and cross-filesystem reliability need OS-specific validation. Power failure may lose a newly published report.
- Temporary filenames can expose metadata; Unix permissions are restricted where applicable, but Windows ACLs inherit directory policy. Only controlled working directories are within current alpha scope.
- The caller's file name might be the input binary via unusual hard-link aliases. Existing `canonicalize` checks do not reliably detect separate hard links. This remains an open correctness/safety gap needing file-identity validation; use controlled inputs.
- No runtime CPU/RSS/parser limits, no process sandbox, and no arbitrary malicious filesystem support are provided.

## Evidence required

Rust tests: exact bytes, existing-file rejection, existing-directory rejection, Unix symlink destination refusal, temporary cleanup; CLI smoke collision tests; `cargo fmt`, Clippy, workspace tests, Windows/Linux release + smoke. Record actual CI URL before declaring verified.
