# EX-01 — Controlled evidence-verifier input policy

**Scope:** `scripts/verify_observation_evidence.py` on the proposed
[issue #76](https://github.com/ELITEAYOTO/REL/issues/76) fix branch.
This is a controlled-input verifier, **not** a hostile-filesystem sandbox.

- Source PE maximum: **2 MiB** read, plus one byte to detect overflow.
- EX-01 JSON evidence report maximum: **2 MiB**, also read through a
  bounded descriptor. The verifier rejects duplicate object members at
  any nesting level and the non-standard `NaN`/`Infinity` constants.
- Leaf inputs must be ordinary files: directories, FIFO nodes, symlinks
  and other special files are refused by the initial `lstat`.
- Under Unix, the final open uses `O_NONBLOCK | O_NOFOLLOW` to refuse
  a swapped-in FIFO or leaf symlink before it can hang or be followed.
  The opened handle is checked for file type and identity.
- On Windows the reader rechecks the opened file identity, but Python's
  normal file open does **not** provide the Win32 final-reparse-point
  guarantee of `rel-inspect`. A race to an alias of the **same file**
  may evade identity detection.
- A second bounded byte pass on the same handle and size/mtime checks
  reject many observable in-place mutations. No atomic file snapshot,
  parent-directory confinement, filesystem-locking or hard CPU/RSS
  budget is established. The report and source are **not** read as
  one atomic pair. SHA hashes demonstrate byte equality, not authorship.
- Inputs are never executed. The existing EX-01 report schema, run-ID
  derivation, producer identity, source-offset oracle, CLI arguments and
  successful report semantics remain unchanged.

Regression coverage includes exact-boundary reads, oversize source and
report, nested/top-level duplicate members, non-JSON constants,
preflight-to-open regular-file and leaf-symlink substitutions,
leaf symlinks on Windows/Ubuntu, and timeout-guarded Unix FIFO cases
both before and after path preflight.

**Acceptance:** latest branch HEAD must pass Windows/Ubuntu CI and the
positive EX-01 evidence verifier smoke on real controlled fixtures;
future platform-specific path-race hardening is a separate task.
