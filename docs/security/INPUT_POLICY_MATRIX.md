# REL — Input acquisition policy matrix (2026-10-19)

These policies apply to **controlled alpha inputs**. None is a general
hostile-file sandbox or an atomic filesystem snapshot. Verify current
GitHub branches and CI before treating an experimental tool as shipped.

| Property | rel-inspect (main) | rel-observe (this candidate) | rel-diff (draft PR #62) |
| --- | --- | --- | --- |
| Input bytes | PE, 512 MiB cap | PE-like, 2 MiB cap | Two PE JSON manifests, 16 MiB each |
| Leaf symlinks | Unix no-follow; Windows reparse guard | Unix no-follow; Windows reparse guard | Unix no-follow; Windows reparse guard |
| Unix swapped FIFO leaf | Nonblocking open + regular-file check | Nonblocking open + regular-file check | Nonblocking open + regular-file check |
| Unix symlink ancestors | Descriptor-relative no-follow walk | Not blocked | Not blocked |
| Windows reparse ancestors | Two path observations, not atomic | Not blocked | Not blocked |
| Windows writer sharing | Read-only sharing | Read-only sharing | Read-only sharing |
| Preflight identity on Unix | Opened device/inode checked | Opened device/inode checked | No preflight identity check |
| Mutable file contents | Same-handle second read + metadata | Same-handle second read + metadata | Bounded reads, no atomic pair snapshot |
| Output | 16 MiB preflight, no-clobber file policy | Buffered stdout JSON; no dedicated byte cap | 16 MiB buffered stdout report cap |
| Safe for arbitrary hostile input | No | No | No |

## What the targeted EX-01 change establishes

- Deterministic Unix and Windows tests simulate leaf-symlink insertion
  after an ordinary-file preflight, before acquisition.
- A Unix test substitutes a regular file with another file of identical
  length and verifies rejection through device/inode identity.
- A Windows test checks that an ordinary conflicting writer is rejected
  while the reader acquires the handle, then succeeds after writer close.
- An unchanged regular-file regression verifies the positive path.

**Not established:** atomic ancestor inspection, no-follow of every
directory in EX-01/EX-02, protection from in-place writes or restored
namespace races, coherent A/B snapshots, kernel process CPU/RSS budgets,
or security against adversarial filesystems.

Source: [threat model](THREAT_MODEL_ALPHA.md),
[bounded input policy](P15A_BOUNDED_INPUT.md), and
[EX-02 draft PR #62](https://github.com/ELITEAYOTO/REL/pull/62).
