# P1.5 — Reproducible malformed-PE rejection/resource observations

**Scope:** issue [#9](https://github.com/ELITEAYOTO/REL/issues/9), controlled alpha
inputs only; no arbitrary-hostile-file sandbox and no new redistributable corpus
claims. The normal successful-input benchmarking workflow is unchanged.

## Why this separate campaign exists

Earlier `profile_resources.py` and `benchmark_cli.py` measure **valid**
PE inputs. Rust preflight tests verify many invalid header limits, but they
did not capture a separate cross-platform series of **CLI failure-path wall
time, sampled RSS and sampled CPU**, with exact mutated input hashes.
This suite exercises that missing black-box evidence without executing any
inspected binary and without adding permanent malformed EXE files.

`scripts/profile_malformed_resources.py` builds exactly **13 temporary cases**:

- For both the hash/size-verified PE32 and PE32+ fixtures: NT header offset
  beyond 1 MiB, 97 declared sections, section raw offset `0xffffffff`,
  declared import-directory size 1 MiB + 1, and declared export-directory
  size 1 MiB + 1 (10 cases)
- PE64 plus an **8 MiB zero-filled overlay** and 97-section declaration;
  this stresses controlled acquisition beyond an individual read chunk
- The unchanged F001 original (1,104 bytes) and reduced witness (1,048
  bytes), each hash-verified against archived incident evidence

Each case must produce a **nonzero CLI exit**, expected diagnostic from
the scoped parser/preflight and **zero stdout bytes** (no partial JSON).
A failed or hanging case makes the CI step fail; its diagnostic is surfaced
for triage. Input SHA-256, reference seed provenance, mutation, file size,
runner/commit/analyzer hash, per-run observed elapsed time and possible
sampled RSS/CPU are saved to a versioned JSON artifact. CI runs 3 samples
per case on Ubuntu and Windows. Pure generator/provenance regressions run
before building the release analyzer.

## Operational interpretation

A 20-second **parent-enforced per-child wall timeout** and 64 KiB maximum
spool lengths protect this *controlled test runner*. The process may exit
before the first 2 ms poll; in that case RSS/CPU are `null`, never zero.
Sampling cannot establish true instantaneous peak RSS or a kernel-enforced
memory ceiling. This script does **not** set `RLIMIT_AS`, `RLIMIT_CPU`
or a Windows Job Object. Those opt-in native controls and their separate
tests remain in `scripts/run_bounded_inspection.py`.

Run locally after building `rel-inspect`:

```sh
python scripts/test_malformed_resource_cases.py
python scripts/profile_malformed_resources.py --binary target/release/rel-inspect --samples 3 --output rel-malformed-pe-resources.json
```

Use `target/release/rel-inspect.exe` on Windows. The output path must not
already exist. The immutable original F001, reduced F001 and golden
fixtures are never overwritten. No PE is loaded or executed.

**Remaining issue #9 acceptance:** independent legally cleared PE/DLL
fixtures, toolchain diversity beyond controlled Windows compiler probes,
imports/exports/resources with adversarial but meaningful layouts,
large/sparse inputs under real enforced isolation and representative
resource baselines. CI success is **not** a universal parser memory/time
limit or proof that hostile files are safe.
