# P1.5-A — Controlled PE measurement corpus and provenance

**Status:** controlled case inventory and measurement gates verified by [Windows/Linux CI #39153900290](https://github.com/ELITEAYOTO/REL/actions/runs/39153900290) and [CI #39153927673](https://github.com/ELITEAYOTO/REL/actions/runs/39153927673); post-merge `main` CI must still be verified. This is a controlled measurement corpus, not a licensed or representative public binary collection. No new third-party executables are committed.

## Sources and rights

| Case | Generation / validation | Redistribution |
| --- | --- | --- |
| Tracked PE32 `fixtures/pe32-basic.exe` | Existing synthetic fixture in REL, SHA-256 and size checked against `fixtures/expected.json` | Not established; REL has no adopted source LICENSE |
| Tracked PE64 `fixtures/pe64-basic.exe` | Existing synthetic fixture, independently hash-verified | Not established |
| PE32 and PE64 1 MiB / 4 MiB overlays | Exact verified seed bytes plus zero-filled suffix, generated locally on each run | Derived from unlicensed-status fixtures |
| Native Windows release REL EXE | Built from current repository in the current Windows CI job, not newly committed to the corpus | Third-party dependency rights and redistribution not assessed |

Public source visibility or the presence of an executable in GitHub **does not** constitute a grant to redistribute it. These scripts make no licensing assertion about authored fixtures or compiler output. See [license decision #16](https://github.com/ELITEAYOTO/REL/issues/16). No external PE files are downloaded and no inspected PE is launched.

## Reproducible cases

`scripts/corpus_cases.py` supplies one shared, hash-checked case inventory to both `scripts/benchmark_cli.py` and `scripts/profile_resources.py`. It refuses reference fixture SHA-256/size drift and non-synthetic metadata. The output includes six controlled cases on each OS: two original 2 KiB fixtures and four generated overlays (1 MiB and 4 MiB for each architecture). On Windows the **locally compiled REL release EXE** adds a seventh case.

Each JSON scenario includes a stable `case_id`, `kind`, `source_fixture`, `source_sha256`, `provenance` and `redistribution_status: not-established`. The profilers also compare the binary manifest's SHA-256 and size to each inspected case. The tool never executes the sample. Generated overlays exist only in a temporary directory, and the profiler/benchmark output files remain separately uploaded CI artifacts.

Run the deterministic unit gate on either OS before benchmarking:

```sh
python scripts/test_corpus_cases.py
```

Existing CI measures each case with one warmup and five measured runs, independently, for both resource profiling and wall-clock benchmarking. Retrieve actual GitHub Actions per-OS artifacts for any values; do not invent performance numbers or treat hosted runner timings as stable baselines.

## Interpretation

These cases increase coverage of **two PE architecture families and file sizes**. Padding stresses file reading and hashing, not import, section, relocation or resource-table complexity. The Windows self-compiled EXE is one genuine compiler output, not a diverse cross-compiler corpus. The declared provenance describes source/derivation, **not legal permission**. A successful run does not imply parser correctness on hostile PE samples, representative performance, enforceable memory peaks or safe redistribution.

Next: select third-party or self-produced samples only after documenting exact producer, version, content hashes, authoritative license terms/permissions, redistribution decision, and expected nontrivial structures. Keep [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) and the [licensing issue #16](https://github.com/ELITEAYOTO/REL/issues/16) open.
