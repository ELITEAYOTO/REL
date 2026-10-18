# P1.5-A — Controlled PE measurement corpus and provenance

**Status:** MSVC corpus increment integrated with successful post-merge [main CI #39155754738](https://github.com/ELITEAYOTO/REL/actions/runs/39155754738). Additional Clang-cl frontend extension is a PR candidate pending CI. The earlier MSVC PE oracle, case inventory and profilers passed [Windows/Linux CI #39155346166](https://github.com/ELITEAYOTO/REL/actions/runs/39155346166) and [CI #39155351313](https://github.com/ELITEAYOTO/REL/actions/runs/39155351313) on Windows/Linux; post-merge `main` CI must still be checked. Earlier inventory and measurement gates were verified by [Windows/Linux CI #39153900290](https://github.com/ELITEAYOTO/REL/actions/runs/39153900290) and [CI #39153927673](https://github.com/ELITEAYOTO/REL/actions/runs/39153927673); post-merge `main` CI must still be verified. This is a controlled measurement corpus, not a licensed or representative public binary collection. No new third-party executables are committed.

## Sources and rights

| Case | Generation / validation | Redistribution |
| --- | --- | --- |
| Tracked PE32 `fixtures/pe32-basic.exe` | Existing synthetic fixture in REL, SHA-256 and size checked against `fixtures/expected.json` | Not established; REL has no adopted source LICENSE |
| Tracked PE64 `fixtures/pe64-basic.exe` | Existing synthetic fixture, independently hash-verified | Not established |
| PE32 and PE64 1 MiB / 4 MiB overlays | Exact verified seed bytes plus zero-filled suffix, generated locally on each run | Derived from unlicensed-status fixtures |
| Native Windows release REL EXE | Built from current repository in the current Windows CI job, not newly committed to the corpus | Third-party dependency rights and redistribution not assessed |
| MSVC x64 C probe | Build `fixtures/probes/msvc_probe.c` during Windows CI using runner-installed MSVC and SDK, then analyze the compiled PE; the EXE is **not** checked into git or executed | The checked-in source is not assigned a redistribution license and MSVC/SDK-built binary redistribution has **not** been cleared |
| Clang-cl x64 C probe (candidate) | Build **the same C source** with LLVM Clang-cl against hosted Windows SDK/toolchain, then independently verify static imports/exports. Record the observed `clang-cl --version` output; compiled EXE is ephemeral | Rights are **not established**; Clang/LLVM compiler version is observed, not pinned |

Public source visibility or the presence of an executable in GitHub **does not** constitute a grant to redistribute it. These scripts make no licensing assertion about authored fixtures or compiler output. See [license decision #16](https://github.com/ELITEAYOTO/REL/issues/16). No external PE files are downloaded and no inspected PE is launched.

## Reproducible cases

`scripts/corpus_cases.py` supplies one shared, hash-checked case inventory to both `scripts/benchmark_cli.py` and `scripts/profile_resources.py`. It refuses reference fixture SHA-256/size drift and non-synthetic metadata. The output includes six controlled cases on each OS: two original 2 KiB fixtures and four generated overlays (1 MiB and 4 MiB for each architecture). On Windows the **locally compiled REL release EXE** adds a seventh case, the optional **MSVC x64 locally built C probe** adds an eighth, and the opt-in **Clang-cl x64 build of the same C source** adds a ninth case when both probes are supplied. The source hash is recorded in the case metadata, while the output PE hash is recorded in each benchmark/resource observation.

Each JSON scenario includes a stable `case_id`, `kind`, `source_fixture`, `source_sha256`, `provenance` and `redistribution_status: not-established`. The profilers also compare the binary manifest's SHA-256 and size to each inspected case. The tool never executes the sample. Generated overlays exist only in a temporary directory, and the profiler/benchmark output files remain separately uploaded CI artifacts.

Run the deterministic unit gate on either OS before benchmarking:

```sh
python scripts/test_corpus_cases.py
```

Existing CI measures each case with one warmup and five measured runs, independently, for both resource profiling and wall-clock benchmarking. Retrieve actual GitHub Actions per-OS artifacts for any values; do not invent performance numbers or treat hosted runner timings as stable baselines.

## Interpretation

These cases increase coverage of **two PE architecture families and file sizes**, plus one additional MSVC-generated PE layout on Windows. Padding stresses file reading and hashing, not import, section, relocation or resource-table complexity. The Windows self-compiled EXE is one genuine compiler output, not a diverse cross-compiler corpus. The declared provenance describes source/derivation, **not legal permission**. A successful run does not imply parser correctness on hostile PE samples, representative performance, enforceable memory peaks or safe redistribution.

Next: select third-party or self-produced samples only after documenting exact producer, version, content hashes, authoritative license terms/permissions, redistribution decision, and expected nontrivial structures. Keep [issue #9](https://github.com/ELITEAYOTO/REL/issues/9) and the [licensing issue #16](https://github.com/ELITEAYOTO/REL/issues/16) open.

## Increment: compiler-produced PE (CI candidate)

The Windows CI uses `scripts/build_windows_msvc_probe.cmd`, which locates the installed MSVC toolchain using `vswhere`, builds the tracked C source, and stores the generated executable under ignored `compiler-probes/`. **No downloaded third-party binary or compiler output is committed.** The build only compiles; the executable is never launched.

A pinned independent `pefile==2024.8.26` oracle (`scripts/check_windows_msvc_probe.py`) checks x64 PE32+, section layout, at least one import and export, and that REL's parsed manifest preserves the source binary's size, SHA-256 and the exported symbol. The profiler and benchmark include the same case ID `msvc-x64-local-build` when passed `--windows-msvc-probe compiler-probes/rel-msvc-probe.exe`.

These checks are against **one source built by MSVC with the hosted Windows environment**; they do not prove compatibility across multiple MSVC versions, compiler families, DLL layouts, signers or unusual resource tables. Runner images/tools can change; observations identify the commit and OS but are not reproducible byte-for-byte compiler artifacts unless the full toolchain and environment are pinned. The `source_sha256` identifies tracked C source, not the compiled EXE (the latter is stored separately as the scenario `sha256`). No rights are granted by tracking the C source, and redistribution remains `not-established` pending issue #16.

## Clang-cl extension (PR candidate, CI pending)

The existing Windows builder now requires Clang-cl in addition to MSVC and records `clang-cl --version` as `compiler-probes/clang-cl-version.txt`. The Clang-cl executable remains ignored and is never launched. The same pinned independent `pefile` oracle compares PE32+ x64 headers, sections, the `GetTickCount64` import, the `rel_probe_transform` export and the REL manifest's size/hash on both compiler-built files.

The new case `clang-cl-x64-local-build` includes `kind=ci-built-clang-cl-x64-pe`, `source_sha256` of the checked-in C file and an observed `toolchain_version`. The exact executable SHA-256 belongs to each benchmark/resource observation. The scenario is blocked if the generated file or Clang version record is missing. This is a compiler-*frontend* diversity experiment: both builds can use Microsoft's linker, CRT and Windows SDK, so no independent linker diversity is claimed. The hosted image versions are not locked and neither compiler build is approved for binary redistribution; keep issues #9 and #16 open. Do not infer performance gains from cross-run hosted CI timings.
