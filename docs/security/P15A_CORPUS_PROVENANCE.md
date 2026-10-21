# P1.5-A — Controlled PE measurement corpus and provenance

**Status (2026-10-20):** The controlled corpus and Windows MSVC/Clang-cl static oracles, resource/relocation probes and x86 PE32 DLL checks are integrated in CI; exact [main CI #39354165057](https://github.com/ELITEAYOTO/REL/actions/runs/39354165057) succeeded on Windows and Ubuntu. Prior scoped historical evidence includes [#39153900290](https://github.com/ELITEAYOTO/REL/actions/runs/39153900290), [#39155346166](https://github.com/ELITEAYOTO/REL/actions/runs/39155346166), [#39156574382](https://github.com/ELITEAYOTO/REL/actions/runs/39156574382) and [#39157915184](https://github.com/ELITEAYOTO/REL/actions/runs/39157915184). This is **not** a licensed or representative external PE corpus; compiled binaries are not committed and their redistribution rights are unverified.

## GNU MinGW-w64 x64 PE test (integrated; scoped CI verified)

A separate **Ubuntu-only CI trial** cross-compiles the existing
`fixtures/probes/msvc_probe.c` source into a Windows PE32+ EXE with
`x86_64-w64-mingw32-gcc` and the GNU MinGW-w64 linker. GNU MinGW-w64
offers a distinct compiler and linker lineage from the MSVC/Clang-cl
Windows-hosted probes; it is **one new controlled build**, not a licensed
representative collection. The existing script
`scripts/check_windows_msvc_probe.py` is reused to compare REL against
independent pinned `pefile==2024.8.26`, now including exact section
name, raw offset, raw size and virtual address for the entire section table,
using a bounded independent resolution of COFF long-section names
(`/4`, `/19`, etc.). The oracle also verifies the observed GetTickCount64
import, named export, PE machine/magic, raw file size and SHA-256.

Separate unit regressions reject malformed COFF string-table lengths, offsets
and missing terminators on Ubuntu and Windows; they do not establish safety
for arbitrary hostile COFF files. CI archives only a JSON evidence record,
including the exact source and generated binary hashes, section table,
compiler/linker version lines, and triggering revision; it does **not**
upload the generated EXE. The Windows binary is **never run or loaded**.
The existing C source and generated binary have **unestablished
redistribution rights** while issue #16 remains unresolved. The
`ubuntu-latest` image and MinGW packages resolved through signed Ubuntu
APT repositories are **not exact-version pinned**: captured compiler/linker
versions identify the observed toolchain, not a reproducible byte-for-byte
build guarantee. Both upstream GNU and REL are exercised only in an
authorized controlled static-input experiment.

**Validation status:** exact final-head [PR CI #39371723078](https://github.com/ELITEAYOTO/REL/actions/runs/39371723078) and [branch CI #39371719521](https://github.com/ELITEAYOTO/REL/actions/runs/39371719521) passed Windows/Ubuntu; the independent [new-main CI #39371988276](https://github.com/ELITEAYOTO/REL/actions/runs/39371988276) passed on squash [a9f8160](https://github.com/ELITEAYOTO/REL/commit/a9f816009dd00388118771c6a1b441be4582e1e1). Ubuntu uploaded JSON artifact `rel-mingw-x64-oracle-ubuntu` (ID 12241996223), not the binary. Keep #9 open for broader legal sources, redistribution clearance and true CPU/RSS budgets.

## Paired profiling of GNU MinGW-w64 PE (integrated; scoped CI verified)

Ubuntu CI extends the **existing** `prepare_cases` inventory for CLI timing
and sampled child RSS/CPU profiling. Case seven is the exact same GNU
MinGW-w64 PE32+ image already checked by independent `pefile`; it is
**never loaded or executed**. Metadata records GCC/linker versions, the
tracked C source SHA-256 and actual PE SHA-256. Same-job paired evidence
requires matching case inventory, provenance and byte hashes; Ubuntu now
expects seven cases and Windows remains eleven. Missing short-process
RSS/CPU samples remain null rather than zero.

This extends **measurements**, not an enforced RSS/CPU ceiling, licensed
corpus or stable cross-run benchmark. Ubuntu runner and APT versions are
not immutable. The exact final-head [PR #109 CI #39373542657](https://github.com/ELITEAYOTO/REL/actions/runs/39373542657) and independent [new-main CI #39373817606](https://github.com/ELITEAYOTO/REL/actions/runs/39373817606) succeeded. The postmerge Ubuntu artifact `rel-measurement-evidence-ubuntu-latest` (ID 12242369176) confirms all seven paired cases and five samples each. Issues #9 and #68 remain OPEN.

## PE32 x86 DLL regression (integrated; scoped CI verification)

The Windows hosted job builds two PE32 **DLL** samples from the newly tracked
`fixtures/probes/x86_dll_probe.c` source, once with the x86 MSVC toolchain
and once with Clang-cl targeting `i686-pc-windows-msvc`. Generated DLLs are
ignored ephemeral CI build outputs. Neither DLL is loaded or executed.
The independent pinned `pefile==2024.8.26` oracle checks I386 machine,
PE32 optional header, DLL bit, nonempty sections, `GetTickCount64` import,
and the named `rel_dll_probe_transform` export. It compares the analyzer's
manifest architecture, exact SHA-256, byte length, sections and expected
imports/exports; the job uploads a JSON record with source and file hashes.
Compilation and the independent oracle passed on the exact [PR #92](https://github.com/ELITEAYOTO/REL/pull/92) head in [Windows/Ubuntu CI #39353143656](https://github.com/ELITEAYOTO/REL/actions/runs/39353143656). The separate [post-squash main CI #39353437460](https://github.com/ELITEAYOTO/REL/actions/runs/39353437460) passed both OS jobs on ce6c4e0; Ubuntu skips DLL compilation and independently tests the non-Windows workspace. The Windows `rel-pe32-dll-oracle-windows` JSON artifact captures source and output hashes, not redistribution rights.

The new tracked source and generated DLLs have **no established redistribution
rights**. This is useful controlled, local-only bitness/type/compiler coverage,
not a cleared redistributable PE corpus. MSVC and Clang-cl can share SDK,
linker and CRT; recorded hashes can vary with hosted toolchain/image changes.
No source-license decision is made here; issues #9 and #16 remain open.

## Sources and rights

| Case | Generation / validation | Redistribution |
| --- | --- | --- |
| Tracked PE32 `fixtures/pe32-basic.exe` | Existing synthetic fixture in REL, SHA-256 and size checked against `fixtures/expected.json` | Not established; REL has no adopted source LICENSE |
| Tracked PE64 `fixtures/pe64-basic.exe` | Existing synthetic fixture, independently hash-verified | Not established |
| PE32 and PE64 1 MiB / 4 MiB overlays | Exact verified seed bytes plus zero-filled suffix, generated locally on each run | Derived from unlicensed-status fixtures |
| Native Windows release REL EXE | Built from current repository in the current Windows CI job, not newly committed to the corpus | Third-party dependency rights and redistribution not assessed |
| MSVC x64 C probe | Build `fixtures/probes/msvc_probe.c` during Windows CI using runner-installed MSVC and SDK, then analyze the compiled PE; the EXE is **not** checked into git or executed | The checked-in source is not assigned a redistribution license and MSVC/SDK-built binary redistribution has **not** been cleared |
| Clang-cl x64 C probe (integrated, controlled) | Build **the same C source** with LLVM Clang-cl against hosted Windows SDK/toolchain, then independently verify static imports/exports. Record the observed `clang-cl --version` output; compiled EXE is ephemeral | Rights are **not established**; Clang/LLVM compiler version is observed, not pinned |

Public source visibility or the presence of an executable in GitHub **does not** constitute a grant to redistribute it. These scripts make no licensing assertion about authored fixtures or compiler output. See [license decision #16](https://github.com/ELITEAYOTO/REL/issues/16). No external PE files are downloaded and no inspected PE is launched.

## Reproducible cases

`scripts/_internal/corpus_cases.py` supplies one shared, hash-checked case inventory to both `scripts/benchmark_cli.py` and `scripts/profile_resources.py`. It refuses reference fixture SHA-256/size drift and non-synthetic metadata. The output includes six controlled cases on each OS: two original 2 KiB fixtures and four generated overlays (1 MiB and 4 MiB for each architecture). On Windows the **locally compiled REL release EXE** adds a seventh case, the optional **MSVC x64 locally built C probe** adds an eighth, and the opt-in **Clang-cl x64 build of the same C source** adds a ninth case when both probes are supplied. The source hash is recorded in the case metadata, while the output PE hash is recorded in each benchmark/resource observation.

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

## Clang-cl extension (PR CI verified)

The existing Windows builder now requires Clang-cl in addition to MSVC and records `clang-cl --version` as `compiler-probes/clang-cl-version.txt`. The Clang-cl executable remains ignored and is never launched. The same pinned independent `pefile` oracle compares PE32+ x64 headers, sections, the `GetTickCount64` import, the `rel_probe_transform` export and the REL manifest's size/hash on both compiler-built files.

The new case `clang-cl-x64-local-build` includes `kind=ci-built-clang-cl-x64-pe`, `source_sha256` of the checked-in C file and an observed `toolchain_version`. The exact executable SHA-256 belongs to each benchmark/resource observation. The scenario is blocked if the generated file or Clang version record is missing. This is a compiler-*frontend* diversity experiment: both builds can use Microsoft's linker, CRT and Windows SDK, so no independent linker diversity is claimed. The hosted image versions are not locked and neither compiler build is approved for binary redistribution; keep issues #9 and #16 open. Do not infer performance gains from cross-run hosted CI timings.

## Windows structured PE resource/relocation increment (PR CI verified)

The Windows CI compiles two *additional* controlled source-built PE32+ inputs from `fixtures/probes/structured_probe.c` and `fixtures/probes/structured_probe.rc`, using the installed Windows SDK resource compiler `rc.exe` plus MSVC or LLVM Clang-cl. The C program exports a global pointer initialized to a static label (a base relocation) and an exported query function; `/DYNAMICBASE /FIXED:NO` enables address relocation. The RC source embeds `RT_RCDATA` ID 101 with fixed sample bytes. The resulting files are only created within ignored `compiler-probes/`; they are **never executed, downloaded, or checked into git**.

The independent pinned `pefile` oracle (`scripts/check_windows_structured_probe.py`) requires an ASLR-enabled PE32+ x64, sections `.rsrc` and `.reloc`, the resource entry/bytes at RCDATA #101, at least one DIR64 relocation, and exported `rel_structured_query` and `rel_structured_pointer`. It then compares REL's original manifest schema, SHA-256, input size and section/export names. **REL does not claim to decode RCDATA or relocation entries; these tests cover acceptance/section reporting of those layouts while a separate engine supplies structure truth.**

The profiler and benchmark receive `--windows-msvc-structured` and `--windows-clang-structured`, creating cases `msvc-x64-structured` and `clang-cl-x64-structured` (Windows: 11; Linux: 6). Each reports a C source SHA-256, separate RC source SHA-256, output-binary SHA-256 and explicit `redistribution_status=not-established`. Clang's observed version is recorded, not pinned. GitHub's runner, MSVC, linker and Windows SDK may change; generated bytes are not guaranteed identical across environments. Compiled binary redistribution rights remain **unverified**, so do not publish binary artifacts or claim a generally redistributable corpus. #9 and #16 remain open.

The two independent structural oracles, case/provenance regressions, static CLI smoke, benchmarks and resource profiles passed [Windows/Linux CI #39157915184](https://github.com/ELITEAYOTO/REL/actions/runs/39157915184) and [CI #39157910924](https://github.com/ELITEAYOTO/REL/actions/runs/39157910924). The controlled structured probes also passed later [main Windows/Ubuntu CI #39354165057](https://github.com/ELITEAYOTO/REL/actions/runs/39354165057). This does not verify byte-for-byte reproducibility across different hosted images, change `binary-manifest` v1.0.0 or improve malicious-input isolation.

## Actual MSVC delay-load import evidence (scoped #9 experiment)

The existing Windows MSVC build step now compiles `fixtures/probes/x86_dll_probe.c`
as a controlled x64 target DLL, then links the tracked
`fixtures/probes/delay_import_probe.c` consumer against its generated import
library with `/DELAYLOAD:rel-delay-target.dll` and `delayimp.lib`. The
generated PE32+ executable and DLL live only in ignored `compiler-probes/`
during CI: **neither is run, loaded, committed or uploaded**.

The existing pinned `pefile==2024.8.26` oracle independently decodes the
consumer's PE delay-import table (directory 13) and named symbol, checks
the actual target DLL export and direct-import table, then requires REL's
`binary-manifest v1.0.0` to preserve exactly the direct imports and produce
the explicit delay-load **coverage warning**. The helper has negative tests for
a missing warning, fabricated direct import, or altered delayed symbol.
No delayed DLL/symbol is added to `imports[]`: this is a coverage test,
not a delay-import extraction implementation or evidence of runtime use.

The additional JSON record is part of the existing Windows
`rel-pe32-dll-oracle-windows` artifact; SHA-256 of both generated binaries,
both checked-in C source files, observed MSVC/SDK version strings, and
independently decoded fields are retained. Generated binaries and their
redistribution rights are **not** cleared; changing hosted compilers does not
prove byte-for-byte reproducibility. This is one true linker-generated
delay-load layout, not a comprehensive or licensed representative corpus.
See [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).

## MSVC-produced ordinal import and NONAME DLL oracle (P1.5 #9)

The existing Windows static-only builder now creates a DLL with one exported
function using `ordinal_import_probe.def`, ordinal **42** and `NONAME`, plus
a separate PE32+ consumer linked with the generated import library. This
exercises a true linker-produced ordinal import rather than rewriting a
synthetic fixture's import thunk. The new C and DEF files are tracked as
source only; generated EXE/DLL/import libraries are ignored, never executed,
loaded, distributed, or included in CI artifacts.

The existing `pefile==2024.8.26` oracle checks that the target export is
unnamed at ordinal 42 and that the consumer imports that ordinal from the
expected DLL, then verifies the exact REL direct-import list and the v1
ambiguity warning. Falsification tests cover missing warning, missing
observation, wrong ordinal and false named-import interpretations. The
existing `rel-pe32-dll-oracle-windows` *JSON-only* evidence retains both
binary hashes, tracked C/DEF source hashes and observed MSVC/SDK versions.
Its internal experimental evidence format becomes v3 when this case is
included; the public `binary-manifest v1.0.0` contract is unchanged.

This proves a single source-produced ordinal-load layout only, not an
exhaustive ordinal-import parser or behavioral runtime test. Compiler
reproducibility and redistribution permissions are **not established**.
Issues [#9](https://github.com/ELITEAYOTO/REL/issues/9) and
[#16](https://github.com/ELITEAYOTO/REL/issues/16) remain open.

## Real mixed named and ordinal imports in one MSVC DLL (P1.5 #9)

The controlled `ordinal_import_probe.c/.def` source extends the previous
x64 ordinal-only case with **two exports in the same DLL**: ordinal 42
`NONAME`, plus the named `rel_named_probe` at ordinal 43. The consumer
calls both through the import library; actual compiled inputs are **only
read as bytes**, never executed or loaded, and remain outside Git/artifacts.

The independent pinned `pefile` oracle now demands *both* imported entries
from `rel-ordinal-target.dll` in the same consumer, verifies the named and
unnamed exports in the linked DLL, compares the complete direct-import list
with REL and preserves the existing v1 ambiguity warning. The oracle's
negative tests reject missing/extra named observations and altered ordinals.
The existing JSON-only artifact preserves the source/binary SHA-256 and
toolchain identity; its **internal experimental** evidence format is v4
for this expanded case, without modifying `binary-manifest v1.0.0`.

This is a single compiler-produced mixed-import layout, **not** general
ordinal coverage, an execution test, a redistribution grant, or a hard
resource/sandbox guarantee. Issues #9 and #16 remain unresolved.
