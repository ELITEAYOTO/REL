# P1.5 — Independent Windows PE oracle

## What this actually tests

On the Windows GitHub runner, Rust compiles `rel-inspect.exe` in Release mode. The existing CLI then **statically analyzes its own executable file**: it does not load, run or instrument an imported third-party executable.

The Python script `scripts/check_windows_pe_oracle.py` compares REL's exported PE manifest to the independent Python parser [pefile 2024.8.26](https://pypi.org/project/pefile/2024.8.26/) (MIT license, version pinned in CI).

The automated assertions cover:
- Target file byte length and SHA-256.
- PE machine type.
- Section names, raw offsets, raw sizes and virtual addresses, **in order**.
- Set of directly imported DLL names, case-insensitive.

This is a **genuine Windows PE compiled from REL source**, not one of the synthetic fixture files. Its contents will vary across compiler/OS revisions. The comparison is generated at CI execution and requires no proprietary binary in this repository.

## Important limits

- Both parsers can be wrong in ways this oracle does not detect.
- Function-level import names and exports are not yet independently verified for the compiled binary.
- One Rust-produced Windows EXE is not a representative corpus of third-party compilers, unusual PE options, DLLs, malware or resource-heavy programs.
- This does not establish full PE security, decompilation capability or safe dynamic execution.

## Reproduce on Windows

```powershell
cargo build --locked --release -p rel-inspect
python -m pip install pefile==2024.8.26
python scripts/check_windows_pe_oracle.py --binary target/release/rel-inspect.exe
```

Further P1.5 requirements include expanding license-verified samples and coverage-guided fuzzing. Do not generalize the narrow CI result.
