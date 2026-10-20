# REL scripts — executable entrypoints and private support

`scripts/` contains CI and local **commands**, plus a small private Python
module package. This directory is not a new application or independent API.

## Stable entrypoints (root of `scripts/`)

- **Static PE checks:** `smoke_cli.py`, `check_windows_*.py`,
  `build_windows_*.cmd`, `test_*_cli.py`.
- **Resource/measurement evidence:** `benchmark_cli.py`,
  `profile_resources.py`, `profile_malformed_resources.py`,
  `check_measurement_evidence.py`, `compare_measurement_campaigns.py`,
  `test_measurement_*.py`.
- **Experimental evidence/diff:** `verify_observation_evidence.py`,
  `validate_observation_envelope.py`, `compare_ex02_corpus_runs.py`,
  `profile_manifest_diff.py` and their existing tests.
- **Safety and maintenance:** `run_bounded_inspection.py`,
  `check_repo_hygiene.py` and their regressions.

These are categories, **not a new programmatic API**. Call commands by their
existing `python scripts/<name>.py` or CI paths. Windows batch tools continue
at their existing `scripts/` paths. A future move must update all callers,
workflow steps, relevant documentation and test imports together.

## Import-only internals

`scripts/_internal/` contains shared Python modules, **not standalone CLI
commands**:

- `corpus_cases.py`: hash-checked synthetic fixture inventory and provenance
- `measurement_environment.py`: hardware/runner context for reported metrics
- `windows_process_usage.py`: retained creation-handle peak working set/final CPU
  accounting for the direct analyzer process on Windows
- `windows_job.py`: opt-in Windows Job Object support for the watchdog

The entrypoints import these as `from _internal.<module> import ...`. The
corpus helper still resolves `fixtures/` relative to the repository root.

## Maintenance rule

Prefer adding tests to an existing script rather than a second harness. Avoid
moving all scripts to a new tree solely for appearance: most root files are
direct GitHub Actions command targets, so mass relocation increases CI/doc
churn. Retain historical references in dated handoff and changelog entries;
update **active** paths and usage examples when paths really change.

Merge requires the existing complete Windows + Ubuntu CI on the exact PR
head and then on the post-squash `main` commit. Success does not prove that
arbitrary hostile PE files are safe or that resource observations are hard
limits.
