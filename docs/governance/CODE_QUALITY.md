# REL code quality and refactor gates

Thresholds are **review conventions**, not universal engineering laws. Count physical source lines for automated reporting. Do not introduce arbitrary splits merely to satisfy a number.

| Code | Soft review | Hard exception / restructure |
| --- | ---: | ---: |
| Rust `.rs` | 350 | 500 |
| Python `.py` | 300 | 450 |
| TypeScript/TSX | 250 | 400 |
| Java `.java` | 350 | 500 |
| C++ `.cpp/.hpp/.h` | 350 | 500 |
| Test source | 500 | 750 |
| Generated files and fixture data | Exempt | Exempt |
| README, ADR, technical docs | No fixed limit | Clarity and review apply |

## Functions and complexity

- Functions >50 lines: review; >80: extract cohesive operations or document exception.
- Cyclomatic complexity >10: review; >15: mitigation/exception, measured by a named tool.
- Branch nesting >4: review, >5: simplify or justify.
- Public functions with >5 parameters: consider a meaningful parameter object if supported by use cases.
- Public APIs should document errors, inputs, invariants and compatibility when relevant.

## Good reasons to refactor

Demonstrated bug, security risk, untestable coupling, repeated stable concept, measured performance regression, or new module blocked by current boundaries. No mass refactor "because another assistant prefers a different pattern."

## Testing and CI

- Unit and integration tests for successful and malformed inputs; record reference binaries and hashes.
- Clippy errors, compiler failures and smoke failures block merge.
- Benchmarks state hardware, build, corpus, warm-up, repeated trials and statistical spread.
- Security-critical data processing receives fuzz/property testing as the corpus grows.
- Every release requires a versioned changelog, toolchain lock/pin and recorded CI evidence.
- Exceptions to hard limits must document path, owner, technical reason, compensating tests and expiry/review date.

`Cargo.lock` is tracked and CI enforces `--locked`. P1.5 deterministic mutation tests are verified, but coverage-guided fuzzing, memory benchmarking and a broader corpus are not yet complete.

## Repository hygiene / preventing stale-file debt

- The live source of truth is GitHub `main` with exact-head CI. `STATUS.md`
  is a **short dated navigation checkpoint**, not live GitHub state. The files
  in `docs/archive/`, past audits and ADRs retain historical evidence, not a task list.
- A tracked source file should have an identified consumer (crate, CLI, test,
  workflow step, or explicitly retained finding). Before deleting or relocating
  it, search callers, workflow steps, docs, fixture references and provenance.
  Never automatically delete a regression witness, fixture, ADR or audit.
- Run `python scripts/test_repo_hygiene.py` and
  `python scripts/check_repo_hygiene.py`. The stdlib-only CI gate checks local
  tracked Markdown file and directory paths on Windows/Linux, NOT external
  URLs, anchor fragments, semantic accuracy, code references or freshness.
- When current documentation is superseded, update its state or link to the
  canonical replacement. Preserve historical snapshots as dated evidence
  rather than silently rewriting history. Avoid redundant status indexes,
  repeated rolling archives and broad cosmetic reorganizations.
- For moved/deleted paths use scoped PRs with consumer/provenance review and
  negative tests. Unreferenced is not evidence of obsolescence.
- Keep executable `scripts/*.py` / `.cmd` entrypoints stable for CI and
  documented invocations; import-only private support modules belong under
  `scripts/_internal/`. Change imports and active references together, and
  require both Windows and Ubuntu CI before further related moves.
