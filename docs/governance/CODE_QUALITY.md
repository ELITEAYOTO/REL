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

`Cargo.lock` and broader input fuzzing are P1.5 work, not previously completed.
