# Architecture P1

- `rel-contracts`: serializable, parser-independent manifest types.
- `rel-pe`: reads untrusted PE bytes statically; no execution.
- `rel-inspect`: single-purpose CLI and input/output safety gates.
- Contract format: JSON, versioned as `1.0.0`.
- No dependency from a library crate on the CLI; dependency graph is one-way.
- Future Ghidra integration is a separate process/module with its own tests.
- Future behavior testing must be opt-in, isolated and on authorized targets.
- Refactoring is evidence-led; breaking interfaces require ADR, migration plan and tests.
