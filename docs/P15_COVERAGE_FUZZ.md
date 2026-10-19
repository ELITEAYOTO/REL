# P1.5 — Coverage-guided PE parser fuzzing

## Purpose

This is the **first independently executable libFuzzer harness** for `rel-pe::inspect`. It is deliberately separate from the Rust stable workspace, CLI and UI; `fuzz/Cargo.toml` declares its own workspace. The target only parses input bytes and ignores whether the parser returns `Ok` or `Err`; a process crash, uncaught panic, sanitizer error or hang is a failure.

## Reference tooling

- Upstream: https://github.com/rust-fuzz/cargo-fuzz
- Rust Fuzz Book CI: https://rust-fuzz.github.io/book/cargo-fuzz/ci.html
- Fuzzer tool: `cargo-fuzz 0.13.2`; `libfuzzer-sys 0.4` (semver range), nightly Rust required.
- Ubuntu x86_64 only initially for the coverage-guided gate. Existing normal CI still covers stable Rust on Windows and Linux.
- Nightly compiler and full fuzz dependencies are **not pinned yet**; recording an exact compiler version does not make the run reproducible across future toolchain updates. This increment fixes historical crash-seed coverage only; the dependency lock and extended campaign remain issue #12. Record the exact compiler and dependency versions in later reproducibility work.

## Corpus

`fuzz/corpus/pe_inspect/pe32-basic.exe` and `pe64-basic.exe` reuse the SHA-identical synthetic source fixtures in `fixtures/`. The third seed, `f001-goblin-tls-oob.bin`, reuses **the exact Git blob** from `fixtures/regressions/goblin-0.9.3-tls-oob.bin` (1104 bytes; SHA-256 `f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e`). The fuzz workflow checks that checksum **before** building the instrumented target, and records the actual nightly compiler version. All three seeds are controlled evidence, never executable inputs run as programs. libFuzzer loads and mutates the seed corpus to collect code-coverage feedback. The known crash is still covered separately by `crates/rel-pe/tests/fuzz_tls_regression.rs`.

## Reproduce on a supported Unix host

```bash
rustup toolchain install nightly --profile minimal
printf '%s  %s\n' 'f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e' 'fuzz/corpus/pe_inspect/f001-goblin-tls-oob.bin' | sha256sum --check -
rustc +nightly --version --verbose
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz build pe_inspect
mkdir -p fuzz/artifacts/pe_inspect
cargo +nightly fuzz run pe_inspect -- -max_total_time=30 -timeout=4 -rss_limit_mb=1500 -max_len=65536 -seed=20261018 -print_final_stats=1
```

## CI gate and limitations

`.github/workflows/fuzz.yml` runs when the parser or fuzz harness changes and on manual dispatch, with a 20-minute job timeout and approximately 30 seconds of mutation after compilation. On failure, the workflow attempts to upload `fuzz/artifacts`; minimization and classification of crashes are manual follow-up steps. A successful run must have an identifiable commit and run ID recorded before this is considered verified.

This is a **bounded smoke fuzz**. Even a green job does not establish an absence of crashes, hangs or exploitable vulnerabilities. A broad multi-hour corpus campaign, coverage tracking, independent oracle and minimized crash registry remain separate acceptance tasks.

See also [deterministic regression](P15_MUTATION_TESTING.md) and [roadmap](../ROADMAP.md).

## Observed failure F001 and mitigation

The initial [CI run 39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574) did **not** pass: libFuzzer found a reproducible panic in goblin's TLS parsing after approximately 182,323 executions. The original crashing input is committed unchanged. See [finding F001](findings/F001_GOBLIN_TLS_PANIC.md).

REL now contains unwinding dependency panics at the parser boundary; this is a **mitigation only**, not a repair of goblin or proof that hostile files are safe. CI must be re-run to prove that the saved regression is handled.

## Confirmed verification after F001 (2026-10-18)

- Original failing run: [39100602574](https://github.com/ELITEAYOTO/REL/actions/runs/39100602574), goblin 0.9.3.
- A subsequent campaign still failed under the initial catch-unwind-only mitigation (fuzzer panic strategy); it was not a sufficient repair.
- `Cargo.toml` and the root `Cargo.lock` now pin `goblin = "=0.10.7"`. See [ADR-0012](adr/ADR-0012-goblin-tls-upgrade.md).
- **Verified bounded run**: [39101228893](https://github.com/ELITEAYOTO/REL/actions/runs/39101228893) returned success. libFuzzer logged **688,395 executions, 31 seconds and 509 MiB peak RSS** on the GitHub Ubuntu runner. These observations are specific to that CI job.
- **Verified normal CI**: [39101228912](https://github.com/ELITEAYOTO/REL/actions/runs/39101228912) passed on Ubuntu and Windows, including the permanent original F001 regression.
- This evidence supports *rejection of F001 without a propagated panic in the tested configurations*, not an absence of other bugs. Preserve the [finding F001](findings/F001_GOBLIN_TLS_PANIC.md) and [follow-up issue #11](https://github.com/ELITEAYOTO/REL/issues/11).
