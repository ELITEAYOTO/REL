# P1.5 — Coverage-guided PE parser fuzzing

## Purpose

This is the **first independently executable libFuzzer harness** for `rel-pe::inspect`. It is deliberately separate from the Rust stable workspace, CLI and UI; `fuzz/Cargo.toml` declares its own workspace. The target only parses input bytes and ignores whether the parser returns `Ok` or `Err`; a process crash, uncaught panic, sanitizer error or hang is a failure.

## Reference tooling

- Upstream: https://github.com/rust-fuzz/cargo-fuzz
- Rust Fuzz Book CI: https://rust-fuzz.github.io/book/cargo-fuzz/ci.html
- Fuzzer tool: `cargo-fuzz 0.13.2`; `libfuzzer-sys 0.4` (semver range), nightly Rust required.
- Ubuntu x86_64 only initially for the coverage-guided gate. Existing normal CI still covers stable Rust on Windows and Linux.
- Nightly compiler and full fuzz dependencies are **not pinned yet**. Record the exact compiler and dependency versions in later reproducibility work.

## Corpus

`fuzz/corpus/pe_inspect/pe32-basic.exe` and `pe64-basic.exe` reuse the SHA-identical synthetic source fixtures in `fixtures/`. They are valid seeds, not proprietary game binaries. libFuzzer mutates those seeds and collects code-coverage feedback.

## Reproduce on a supported Unix host

```bash
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz build pe_inspect
mkdir -p fuzz/artifacts/pe_inspect
cargo +nightly fuzz run pe_inspect -- -max_total_time=30 -timeout=4 -rss_limit_mb=1500 -max_len=65536 -seed=20261018 -print_final_stats=1
```

## CI gate and limitations

`.github/workflows/fuzz.yml` runs when the parser or fuzz harness changes and on manual dispatch, with a 20-minute job timeout and approximately 30 seconds of mutation after compilation. On failure, the workflow attempts to upload `fuzz/artifacts`; minimization and classification of crashes are manual follow-up steps. A successful run must have an identifiable commit and run ID recorded before this is considered verified.

This is a **bounded smoke fuzz**. Even a green job does not establish an absence of crashes, hangs or exploitable vulnerabilities. A broad multi-hour corpus campaign, coverage tracking, independent oracle and minimized crash registry remain separate acceptance tasks.

See also [deterministic regression](P15_MUTATION_TESTING.md) and [roadmap](../ROADMAP.md).
