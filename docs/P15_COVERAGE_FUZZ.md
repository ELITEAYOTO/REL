# P1.5 — Coverage-guided PE parser fuzzing

## Purpose

REL fuzzes `rel-pe::inspect` through an independently compiled libFuzzer target. The target **parses only**; it never executes input PE binaries. The fuzz workspace `fuzz/` is separate from the stable Rust workspace and its public `binary-manifest v1.0.0` contract.

## Versioned toolchain and dependency graph (2026-10-19)

- Production keeps stable `rust-toolchain.toml` (`1.85.1`). Fuzzing alone uses `fuzz/rust-toolchain.toml`: **`nightly-2026-10-19`**. The generation job [#39314506973](https://github.com/ELITEAYOTO/REL/actions/runs/39314506973) installed this date successfully and reported **`rustc 1.101.0-nightly (b6eeb93c9 2026-10-18)`**.
- `fuzz/Cargo.toml` pins `libfuzzer-sys = "=0.4.13"`; the independently generated **`fuzz/Cargo.lock`** fixes transitives/checksums (25 packages at generation). The stable root `Cargo.lock` is untouched. The lock was produced with `cargo +nightly-2026-10-19 generate-lockfile --manifest-path fuzz/Cargo.toml`, not reconstructed by hand.
- The CLI helper stays **`cargo-fuzz 0.13.2`**, installed with `--locked` from its published package. `cargo-fuzz` is separate from the target's `fuzz/Cargo.lock`.
- CI verifies `cargo metadata --locked --manifest-path fuzz/Cargo.toml` before instrumented build and checks that `fuzz/Cargo.lock` is not modified afterward. `cargo fuzz` 0.13.2 does **not** expose a `--locked` option for its build/run subcommands; this guard makes any lock rewrite visible instead of relying on a nonexistent flag.
- The dated nightly improves repeatability, **not** byte-identical fuzz executions. GitHub runners, LLVM/sanitizer behavior, timing and mutation scheduling may differ.

## Corpus and immutable regression

Three tracked controlled seeds reside in `fuzz/corpus/pe_inspect/`: synthetic `pe32-basic.exe`, `pe64-basic.exe`, and the unchanged **1104-byte F001** TLS panic reproducer `f001-goblin-tls-oob.bin` (SHA-256 `f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e`). The workflow validates F001's hash before fuzzing and lists all seed hashes; a separate deterministic test keeps the historic issue reproducible. The source files are never launched.

The prior bounded [fuzz run #39310575742](https://github.com/ELITEAYOTO/REL/actions/runs/39310575742) with the then-moving nightly loaded all three seeds and reported 370,650 units / 31 seconds / 577 MiB peak RSS. That historical observation **predates** this pinned lock and is not evidence that the new pinned setup passed.

## Reproduce locally (Unix x86_64; repository root)

```bash
rustup toolchain install nightly-2026-10-19 --profile minimal
rustc +nightly-2026-10-19 --version --verbose
cargo +nightly-2026-10-19 install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-10-19 metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 --no-deps >/dev/null
printf '%s  %s\n' 'f65f21c07542483584cf156f1171ef6d02af1ce7168c573da79f8b81b96cc59e' 'fuzz/corpus/pe_inspect/f001-goblin-tls-oob.bin' | sha256sum --check -
sha256sum fuzz/corpus/pe_inspect/*
cargo +nightly-2026-10-19 fuzz build pe_inspect
mkdir -p fuzz/artifacts/pe_inspect
cargo +nightly-2026-10-19 fuzz run pe_inspect -- -max_total_time=30 -timeout=4 -rss_limit_mb=1500 -max_len=65536 -seed=20261018 -print_final_stats=1
git diff --exit-code -- fuzz/Cargo.lock
```

## CI: fast smoke and separately dispatched longer run

- `.github/workflows/fuzz.yml` runs when fuzz/ or the parser changes (plus manual dispatch); 30-second libFuzzer smoke, `-timeout=4`, `-rss_limit_mb=1500`, `-max_len=65536`, runner timeout 20 minutes, failure artifacts preserved.
- **`.github/workflows/fuzz-long.yml`** is a separate **manual `workflow_dispatch`** only: 300-second campaign, same bounded input/RSS/per-input-time settings, overall job timeout 20 minutes. The run logs exact commit, nightly compiler, helper version, target and seed hashes; uploads metadata, execution log and any failure artifacts even when the fuzz process exits unsuccessfully.
- GitHub's `-rss_limit_mb` is an instrumented runtime limit, not a kernel process-tree quota. The runner/job timeout is not a comprehensive CPU/memory or filesystem sandbox.

**Acceptance outstanding:** run and inspect the manual long campaign; extend licensed corpus diversity and independent semantic oracles, triage/minimize all distinct failures and investigate upstream TLS panic [F001](findings/F001_GOBLIN_TLS_PANIC.md). Do not close [issue #12](https://github.com/ELITEAYOTO/REL/issues/12) on workflow presence or a green short smoke alone. A green campaign never proves arbitrary hostile PE safety.
