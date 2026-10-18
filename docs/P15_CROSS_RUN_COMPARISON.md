# P1.5-A — Comparison of independent measurement campaigns

**Status:** experimental *offline* comparison of existing CI measurement JSON; real-world stability and representative performance thresholds remain **unverified**. No compiled PE is executed.

## Why a new check is required

[PR #36](https://github.com/ELITEAYOTO/REL/pull/36) records a full `measurement_context_sha256` in each timing/resource pair. Its fingerprint includes the GitHub run ID and attempt. Therefore the *same-job* fingerprint must **not** be compared unchanged across campaigns: two independent runs should have different session identities.

The independent `scripts/compare_measurement_campaigns.py` validates each campaign internally using `build_evidence` from the existing checker. It then compares every recorded context field *except* `github_run_id` and `github_run_attempt`, requires both IDs to be known **and distinct**, verifies matching benchmark and resource sampling policies, and requires **identical input binary hashes and provenance for every case**. It also rejects missing critical observed metadata, different compiler/toolchain/runner/CPU, a different **REL executable SHA-256**, a different input corpus or fewer than five samples.

Only when all these checks pass does it compute descriptive per-case median timing differences and ratios from the original per-run timing samples. An incompatible or unverified pair **never** receives a ratio: JSON `status=not_comparable`, a list of `blockers` and `cases=[]`. The CLI writes this evidence report but returns exit code **2** so a pipeline cannot treat abstention as a successful comparison. Missing/invalid within-campaign reports are rejected as an input validation error.

## Reproduce after downloading both runs' per-OS artifacts

Both runs must be for the **same OS** and contain the four existing reports, retrieved from their original GitHub Actions artifacts. Do not synthesize hardware equivalence or edit any `measurement_context`.

```bash
python -m pip install psutil==7.0.0
python scripts/test_measurement_campaigns.py
python scripts/compare_measurement_campaigns.py \
  --baseline-benchmark run_a/rel-benchmark.json \
  --baseline-resources run_a/rel-resources.json \
  --candidate-benchmark run_b/rel-benchmark.json \
  --candidate-resources run_b/rel-resources.json \
  --output rel-campaign-comparison.json
```

On PowerShell, write the command on a single line. JSON output has the separate `rel-measurement-campaign-comparison-v1` schema; it is **not** an update to REL's `binary-manifest v1.0.0`. CI tests the tool with controlled synthetic JSON on both Windows and Linux, without pretending that two hosted CI runs share hardware.

## Interpretation constraints

- **Descriptive only:** a median ratio from five startup+parse+hash+stdout iterations cannot certify performance improvement or regression. No statistical hypothesis test, variance threshold, speed budget or authorization to release changes follows from it.
- Matching reported CPU/OS/toolchain/image fields and the executable hash **does not prove the physical host, scheduler load, thermal state or CPU quota are equivalent**. Even a `descriptive_only` result is a provisional comparison.
- Rejecting unmatched binaries is deliberate: Windows MSVC/Clang-cl output can differ between runs even for the same C/RC source. This is evidence of incomplete comparability, not necessarily a functional failure.
- **RSS and sampled CPU values are not compared**: the profiler can miss peaks and final CPU totals, especially for short-lived processes. The tool validates their internal report consistency but does not interpret changes as memory or CPU regressions.
- A truly defensible budget requires repeatable campaigns on fixed controlled hardware, pinned runners/toolchains, an independently legal and structurally representative corpus, and a separately approved statistical acceptance policy. See [resource observations](P15_RESOURCE_PROFILING.md), [corpus rights](security/P15A_CORPUS_PROVENANCE.md), and [issue #9](https://github.com/ELITEAYOTO/REL/issues/9).
