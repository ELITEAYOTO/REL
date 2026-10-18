# P1.5-A — Opt-in direct-child watchdog (v0)

**Status: bounded direct-child supervision tested on [Windows/Linux PR CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060), main integration pending.** This is an optional controlled-input runner, not a sandbox or a hard memory/CPU cap.

## Scope

The existing scripts/profile_resources.py gathers sampled RSS/CPU and has a profiler-only timeout. The separate scripts/run_bounded_inspection.py now provides an opt-in supervised execution path. The analyzer is launched as a direct child with the subcommand analyze and the PE pathname as **data**; the PE is never run.

- Default wall-time budget: 30 seconds, user-adjustable up to 600. If exceeded, kill and reap the direct child; wrapper exit code 124.
- Default observed-RSS threshold: 512 MiB, user-adjustable from 16 to 4096 MiB. Poll at a nominal 10 ms cadence, and kill/reap the direct child when a sample exceeds the threshold; exit code 125.
- Capture child stdout and stderr into temporary files (not pipes). Return complete child stdout only on success and after a 16 MiB plus newline byte check; suppress partial stdout after failures. Nonzero child exit, monitoring failure or oversized output returns 1.
- Use Python 3.12 and psutil==7.0.0, already pinned in the profiling CI. Do not change Rust crates, binary-manifest v1.0.0 or the default rel-inspect CLI.

## Running against a controlled reference fixture

After building the release executable and installing psutil==7.0.0:

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect --input fixtures/pe64-basic.exe --wall-seconds 30 --max-sampled-rss-mib 512
    python scripts/test_bounded_inspection.py --binary target/release/rel-inspect

Use target/release/rel-inspect.exe under Windows. Output is the unchanged JSON manifest on stdout; errors are on stderr. Only use authorized input files.

## Tests

The cross-platform suite exercises exact successful stdout bytes, withholding partial stdout on a nonzero exit, killing a sleeping process on timeout, killing a synthetic Python allocation when its **sampled** RSS breaches a threshold, a test-only small stdout cap, invalid budget rejection, and an actual REL PE64 fixture with manifest schema/hash/size assertions. Run tests after the existing CI psutil installation on Windows and Ubuntu.

## Validation evidence

[CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060) completed successfully on Windows and Ubuntu. Dedicated watchdog regressions (including real REL PE64 fixture manifest/hash/size) passed alongside existing Rust tests, Release, CLI smoke and Windows PE oracle. This does not validate arbitrary hostile-file or process-tree safety.

## Important limitations

- The wall timeout is a best-effort supervisor deadline with process-termination latency; it is not a CPU-time budget. Process creation is outside the monitored loop.
- RSS is **sampled, not kernel-enforced**. Short spikes or a quick child exit can escape observation. A successful run does not establish that peak memory stayed below its threshold.
- Only the **direct child** is killed, not arbitrary descendants; the wrapper is not an OS sandbox, Job Object, cgroup or rlimit. It is not a safe way to run arbitrary hostile programs.
- Captured stdout goes to a temporary file; a child can still fill disk before exiting. The final stdout size check is not an incremental disk-write quota.
- The regular rel-inspect CLI is unchanged and does **not** enforce these limits when run directly. Other unresolved risks include path races, coherent file snapshots, process isolation and a broader licensed PE corpus.
- Thresholds are provisional engineering defaults, not validated production resource ceilings. OS-native containment and enforceable RAM/CPU controls remain future P1.5-A/B work.

Keep issue #9 open. See resource profiling, threat model, ADR-0013 and ROADMAP.
