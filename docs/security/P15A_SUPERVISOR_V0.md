# P1.5-A — Opt-in direct-child watchdog (v0)

**Status: optional watchdog, Linux native limits, Windows Job Object and sampled stdout/stderr spool controls integrated on `main`; latest combined [post-merge CI #39305827604](https://github.com/ELITEAYOTO/REL/actions/runs/39305827604) succeeded on Windows/Ubuntu.** [PR #79](https://github.com/ELITEAYOTO/REL/pull/79) added the sampled spool checks. This is a controlled-input runner, not a sandbox or a general hard memory/CPU/disk quota.

## Scope

The existing scripts/profile_resources.py gathers sampled RSS/CPU and has a profiler-only timeout. The separate scripts/run_bounded_inspection.py now provides an opt-in supervised execution path. The analyzer is launched as a direct child with the subcommand analyze and the PE pathname as **data**; the PE is never run.

- Default wall-time budget: 30 seconds, user-adjustable up to 600. If exceeded, kill and reap the direct child; wrapper exit code 124.
- Default observed-RSS threshold: 512 MiB, user-adjustable from 16 to 4096 MiB. Poll at a nominal 10 ms cadence, and kill/reap the direct child when a sample exceeds the threshold; exit code 125.
- Capture child stdout and stderr into temporary files (not pipes). Return complete child stdout only on success, with a 16 MiB plus newline byte check; suppress partial stdout after failures. A sampled temporary-file length check also kills a still-running child when stdout grows past this cap or stderr past 1 MiB. The same limits are checked on exit. On Linux, an inherited per-file kernel `RLIMIT_FSIZE` ceiling additionally blocks writes above `max(stdout_budget, stderr_budget) + 1` bytes (or a smaller inherited hard cap) **before** a polling cycle catches up. Nonzero child exit, monitoring failure or oversized output returns 1. This is NOT a filesystem disk quota: a child may create many separate files, and stderr retains its smaller *sampled* limit.
- Use Python 3.12 and psutil==7.0.0, already pinned in the profiling CI. Do not change Rust crates, binary-manifest v1.0.0 or the default rel-inspect CLI.

## Running against a controlled reference fixture

After building the release executable and installing psutil==7.0.0:

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect --input fixtures/pe64-basic.exe --wall-seconds 30 --max-sampled-rss-mib 512
    python scripts/test_bounded_inspection.py --binary target/release/rel-inspect

Use target/release/rel-inspect.exe under Windows. Output is the unchanged JSON manifest on stdout; errors are on stderr. Only use authorized input files.

## Tests

The cross-platform suite exercises exact successful stdout bytes, withholding partial stdout on a nonzero exit, killing a sleeping process on timeout, killing a synthetic Python allocation when its **sampled** RSS breaches a threshold, short stdout/stderr spool budgets with a still-running child, a child that exits with oversized stderr, invalid budget rejection, and an actual REL PE64 fixture with manifest schema/hash/size assertions. Run tests after the existing CI psutil installation on Windows and Ubuntu.

## Validation evidence

[CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060) completed successfully on Windows and Ubuntu. Dedicated watchdog regressions (including real REL PE64 fixture manifest/hash/size) passed alongside existing Rust tests, Release, CLI smoke and Windows PE oracle. This does not validate arbitrary hostile-file or process-tree safety.

## Important limitations

- The wall timeout is a best-effort supervisor deadline with process-termination latency; it is not a CPU-time budget. Process creation is outside the monitored loop.
- RSS is **sampled, not kernel-enforced**. Short spikes or a quick child exit can escape observation. A successful run does not establish that peak memory stayed below its threshold.
- On **Linux**, the wrapper launches the analyzer into a fresh session/process group, then sends SIGKILL to that group on timeout, error **and normal exit**. Ordinary forked descendants remaining in that group are terminated; processes that create another session/group can escape. This is not a cgroup, process-tree sandbox, aggregate RSS/CPU quota or complete containment. On **Windows**, descendant cleanup is only provided when the optional Job Object mode is enabled; without it only the direct child is stopped. It is not safe for arbitrary hostile programs.
- Captured stdout and stderr go to temporary files. Linux additionally applies an inherited **per-file** `RLIMIT_FSIZE` in the supervised analyzer (cap derived from the larger output budget), preventing that process from growing any one regular file beyond the kernel ceiling. The smaller stderr budget remains sampled, not kernel-enforced. Windows continues to sample both spool sizes; fast bursts may exceed budgets between polls. Neither platform has an aggregate disk-space quota; writes across many files, hostile descendants that escape process groups, and other filesystem activity remain outside this guard.
- The regular rel-inspect CLI is unchanged and does **not** enforce these limits when run directly. Other unresolved risks include path races, coherent file snapshots, process isolation and a broader licensed PE corpus.
- Thresholds are provisional engineering defaults, not validated production resource ceilings. OS-native containment and enforceable RAM/CPU controls remain future P1.5-A/B work.

Keep issue #9 open. See resource profiling, threat model, ADR-0013 and ROADMAP.


## Linux native virtual address-space cap (scoped PR CI verified)

The optional `--max-address-space-mib N` argument (Linux only, `128 <= N <= 8192`) installs a **kernel-enforced RLIMIT_AS soft and hard limit** in the analyzer child *before* `exec` using Python `resource.setrlimit`. Existing watchdog usage stays unchanged unless this new flag is supplied; Windows rejects the flag before spawning the analyzer. The flag limits the child process's **virtual address space**, which includes mapped and reserved address ranges, **not physical RAM/RSS**. On a denied allocation the analyzer may return an ordinary nonzero exit or fail to start; no universal "limit exceeded" status can be deduced from an exit code. The prior sampled RSS guard and wall timeout remain separate checks.

The native-cap regressions passed [Windows/Linux PR CI #39149771201](https://github.com/ELITEAYOTO/REL/actions/runs/39149771201) in the controlled Ubuntu job. Dedicated Linux tests inspect `resource.getrlimit(RLIMIT_AS)` from the subprocess and cause a Python allocation larger than its enforced limit, expecting `MemoryError`/a known exit status. The standard REL PE64 manifest smoke also runs with a 2048 MiB address-space ceiling on Linux. Existing Windows tests and the ordinary CLI are unaffected.

This is **not** a cgroup aggregate RAM cap, a strict RSS threshold, a CPU-time limit, process-tree isolation or a sandbox. Each process has its own address-space limit; the test wrapper is single-threaded because Python's `preexec_fn` is unsafe in a multithreaded parent. Settings below a binary's required mappings may cause legitimate failures. Boundaries on other Unix platforms, Windows Job Objects, descendants and disk-output quotas remain future work.

### Reproduce Linux native address-space cap

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect --input fixtures/pe64-basic.exe --wall-seconds 30 --max-sampled-rss-mib 512 --max-address-space-mib 2048

The added cap is off by default. A too-small virtual-address-space ceiling may cause ordinary analyzer failure rather than a distinguished budget exception; do not present error code 1 as proof of an RSS breach. The effective kernel limit and an intentionally rejected allocation were checked by dedicated Ubuntu tests in [Windows/Linux PR CI #39149771201](https://github.com/ELITEAYOTO/REL/actions/runs/39149771201); this is not a system-wide memory bound.

## Windows native Job Object memory-commit budget (PR CI verified)

Windows gains the optional `--max-job-memory-mib N` argument (range `128..8192`, disabled by default). It creates a Windows Job Object with `JOB_OBJECT_LIMIT_JOB_MEMORY` and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, creates the analyzer child with `CREATE_SUSPENDED`, attaches it to the Job Object, verifies membership through `IsProcessInJob` and resumes its only initial thread. If any step fails, it terminates the suspended child and reports failure; it does not run REL without the requested job. During cleanup, closing the Job Object terminates associated descendants. This protects the **supervised direct analyzer process and cooperating descendants assigned to this job**, not external processes.

Example after building REL and installing `psutil==7.0.0`:

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect.exe --input fixtures/pe64-basic.exe --max-job-memory-mib 512

This memory budget is **job commit charge**, not a strictly enforced resident RSS/physical RAM quota. Native job memory denials may surface as allocation errors or ordinary nonzero child failures; they cannot automatically be labeled a sampled-RSS breach. The sampled RSS threshold and wall-time watchdog remain separate. The option is rejected on Linux; Linux's optional `RLIMIT_AS` remains unchanged.

Windows tests exercise assignment before user code, native memory allocation refusal under a smaller limit, descendant termination after a supervisor timeout, and actual REL manifest compatibility. This is not a sandbox: custom breakaway/ancestor jobs, protected processes, malicious descendant handle duplication, drivers, filesystem races, CPU-time and temp-file disk quotas remain open. The job handle remains owned exclusively by the Python wrapper. Windows 8+ nested job behavior is assumed in hosted CI; association failure must be treated as an error, never silently disabled. The implementation plus native Windows allocation, process startup, descendant cleanup and PE64 compatibility regressions passed [Windows/Linux PR CI #39151722498](https://github.com/ELITEAYOTO/REL/actions/runs/39151722498), along with Rustfmt, Clippy, locked tests, Release, smoke and oracle. The memory quota is the Job Object's **committed memory**, not RSS. The integrated Job Object regressions also passed the later [main Windows/Ubuntu CI #39354165057](https://github.com/ELITEAYOTO/REL/actions/runs/39354165057); that run cannot establish general hostile-process isolation. Issue #9 remains open.

Microsoft references: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject), [Job Object limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information).


## Linux opt-in per-process CPU-time ceiling (PR CI verified)

The Python watchdog can additionally accept `--max-cpu-seconds N` on Linux (`1..300`, disabled by default). Combined with optional RLIMIT_AS, the wrapper installs `resource.RLIMIT_CPU` *before exec* with **soft limit N seconds** and **hard limit N+1 seconds**. A CPU-bound child crossing the soft limit receives SIGXCPU (usually terminating it, e.g. subprocess exit `-SIGXCPU`); if caught/ignored, the hard limit is a kernel backstop. Ordinary successful REL inspection continues unchanged under a 10-second CPU budget. Other errors/terminations are reported as ordinary child failures; the wrapper does not falsely call all nonzero exit statuses proven CPU-limit breaches.

Reproduce on a controlled Linux fixture:

    python scripts/run_bounded_inspection.py --binary target/release/rel-inspect --input fixtures/pe64-basic.exe --max-address-space-mib 2048 --max-cpu-seconds 10

**This is a per-process accumulated user+system CPU-time ceiling, not a wall-time limit, aggregate descendant CPU quota, job-wide accounting, scheduler quota, RSS bound or sandbox.** A forked descendant has its own RLIMIT_CPU counter, so processes collectively can consume more CPU than the requested budget. Windows explicitly rejects the option. Regressions assert the kernel's soft/hard values before exec, test that a busy child dies by SIGXCPU, test unsupported/invalid flags, and preserve the PE64 manifest under the configured CPU/address-space limits. The kernel-limit, SIGXCPU, invalid-option and real-PE64 regressions passed [Windows/Linux CI #39152737826](https://github.com/ELITEAYOTO/REL/actions/runs/39152737826); the integrated Linux CPU-limit regressions also passed [main Windows/Ubuntu CI #39354165057](https://github.com/ELITEAYOTO/REL/actions/runs/39354165057), without establishing aggregate descendant CPU bounds.

## Linux process-group cleanup (integrated, narrow CI-verified scope)

The opt-in watchdog now requests `start_new_session=True` on Linux when spawning the analyzer. This puts the analyzer in a fresh process group instead of the wrapper's group. At normal exit or failure, `SIGKILL` targets that group (ignoring an already absent group) so ordinary subprocess descendants do not remain running after the wrapper returns. The existing child is still explicitly waited/reaped. Deterministic Linux regressions launch a parent plus delayed-write descendant; they assert that the descendant never creates its marker after timeout or successful parent exit. Windows behavior and public manifest contracts are unchanged.

**Boundary:** this cleans up only processes in that group. A descendant can call `setsid`/`setpgid`, fork into another group or otherwise escape; CPU and address-space limits are per process, RSS is sampled, and outputs remain temporary spools without a hard disk quota. It is neither a complete process-tree kill guarantee nor a sandbox. These Linux-only regressions passed in [PR #91](https://github.com/ELITEAYOTO/REL/pull/91) final-head [CI #39351908549](https://github.com/ELITEAYOTO/REL/actions/runs/39351908549); post-squash main [CI #39352685559](https://github.com/ELITEAYOTO/REL/actions/runs/39352685559) also passed both Windows and Ubuntu. This is a scoped verification, not a hostile-input guarantee.

## Linux RLIMIT_FSIZE spool containment (scoped increment; issue #9 still open)

The opt-in Linux watchdog now applies `resource.RLIMIT_FSIZE` in its single-threaded pre-exec child hook even when optional `RLIMIT_AS` and `RLIMIT_CPU` are disabled. The soft and hard ceiling is one byte over the *larger* configured stdout/stderr limit, never exceeding any smaller inherited hard limit. Both temporary streams are regular files and inherit this per-file restriction; direct-child writes to **other regular files** are affected too. Oversized writes can terminate the analyzer by SIGXFSZ or fail with EFBIG, reported as a generic worker failure, never as proof of aggregate disk exhaustion. Existing post-exit checks still suppress partial JSON, and the 1 MiB stderr budget remains enforced by polling/post-exit checks because the kernel ceiling must permit up to the larger 16 MiB stdout budget. Windows is unchanged. The Linux regressions inspect the native limit before execution and force a fast oversized file write while the polling interval is deliberately long.

This is **not** a cgroup, quota for a filesystem, cap across many output files, a descendant-process sandbox or a guarantee against all hostile inputs. No additional third-party dependency or binary-manifest format change.

## Controlled Python tests and Windows virtual environments

The watchdog regression suite launches its controlled Python workloads with
`sys._base_executable` when available, falling back to `sys.executable`.
A Windows venv executable may be a redirector: the PID returned by process
creation belongs to that launcher, while a second process performs the Python
allocation or creates descendants. A regression requires the controlled
interpreter's reported PID to equal the created process PID before treating
the resource tests as direct-process evidence. CLI integration still launches
the watchdog with `sys.executable`, preserving the caller's Python environment,
and the supervised analyzer is the native `rel-inspect` executable.

On Windows 10 build 19045 with Python 3.11.9 from the Microsoft Store, the prior
venv-controlled tests failed the sampled RSS, job memory and descendant-cleanup
assertions; the same suite passed with the base interpreter. This change fixes
the test workload selection, not the production supervisor. Sampled RSS still
observes only the direct child, and this evidence does not establish containment
for arbitrary launchers, brokered processes or hostile workloads. The PE inputs
remain static data and are never executed.
