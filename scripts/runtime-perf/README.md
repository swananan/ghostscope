# Runtime performance baseline

This suite extends the hot-function comparison harness with real CLI output.
The original `scripts/compare/compare_hot_function_bench.py` remains the manual
GDB comparison with steady-state output suppressed. This suite measures three
workloads at the same function entry:

| Workload | Work performed for each hit |
|---|---|
| `print` | Read and print a scalar event sequence number |
| `complex` | Print the sequence number and dereference/format a nested C struct with a 16-element array and a character array |
| `backtrace` | Print the sequence number and execute `bt full` through a known application call chain, with depth 8 |

The fixture uses `-O2`, DWARF, no PIE, and disabled sibling-call optimization.
Every run starts a fresh target and observer. One untimed warmup per workload
precedes five recorded repetitions by default. Candidate ordering alternates,
and workload ordering rotates between repetitions. Each repetition includes a
fresh untraced target for the slowdown denominator. The default workload is
2,000 calls with 32,768 inner arithmetic iterations per call; these are fixed
inputs, not an adaptive calibration.

## Run

Build the binary and benchmark test before measuring. Use an otherwise idle
Linux x86_64 machine with eBPF privileges, at least two allowed logical CPUs,
and `taskset` from util-linux:

```bash
cargo build --release -p ghostscope --all-features
cargo test --release -p ghostscope-e2e-tests --all-features \
  --test manual_runtime_performance_baseline --no-run

sudo -E env \
  GHOSTSCOPE_RUNTIME_BENCH_BIN="$PWD/target/release/ghostscope" \
  GHOSTSCOPE_RUNTIME_BENCH_PROFILE=release \
  GHOSTSCOPE_RUNTIME_BENCH_OUTPUT_JSON=/tmp/runtime.json \
  GHOSTSCOPE_RUNTIME_BENCH_OUTPUT_MARKDOWN=/tmp/runtime.md \
  "$(command -v cargo)" test --release -p ghostscope-e2e-tests --all-features \
  --test manual_runtime_performance_baseline manual_runtime_performance_baseline -- --nocapture
```

The test requires that exact filter and skips measurement in routine full e2e.
Agent-driven execution should use the existing e2e runner service and select
`manual_runtime_performance_baseline`. The service's default build is debug;
debug measurements validate the harness but should not be compared with release
measurements.

Set `GHOSTSCOPE_RUNTIME_BENCH_BASE_BIN` to a separately built baseline binary to
measure base/head on the same host using exactly the same fixture and scripts.
Both builds must support the benchmark's CLI flags. Set
`GHOSTSCOPE_RUNTIME_BENCH_FAIL_ON_REGRESSION=1` to enforce comparison thresholds.
It requires a baseline binary. The defaults flag increases greater than 15% in
slowdown, 20% in observer peak RSS, or 1 percentage point in event loss. JSON and
Markdown are written before returning failure on a regression.

Optional environment overrides passed by the test:

| Variable suffix after `GHOSTSCOPE_RUNTIME_BENCH_` | Meaning |
|---|---|
| `ITERATIONS`, `INNER_WORK` | Target workload size |
| `REPETITIONS`, `WARMUPS` | Recorded repetitions and untimed warmups |
| `MAX_SLOWDOWN_PCT`, `MAX_RSS_PCT`, `MAX_LOSS_PP` | Regression thresholds |
| `TARGET_CPU`, `OBSERVER_CPU` | Optional logical CPU IDs for the target and GhostScope |

## Measurement contract

- **Target elapsed time** comes from the fixture's monotonic clock. The target
  remains behind a stdin barrier until GhostScope emits its post-attach ready
  marker. Attach, DWARF/LLVM preparation, draining, and shutdown are excluded.
- **CPU placement** fixes all targets to the first allowed logical CPU by
  default. GhostScope is pinned to another physical core when topology permits;
  the harness uses remaining cores, or shares the observer CPU when no other
  core is available. When other cores are available, SMT siblings of the target
  are excluded from the harness. Bindings and topology IDs are recorded in JSON.
  Override the target and observer CPU IDs on controlled hosts.
- **Slowdown** is the median of per-repetition target-time ratios to the
  untraced target in that repetition. Raw samples and checksums are retained;
  changed target checksums invalidate a measurement.
- **Ready latency** includes DWARF indexing, compilation, loading, and attach.
- **Event loss** is the fraction of expected sequence IDs absent from stdout
  after draining (up to five seconds by default) and bounded observer shutdown.
  The fixture remains alive
  after its timed loop so PID exit cannot interrupt delivery. Duplicate IDs,
  invalid IDs, value errors, and workloads that never render a payload or the
  known backtrace caller fail validation. This is end-to-end non-delivery within
  this delivery window; it does not attribute loss to individual pipeline stages.
- **Observer peak RSS** uses `/proc/<pid>/status` `VmHWM` and includes startup
  preparation. **Steady peak RSS** is the maximum `VmRSS` sampled every 10 ms
  during the timed target interval; short transient peaks can be missed.
  Target `VmHWM` is recorded separately. These are userspace resident memory
  metrics, not kernel BPF/map memory or a whole-process-tree memory budget.
- Both output pipes are drained concurrently. Full trace output is discarded;
  only IDs, counters, workload validation flags, and bounded diagnostic tails
  are retained. The CLI output limiter, debuginfod, logging, debug artifact
  saves, and background backtrace module loading are disabled. An explicit
  empty config selects project defaults instead of local user settings.

JSON includes raw samples, binary hashes, build-profile label, kernel, CPU,
compiler, compiler flags, fixture/harness hashes, and exact trace scripts.
Compare recorded artifacts only when these inputs and settings are compatible.
Host load, CPU frequency scaling, compiler changes, and kernel changes can all
affect results. A decrease in elapsed time accompanied by increased loss should
not be treated as a successful optimization.

## CI

`.github/workflows/runtime-perf-regression.yml` builds release base/head binaries
and runs them sequentially on the same runner with the head benchmark harness.
It runs on relevant pull requests, weekly, and on manual dispatch. Pull requests
compare against their base SHA; scheduled/manual runs default to `origin/main~1`.
Manual dispatch accepts a different baseline ref and optional threshold
enforcement. Reports and raw JSON are attached to each run for 90 days, and the
Markdown comparison appears in the job summary.

Hosted runners report regressions without failing solely on performance
thresholds by default; measurement or workload failures still fail the job.
Use repeated measurements on a controlled host before adopting strict gates.
The same-host paired comparison reduces drift but does not eliminate noise.

Test the harness without eBPF privileges:

```bash
python3 -m unittest discover -s scripts/runtime-perf -v
```
