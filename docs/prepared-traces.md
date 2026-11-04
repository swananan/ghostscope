# Prepared trace bundles

Prepare a trace once, then attach the saved eBPF programs to a running process
without repeating DWARF parsing or LLVM code generation:

```bash
ghostscope prepare -t /path/to/app --script-file trace.gs -o trace.gsb
sudo ghostscope run-bundle trace.gsb -p <PID>
```

`prepare` runs as an ordinary user. It reads the target and its debug information,
resolves the script, and writes a new bundle. It does not probe BPF kernel
capabilities, load BPF programs, attach uprobes, start sysmon, or create bpffs pins.
An existing output file is never overwritten. Compilation must succeed for every
resolved target; partial compilations are not published as bundles.

`run-bundle` verifies the bundle format, GhostScope version, native architecture,
target file SHA-256, module cookie, and the target's executable mapping in the
specified process. It then checks kernel capabilities, initializes runtime module
offsets, and attaches the saved probes. Event decoding, output-loss reporting,
and signal handling use the normal CLI runtime. There is no fallback to DWARF
loading or recompilation.

## First milestone scope

- CLI scripts targeting one executable or shared-library module in a host process.
- Process-scoped multi-uprobe support is required on the runtime kernel, including
  correct coverage of worker threads. Preparation does not require this support
  on its own kernel.
- `bt` / `backtrace`, including nested uses, are rejected during preparation.
- `$input_pid` is unavailable during preparation. `$pid` and `$tid` are read at
  probe time and use host PID semantics. Container PID namespaces are not yet
  supported by `run-bundle`.
- RingBuf is the default event transport. To prepare for PerfEventArray, use
  `--config` with `[ebpf].force_perf_event_array = true`. Sleepable uprobes can
  also be selected in the preparation config and require compatible runtime
  capabilities. The consumer never silently changes the compiled backend.

## Debug files, identity, and configuration

`prepare` accepts `--config` and `--debug-file`, using the normal debug-file
matching rules. The bundle stores its script, compilation configuration, probe
attachment offsets, eBPF objects, and event-decoding type/context tables. Debug
files and source files are not required by `run-bundle`.

The target binary must remain byte-for-byte identical. In particular, strip or
otherwise transform the binary **before** preparation, not afterwards. Removing
a separate debug file after preparation is supported. To use an identical target
at another location, pass `run-bundle ... -t /new/path/to/app`; its module cookie
must also match. A target without an ELF build ID must retain its filesystem
identity, so copying it to a different inode requires preparing another bundle.

Bundles use a versioned JSON format and are limited to 64 MiB. Treat a bundle as
executable code: run only artifacts from a trusted preparation workflow. The
identity checks establish which target it was prepared for, not who produced it.
Reprepare after changing the target, script, compilation configuration, or
GhostScope version. Bundle schema changes also require repreparation.

The runtime uses the saved eBPF configuration rather than the current user's
configuration file. `--script-output pretty|plain|jsonl` and `--no-status` control
runtime presentation.

## Measuring startup cost

Preparation reports its compilation time; `run-bundle` reports time to attachment
unless `--no-status` is set. Target hashing, ELF mapping discovery, kernel
capability checks, and BPF verification/loading still occur at runtime. This is
not a zero-cost attach path.

The `prepared_bundle_execution` e2e tests compare normal and prepared startup on
a small C fixture with separate DWARF, verify reuse across PIDs and worker-thread
coverage, and remove the debug file before running the bundle. Timing is reported
without a brittle pass/fail threshold. Measure representative production binaries
before extrapolating the speedup to large debug-info workloads.
