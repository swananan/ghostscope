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
every module's file SHA-256 and cookie before attaching any probe. With `-p`, it also verifies the primary target's
executable mapping in the specified process. It then checks kernel capabilities,
initializes runtime module offsets, and attaches the saved probes. Event decoding,
output-loss reporting, and signal handling use the normal CLI runtime. There is no fallback to DWARF
loading or recompilation.

## Target scope

- `run-bundle trace.gsb -p PID` traces one existing host process, using the
  prepared module paths unless overrides supply identical files elsewhere.
- `run-bundle trace.gsb -t /path/to/app` attaches to all prepared modules without
  a PID filter. It traces existing and future processes using any of those files,
  including worker threads, and stays attached across process restarts.
  No target process needs to exist when the tracer starts.

Specify at least one of `-p` or `-t`. Target mode reuses normal `-t` lifecycle
tracking and runtime module-offset maintenance; the bundle's saved
`enable_sysmon_for_target` setting controls that monitor. It still performs no
DWARF parsing or LLVM compilation. Attachment follows the validated file inode;
replacing the file at that path requires preparing and attaching again.

## Multiple modules

List additional executables or shared libraries explicitly; preparation does not
automatically scan dependencies or require a running process:

```bash
ghostscope prepare -t /build/app \
  --module /build/libfoo.so --module /build/libbar.so \
  --script-file trace.gs -o trace.gsb
sudo ghostscope run-bundle trace.gsb -t /build/app
# Or restrict every probe to one process:
sudo ghostscope run-bundle trace.gsb -p <PID>
```

Function and source patterns resolve across the selected modules. Same-named
functions in different modules produce separate probes with their own variable
contexts. Use `trace libfoo.so:handle_request { ... }` to select just one module,
or `trace libfoo.so:"ns::Handler::run(int)" { ... }` for a quoted function name.
The module must match a full path or unique suffix among the prepared modules;
unknown or ambiguous selectors fail. Bare addresses refer to the primary `-t` module; use `libfoo.so:0x1234`
for a module-qualified address. A bundle supports up to 64 modules. Duplicate
module identities are rejected, including copies with the same build ID.

With `-p`, the primary module must already be mapped; additional libraries can
be loaded later with `dlopen`. Without `-p`, each prepared module is tracked
independently, including in processes that do not map the primary module.
The saved sysmon settings must allow module tracking for late mappings and new
processes to receive runtime offsets.

Paths may be relocated independently:

```bash
sudo ghostscope run-bundle trace.gsb -t /deploy/app \
  --module-path libfoo.so=/deploy/libfoo.so \
  --module-path libbar.so=/deploy/libbar.so
```

The left side of `--module-path MODULE=PATH` matches a saved full path or a unique
path suffix. Ambiguous, unknown, or repeated overrides fail. `-t` overrides the
primary path; without overrides, saved paths are used. All files must pass
identity checks, including modules not mapped yet.

## Current scope

- CLI scripts targeting executable and shared-library modules in host processes.
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
matching rules. `--debug-file` applies to the primary module; additional modules
use normal debuglink, configured search paths, and debuginfod discovery.
The bundle stores its module identities, script, compilation configuration, probe
attachment offsets, eBPF objects, and event-decoding type/context tables. Debug
files and source files are not required by `run-bundle`.

Every module binary must remain byte-for-byte identical. In particular, strip or
otherwise transform binaries **before** preparation, not afterwards. Removing
a separate debug file after preparation is supported. To use an identical target
at another location, pass `run-bundle ... -t /new/path/to/app`; its module cookie
must also match. A target without an ELF build ID must retain its filesystem
identity, so copying it to a different inode requires preparing another bundle.

Bundles use a versioned JSON format and are limited to 64 MiB. Treat a bundle as
executable code: run only artifacts from a trusted preparation workflow. The
identity checks establish which target it was prepared for, not who produced it.
Reprepare after changing the target, script, compilation configuration, or
GhostScope version. The multi-module schema is version 2; version 1 bundles must
be prepared again, including single-module bundles.

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
