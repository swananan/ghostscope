# Design Guarantees and Trust Model

GhostScope turns live machine state into source-aware observations. This
document defines the conditions under which those observations are intended to
be trustworthy and the invariants that the implementation must preserve.

This is a normative design contract. The [architecture](architecture.md)
describes how the current implementation enforces it, while
[limitations](limitations.md) describe behavior outside the supported envelope
or behavior that degrades explicitly. Future guarantees belong in the
[roadmap](roadmap.md), not in this document.

A violation of an invariant inside the supported envelope is a correctness bug,
not a limitation. Early-development status means such bugs may still exist; it
does not permit known unsupported paths to return plausible but unproven data.

## Supported Operating Envelope

- Official release artifacts and correctness testing target Linux x86_64.
  Source code compiling on another architecture does not make that architecture
  supported.
- Source-aware values require DWARF that corresponds to the module being
  traced. Embedded DWARF is read from that module. For separate debug files,
  available `.gnu_debuglink` CRC and Build ID evidence is checked strictly by
  default.
- C has the strongest end-to-end coverage. C++ and Rust currently use a more
  limited, DWARF-layout-oriented model. Language coverage is documented in
  [limitations](limitations.md).
- The kernel must provide the required eBPF, uprobe, and event transport
  facilities, and GhostScope must have permission to use them.

`--allow-loose-debug-match` explicitly opts out of strict separate-debug-file
matching. When enabled, GhostScope warns about the mismatch, but the user has
weakened the evidence behind source-level interpretation. An explicit debug
file for which neither CRC nor a comparable Build ID is available also cannot
be proven identical to the module; the warning makes that a user-supplied trust
decision outside the strict evidence envelope.

## Trust Boundaries

GhostScope relies on the Linux kernel, the eBPF verifier and helpers, the target
module and its compiler-produced DWARF, and process metadata exposed through
`/proc`. It validates and narrows those inputs where it can, but it cannot prove
that a compiler emitted semantically correct DWARF.

An event is a point-in-time observation at a uprobe hit, not a process-wide
atomic snapshot. Registers and the current thread's frame correspond to that
hit. Memory shared with other threads can change while a multi-field event is
being collected.

Read-only also does not mean zero-impact. Linux uprobes install trap points, and
the target thread synchronously pays the uprobe and eBPF work on every hit.
GhostScope avoids debugger-controlled suspension and application-state writes,
but it cannot guarantee unchanged timing.

## Invariants

### SCOPE-1: The supported platform is explicit

**Guarantee.** Official builds and correctness claims are scoped to Linux
x86_64.

**Enforcement.** Release artifacts are built and named for x86_64, and
architecture-specific register, ABI, TLS, and unwind behavior is tested in that
environment.

**Failure boundary.** Other architectures must not be presented as supported
until their platform mappings and end-to-end behavior are implemented and
tested. Accidental compilation is not evidence of support.

### SAFE-1: Observation does not control the target

**Guarantee.** GhostScope exposes no operation that intentionally changes
application-visible variables, memory, or control flow, and it does not suspend
the process for interactive inspection, stepping, or continuation.

**Enforcement.** The script language is observational, generated eBPF programs
use target-read, internal-map, and event-output operations, and the kernel
verifier constrains loaded programs.

**Failure boundary.** Uprobe traps and eBPF execution still perturb scheduling
and latency. A feature that writes target memory or changes control flow would
change this contract and must not be introduced as an ordinary tracing feature.

### IDENT-1: Every observation matches the requested target scope

**Guarantee.** An event must be attributable to the trace and runtime target
scope that produced it. GhostScope must not silently use another PID, module, or
address-space interpretation when the requested one is unavailable.

The startup modes define that scope:

- `-p <pid>` selects a process view and its loaded modules.
- `-t <path>` selects a target-module, multi-process view.
- `-t <path> -p <pid>` resolves trace targets in the selected module and limits
  runtime events to the selected process.

**Enforcement.** Trace IDs, PID/TID metadata, PID filters, PID-namespace-aware
process discovery, module cookies, and runtime module offsets carry identity
through attach, collection, and rendering.

**Failure boundary.** Missing process visibility, an unavailable module
mapping, or an ambiguous target must fail setup or make the dependent semantic
operation explicitly unavailable. It must not fall back to an unrelated scope.

### SEM-1: Source semantics require a complete evidence chain

**Guarantee.** GhostScope renders a source-level value only when it can connect
the target module and probe PC to the applicable DWARF scope, type, location,
and runtime read plan.

The evidence chain is:

```text
target scope -> runtime module -> module-relative PC -> DWARF scope/type/location
             -> typed read plan -> runtime read result -> rendered observation
```

**Enforcement.** Strict debug-file matching, module-aware PC contexts,
ASLR/PIE relocation, lexical and inline scope resolution, typed lowering, and
runtime read status preserve the meaning of each step.

**Failure boundary.** If any step cannot be established, GhostScope must report
an unsupported location, `OptimizedOut`, a read error, `ExprError`, or another
explicit unavailable status. It must not substitute a same-named variable from
another scope, guess an address, or render an unverified value as valid.

### FAIL-1: Known uncertainty is explicit

**Guarantee.** A known inability to compile, attach, read, unwind, parse, or
attribute an observation must remain visible to the user or automation.

**Enforcement.** Setup and lowering failures are errors; runtime expression and
memory failures are structured protocol states; backtraces report complete,
truncated, and stopped states with reasons.

**Failure boundary.** Best-effort behavior may return partial results only when
the missing portion is marked. Logging a warning while emitting an apparently
complete but unsupported value does not satisfy this invariant.

### LOSS-1: Detectable event loss is not silent

**Guarantee.** A successful trace does not imply a lossless event stream. When
the eBPF output helper rejects an event, GhostScope counts the failure per trace
and reports interval and cumulative loss to CLI and TUI users.

**Enforcement.** Generated programs update loss counters when RingBuf or
PerfEventArray output fails. The runtime periodically reads and reports those
counters.

**Failure boundary.** These counters cover kernel output-helper failures. They
cannot identify which events were lost and do not prove the absence of losses
outside that measurement point, such as events before attachment or after
shutdown. Any nonzero report means the corresponding observation interval is
incomplete.

### COST-1: Per-event work is bounded, aggregate impact is workload-dependent

**Guarantee.** Generated eBPF execution, trace-event size, memory reads, and
backtrace depth are subject to verifier-compatible and configurable bounds.
Reaching a semantic or resource bound must reject the trace or produce an
explicit truncation/unavailable state.

**Enforcement.** The compiler applies event-size and read bounds, the verifier
checks eBPF control flow, transports have configured capacity, and DWARF
unwinding uses depth and tail-call budgets.

**Failure boundary.** GhostScope does not promise a fixed total overhead. A
bounded program attached to a hot path can still materially slow the target.
Probe frequency and payload cost must be included in the operator's budget.

## Result States

The invariants imply four distinct outcomes:

| Outcome | Meaning |
|---|---|
| Complete | The requested operation completed within the supported envelope. |
| Explicitly partial | Some requested data is unavailable or truncated, and the event carries that status. |
| Rejected | Setup, compilation, verification, or attachment could not establish the required conditions. |
| Stream incomplete | One or more detectable events were lost; delivered events may still be valid, but the interval is not complete. |

These states must not be collapsed into a generic success path.

## Verification Expectations

Tests are evidence for this contract, not the definition of the contract. The
main evidence currently lives in these areas:

| Invariant | Primary evidence |
|---|---|
| `SCOPE-1` | x86_64 release workflow and platform-specific unit tests |
| `SAFE-1` | Script/compiler operation surface, eBPF helper usage, verifier-backed load tests |
| `IDENT-1` | PID-specific execution tests and container-topology tests |
| `SEM-1` | PC-context, scalar, global, optimized-code, and cross-module fixtures with exact-value oracles |
| `FAIL-1` | Compile-error, `OptimizedOut`, `ExprError`, read-failure, and backtrace-status tests |
| `LOSS-1` | eBPF output-failure counters and CLI/TUI reporting paths; pressure coverage is required when this path changes |
| `COST-1` | Compiler bound checks, verifier-backed loading, configured-depth and deep-backtrace tests |

When a change touches target selection, process identity, module/PC mapping,
DWARF lowering, generated helpers, event protocol, transport, or rendering, its
validation should identify the affected invariant and provide a positive oracle
and a relevant failure-path oracle.

## Documentation Discipline

- Put current, enforced guarantees in this document.
- Put supported-but-degraded cases and unsupported conditions in
  [limitations](limitations.md).
- Put intended future guarantees in the [roadmap](roadmap.md).
- Keep user-facing claims in the README and comparison document no stronger
  than this contract.
- Update the English and Chinese versions together when the contract changes.
