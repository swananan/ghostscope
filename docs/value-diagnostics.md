# Understanding value diagnostics

GhostScope distinguishes an unavailable value, a failed memory read, a display
fallback, and a partial capture. A display note does not mean the trace failed
to attach. Successfully captured fields remain available.

| Output | Meaning | Next step |
| --- | --- | --- |
| `<unavailable: optimized out>` | No recoverable value at this probe location | [Choose another location](#optimized-out) |
| `<unreadable: memory read failed; errno=…; address=…>` | This read failed; possible causes include a page that cannot be faulted in or an invalid address | [Check memory reads; consider sleepable uprobes](#memory-read-failed) |
| `<internal fields: layout unsupported>` | The type's contents could not be interpreted; physical fields are shown | [Check supported layouts](#layout-unsupported) |
| `<internal fields: read plan unsupported>` | Debug information could not describe the required reads | [Inspect the debug information](#read-plan-unsupported) |
| `<truncated: byte limit>` | Only a prefix of the bytes was captured | [Check the byte budget](#byte-limit) |
| `<truncated: element limit>` | The nested sequence reached the configured width | [Check the element limit](#element-limit) |
| `<truncated: capture limit>` | Capture was incomplete; the status alone does not identify which limit | [Check capture limits](#capture-limit) |
| `<not expanded: capture budget>` | Nested capture did not fit; the root display is retained | [Check the nested budget](#capture-budget) |
| `<nested display limits: depth limit; see trace details>` | Some nested types have static display limits | Read the trace's display notes |

## Finding the reason

Read this guide offline from the installed binary:

```bash
ghostscope --value-diagnostics-help
```

Like `--script-help`, this prints the embedded English reference to stdout and
exits without loading configuration, inspecting a target, or requiring eBPF
privileges. The content ships with the binary, so it is also available to LLM
tools without a source checkout or network access.

CLI mode prints static display notes to stderr once per expression/type/reason
in each compiled trace, even with `--no-log` and `--no-status`. TUI mode shows
them in trace creation results and retains them in `info trace <id>`. This also
applies to traces loaded from a saved file. Dry runs report the same static
notes; runtime reads cannot be checked until a probe runs.

A note names the expression and affected path, the type, a stable reason, the
technical detail, and a link to this page. `[]` denotes collection elements;
`::Some.__0` denotes a possible enum payload (field names follow DWARF).
These are **capture-plan limits**:
they do not claim that a collection is nonempty or that a variant is active.
Runtime read errors belong to the actual captured value or child slot.

Normal structs do not need a special adapter. Their ordinary field display is
not itself a failure. Debug logs and `dwarf-tool rust-adapter` remain useful for
deeper investigation, but are not required to see a display fallback.

## optimized-out

`<unavailable: optimized out>` means the selected location has no recoverable
value for that variable. Direct printing can emit this placeholder; using the
variable in arithmetic or taking its address fails during script compilation.

Try a source location where the value is still live. If rebuilding the target
is possible, retain debug information and consider reducing optimization.
Increasing capture limits or enabling sleepable uprobes cannot recover a value
that the compiler removed.

## memory-read-failed

`<unreadable: memory read failed>` means a target-memory read failed on this
event. **The errno alone, including `-EFAULT`, cannot distinguish a page that
cannot be faulted in from an invalid address.** Other possibilities include
inaccessible memory, a value observed during mutation, mismatched debug
information, or incorrect address calculation by GhostScope. This is a runtime
read failure; a static depth-limit note does not explain its cause. Other
successfully captured fields remain useful; the event is not a process-wide
atomic snapshot.

First confirm that the binary and separate debug information match, and that
the probe location and object's lifetime are appropriate. A target pointer may
itself be null, dangling, or changing concurrently even with matching debug
information. **If GhostScope computes an invalid address for an object known
to be valid and live, with matching debug information, that is a GhostScope
bug.** Report the expression, source/probe location, exact output (including
errno and address), binary/debug-file identity, GhostScope version, and a
minimal reproducer when possible. A failed read alone does not establish which
component is responsible.

If the memory is valid but may not be resident, retry the existing command
with **`--sleepable-uprobe`**, or use:

```toml
[ebpf]
sleepable_uprobe = true
```

Sleepable uprobes allow supported reads to fault in pages. They require Linux
5.18+ and RingBuf output. Fixed-length reads use a fault-capable helper;
NUL-terminated reads that use `bpf_probe_read_user_str()` still cannot fault in
pages. This option cannot fix an invalid address, missing DWARF, or an
unsupported type layout.

Enabling it can add probe latency, especially when a read actually faults or
blocks on I/O. The impact may be small for a particular workload, but is not
guaranteed to be small; measure the target's latency and probe frequency.
See [Sleepable Uprobe](configuration.md#sleepable-uprobe) for kernel checks,
output compatibility, and backtrace behavior.

Null-pointer dereference, address-computation failure, and unavailable process
offsets have their own messages. Do not assume that enabling sleepable uprobes
resolves those conditions.

## layout-unsupported

The type matched a known adapter, but its target DWARF layout did not satisfy
the adapter's checks. GhostScope retains the ordinary field representation.
These are implementation fields, not the semantic contents of a string or
collection. Increasing a capture budget will not make this layout supported.

Check [Rust value rendering](scripting.md#rust-value-presentation). For a report,
include the type, rejection detail, target rustc version, matching debug
information, and a minimal reproducer. If ordinary DWARF capture also fails,
the compilation error includes the adapter's rejection report.

## read-plan-unsupported

The required dependent type, pointer target, projection, width, or alignment
could not be resolved from the target debug information. The note includes the
available technical reason. Check that the target's matching, full debug
information is available; report a reproducible unsupported case. Raising
memory limits or enabling sleepable uprobes does not supply missing DWARF.

## byte-limit

A string or byte-string capture returned only a prefix. Check
`[ebpf].mem_dump_cap` (default 256 bytes per indirect argument). Nested values
share this budget with their root, metadata, and sibling values, so a child
can receive fewer bytes than that setting. An omitted payload instead reports
the broader `capture limit`, because it could also reflect the event budget.

## element-limit

The captured nested sequence reached `value_adapters.max_sequence_elements`.
Only the displayed elements were captured. Print a specific element or increase
that setting if more elements are needed; the shared byte budget still applies.

## capture-limit

The result is partial. The available runtime status does not always distinguish
byte, element, sparse-bucket, tree-node, and total-event limits. GhostScope does
not invent a more specific cause when the capture metadata cannot prove it.

Check `[ebpf].mem_dump_cap`, `[ebpf].max_trace_event_size`, and
`[value_adapters].max_sequence_elements` (default 4). The last setting limits
nested sequence elements or hash buckets; sparse buckets may contain fewer
actual entries. See [Value Adapter limits](configuration.md#value-adapter-limits).
Increase only the relevant limit: larger captures can increase eBPF program
size, event size, and probe overhead.

## depth-limit

The semantic planner stopped expanding nested contents at
`[value_adapters].max_nesting_depth` (default 4). The note identifies the path
beyond the limit. A plain struct or enum payload also consumes a semantic edge.
This is not a memory-read error and does not imply that the root value is
missing. Inspect a shallower expression or increase the limit deliberately.
The separate native DWARF formatting limit reports `<MAX_DEPTH_EXCEEDED>`.

## recursive-type

The planner encountered a repeated DWARF type on the current expansion path.
It keeps the existing representation rather than following the type
indefinitely. This concerns the type graph; it does not prove that runtime
objects form a cycle. Raising the nesting limit does not disable this guard.
Inspect a specific field or explicitly dereference a known pointer instead.

## capture-budget

The compiled nested capture could not fit within the shared byte budget.
The root display or other captured fields remain, and the note identifies the
affected path when available. Print the field separately, reduce requested
nesting or collection width, or increase `ebpf.mem_dump_cap` deliberately.
This limitation is determined before the probe runs.
