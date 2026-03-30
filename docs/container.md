# Container Environments

This document explains how GhostScope behaves in container environments, which scenarios matter, and what the current implementation limits are.

## Topic 1: PID Namespaces and `-p` Mode

PID namespaces are the core source of complexity in container environments, so this section focuses on that first.

This document assumes a local CLI workflow: GhostScope runs in the same environment where you actually invoke `ghostscope -p`. The deployment-scope discussion for running GhostScope itself inside a container is collected later in Topic 4.

### The Most Important Rule

When using `ghostscope -p <PID>`, the rule is simple:

Enter the PID as seen in the same environment where you run `ghostscope -p`, for example from `ps`, `top`, or `pgrep`.

In other words:

- If you run `ghostscope -p` on the host, enter the PID you see on the host.
- If you run `ghostscope -p` inside a container, enter the PID you see inside that container.

Users should not manually convert between "host PID" and "container PID". GhostScope is responsible for translating the user input into the internal PID meanings it needs.

### Why Containers Make This More Complicated

PID namespaces allow the same process to have multiple PIDs at the same time.

Typical example:

- The host sees a process as `81234`
- A container sees the same process as `17`

Both are correct. They are just different views of the same process.

GhostScope depends on two kinds of information:

- userspace `/proc/<pid>/...`
- kernel events and eBPF PID filtering

These two sources do not always speak the same PID language, so container scenarios require extra PID mapping logic.

### PID Terms Used in This Document

For clarity, this document uses the following names:

- `input_pid`
  The PID entered by the user when running `ghostscope -p`, meaning the PID visible in that command's current environment.
- `proc_pid`
  The PID visible in GhostScope's current userspace `/proc` view, and the PID that can be used to read `/proc/<pid>/maps`.
- `host_pid`
  The PID of the same target process in the host / initial PID namespace. Traditional `bpf_get_current_pid_tgid()` uses this PID view as well.
- `container_pid`
  The PID of the same target process in the innermost / target PID namespace view that GhostScope can resolve, usually the tail of `NSpid` when that mapping is explicit. In host-only or shared-PID cases it often collapses to the same numeric value as `host_pid`, so it is not always a distinct extra PID.
- `pid_filter`
  This term is only relevant in `-p` mode. After the user enters `ghostscope -p <PID>`, GhostScope resolves the internal PID views it needs and then installs an eBPF-side filter that keeps runtime events associated with that original `input_pid`. The purpose of `pid_filter` is to make sure GhostScope still filters the process the user intended, even when container PID namespaces mean the userspace-visible PID and the kernel-side PID view are not expressed the same way. In simpler cases this behaves like host-view TGID filtering; in namespace-aware cases it behaves more like "the target PID in a specific PID namespace".
- `event_pid`
  The PID carried by runtime kernel events. GhostScope has a process-lifecycle monitoring pipeline that listens for `exec`, `fork`, and `exit` events, and this is the PID that pipeline sees first. In the current implementation, `event_pid` is populated from `bpf_get_current_pid_tgid() >> 32`, so it reflects the TGID in the host / initial PID namespace view. When the event comes from a particular target process, it will usually align with that process's `host_pid`, but it cannot directly replace `proc_pid` for accessing the current `/proc` view or for cleaning caches keyed by `proc_pid`.

From a product perspective, users only need to care about `input_pid`. The other PID values are internal views that GhostScope maintains for `/proc` access, eBPF filtering, and cleanup.

### One Important Fact About the Current Implementation

The current runtime environment detection in the code, which classifies the environment as `container`, `host`, or `unknown`, is about **GhostScope itself**, not about whether the target process runs in a container.

This means:

- User-facing docs need to describe the rule from the user's perspective: enter the PID visible where you run `ghostscope -p`.
- Implementation analysis still needs to care about which PID namespace GhostScope itself is in, because that affects `/proc` visibility, helper selection, and whether fallback behavior is safe.

So this document distinguishes between:

- user-facing scenario semantics
- implementation-level technical differences caused by GhostScope's own runtime environment

### Scenario Matrix

The main scenarios can be described using two axes: where GhostScope runs, and where the target process runs.

#### Scenario 1: GhostScope on the Host, Target Also on the Host

This is the simplest case.

- The user enters a host-visible PID.
- `input_pid`, `proc_pid`, and `host_pid` are usually the same.
- No extra PID-namespace mapping is involved.

#### Scenario 2: GhostScope on the Host, Target in a `--pid=host` Container

This is very close to scenario 1 because the container shares the same PID namespace as the host.

- The user still enters a host-visible PID.
- The PID seen inside the container matches the host PID.
- `input_pid`, `proc_pid`, and `host_pid` are still usually the same.
- Even if `bpf_get_ns_current_pid_tgid` is unavailable, GhostScope can still safely use host-view PID filtering as long as the target remains in the initial PID namespace.

The key point is that although the process is "inside a container", it still belongs to the host PID namespace from a PID-semantics perspective.

#### Scenario 3: GhostScope on the Host, Target in a Private PID-Namespace Container

This is the most important container PID scenario for the current implementation.

- The user runs GhostScope on the host, so the input is the host-visible PID.
- The container has another namespace-local PID for the same target.
- The same target process has both a `host_pid` and a container-local PID.

Common observations in this case:

- GhostScope's `/proc` access is closer to the host view.
- Kernel events are also usually expressed using host / initial PID namespace PIDs.
- If the script uses `$pid/$tid`, or if helper support is unavailable and GhostScope must consider fallback behavior, the difference between host PID and container-local PID becomes visible.
- In this case, `$input_pid` still reflects the host-side `-p` input value, `$host_pid` still reflects the host PID view, and `$pid/$tid` are closer to the target PID namespace view.

This is the class of scenarios that the current implementation primarily tries to support and reason about.

#### Scenario 4: GhostScope in a `--pid=host` Container, Target on the Host or in Another Host-PID-Namespace Process

From a PID-semantics perspective, this is very similar to scenarios 1 and 2.

This scenario is listed mainly to show that GhostScope being inside a container does not automatically mean the PID language has changed.

- GhostScope runs in a container, but the PID view it sees is still the host view.
- The PID entered in that container shell is usually already the host PID.
- The `/proc` view is still close to the host.

What changes here is mostly the answer to "does GhostScope itself look container-like?", not whether the PID values themselves need translation.

#### Scenario 5: GhostScope in a Private PID-Namespace Container, Target in the Same PID Namespace

Here, the user runs GhostScope inside the container, so the input is the container-visible PID.

This scenario is included because it explains what changes once GhostScope and the target share the same private PID namespace.

- `input_pid` usually equals the container-visible `proc_pid`.
- `host_pid` may differ.
- If GhostScope needs to line up with kernel events or host-side PID semantics, explicit PID mapping is required.

From the user's perspective, the rule is still the same: enter the PID visible where you run the command. But GhostScope's internal implementation is much more complex here than in host-side scenarios.

#### Scenario 6: GhostScope in a Private PID-Namespace Container, Target in a Descendant / Nested Private PID Namespace

This is the "outer container -> child container" case that sits between scenarios 5 and 7.

The important difference from scenario 5 is that GhostScope and the target do not share the exact same PID namespace, but the target is still visible from GhostScope's current `/proc` view because the target lives in a descendant namespace.

- The user still runs GhostScope in the outer container, so `input_pid` is the PID visible from that outer container.
- `proc_pid` is still usually the same as that outer-container-visible PID.
- The target may also have a different innermost PID in the child container, so `container_pid` can differ from both `input_pid` and `proc_pid`.
- If GhostScope uses namespace-aware PID filtering here, the comparison target is no longer "the current `/proc` PID view"; it needs the target PID in the target's own innermost namespace.

This scenario is now a separately validated `-p` path: GhostScope still accepts the PID visible from the outer container's `/proc`, but namespace-aware filtering must compare against the target's innermost `container_pid`. If the helper path is unavailable and `NSpid` does not expose a trustworthy host mapping, GhostScope should still fail fast rather than guess.

#### Scenario 7: GhostScope in One Private PID-Namespace Container, Target Outside That PID Namespace

This is one of the most ambiguous and failure-prone cases.

In the current implementation, this scenario is not part of the supported path.

It is mainly useful to explain why GhostScope must not blindly guess PID mappings across namespaces.

Potential problems include:

- The target PID is not visible at all in the current `/proc` view.
- GhostScope may receive some kernel-view events, but cannot reliably map them back to the current namespace's `/proc` path.
- If helpers are unavailable, fallback behavior may be unsafe.

In these cases, GhostScope should fail clearly and early rather than guessing mappings.

### Scenario-to-PID Reference Table

The prose above explains the semantics. The table below turns those same cases into a quick lookup for `-p` mode.

Here, "scenario" always means the relationship between two sides:

- where GhostScope itself is running
- where the observed target process is running

| Scenario | `input_pid` | `proc_pid` | `host_pid` | `container_pid` | `pid_filter` | `event_pid` | Support |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1. Host -> host | Host-visible PID entered on the host | Usually the same as `input_pid` | Usually the same as `input_pid` and `proc_pid` | Usually the same as `host_pid`, because no nested PID namespace is involved | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`, usually the same as `host_pid` | Supported |
| 2. Host -> `--pid=host` container | Host-visible PID entered on the host | Usually the same as `input_pid` | Usually the same as `input_pid` and `proc_pid` | Usually the same as `host_pid`, because the container shares the host PID namespace | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`, usually the same as `host_pid` | Supported |
| 3. Host -> private PID-namespace container | Host-visible PID entered on the host | Usually the same as `input_pid` in the host `/proc` view | Usually the same as `input_pid` and `proc_pid` | Target PID inside the inner namespace; may differ from `host_pid` | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`, usually the same as `host_pid` | Supported |
| 4. `--pid=host` container -> host / shared-PID target | PID entered inside the container shell, which is already host-visible | Usually the same as `input_pid` | Usually the same as `input_pid` and `proc_pid` | Usually the same as `host_pid` | Helper supported: `bpf_get_ns_current_pid_tgid(...).tgid == proc_pid`; helper unsupported: `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`, usually the same as `host_pid` | Supported |
| 5. Private PID-namespace container -> same private PID namespace | Container-visible PID entered inside that container | Usually the same as `input_pid` in the current container `/proc` view | Usually different from `input_pid` and `proc_pid`; corresponds to the first value in `NSpid` | Usually the same as `input_pid` and `proc_pid` when GhostScope and the target share that namespace | Helper supported: `bpf_get_ns_current_pid_tgid(...).tgid == proc_pid`; helper unsupported: if `NSpid` exposes an explicit host mapping, `bpf_get_current_pid_tgid() >> 32 == host_pid`, otherwise fail fast | `bpf_get_current_pid_tgid() >> 32`, usually aligned with `host_pid` rather than `input_pid` | Conditionally supported |
| 6. Private PID-namespace container -> descendant / nested private PID namespace | PID entered inside the current container shell, meaning the PID visible from the current container's `/proc` view, not the child container-local PID | Usually the same as `input_pid` in the current container `/proc` view | Usually different from `input_pid` and `proc_pid`; corresponds to the first value in `NSpid` | Usually different from `input_pid` and `proc_pid`; corresponds to the tail of `NSpid`, often the child container-local PID | Helper supported: `bpf_get_ns_current_pid_tgid(...).tgid == container_pid`; helper unsupported: if `NSpid` exposes an explicit host mapping, `bpf_get_current_pid_tgid() >> 32 == host_pid`, otherwise fail fast | `bpf_get_current_pid_tgid() >> 32`, usually aligned with `host_pid` | Conditionally supported |
| 7. Private PID-namespace container -> target outside that PID namespace | Often not satisfiable because the target is not visible in the current `/proc` view | Often unavailable from the current `/proc` view | Often not stably resolvable from the current view; if it exists, it belongs to a PID view outside the current `/proc` namespace | Unreliable or not visible from the current namespace | No stable comparison is installed; GhostScope should fail fast | No stable `event_pid` to `proc_pid` mapping can be assumed | Unsupported |

Notes:

- `pid_filter` only exists in `-p` mode. Its job is to keep eBPF-side runtime events associated with the original `ghostscope -p <PID>` input.
- `container_pid` here means "the tail of `NSpid` when GhostScope can resolve one". It is often not a distinct extra value in host-only or shared-PID cases.
- When the table says `bpf_get_current_pid_tgid() >> 32 == host_pid`, GhostScope is comparing the current event's host-view TGID against the resolved target `host_pid`.
- When the table says `bpf_get_ns_current_pid_tgid(...).tgid == proc_pid`, GhostScope is comparing the current event's TGID in the target PID namespace against the resolved target `proc_pid`.
- `event_pid` always comes from `bpf_get_current_pid_tgid() >> 32`, so it stays aligned with host-view TGID semantics even when `pid_filter` uses namespace-aware matching.
- Values marked "usually" or "may differ" still depend on the actual `/proc` view, `NSpid`, and helper availability at runtime.

### Current `-p` Decision Flow

The scenario matrix above is meant to explain semantics. The current implementation does not literally decide "this is scenario 1" or "this is scenario 3" first. Instead, it infers behavior from a sequence of signals.

#### 1. First Verify That the User Input Matches the Contract

Depends on:

- `/proc/<input_pid>` in the current environment

Precondition:

- `input_pid` is already defined to mean "the PID visible where `ghostscope -p` is being run".

Result:

- If `/proc` does not contain that PID at all, GhostScope fails immediately.
- This means the input does not satisfy the `-p` contract. GhostScope does not try to guess some other PID across namespaces.

This removes obviously invalid inputs early, including scenario-7-like cases where the target is simply not visible in the current `/proc` view.

#### 2. Check Whether GhostScope Itself Looks Like It Runs in a Container

Depends on:

- `/.dockerenv`
- `/run/.containerenv`
- `/proc/1/cgroup`

Result:

- Produces `container-likely`, `host-likely`, or `unknown`

This is about **GhostScope itself**, not the target process. It mainly influences later conservative behavior, for example whether GhostScope should fail earlier when helpers are unavailable.

`container-likely` should be understood as a risk signal:

- It means GhostScope's current environment may involve PID-namespace view differences, so later PID inference must be more conservative.
- It does not prove that the target process is in a container.
- It does not prove whether `input_pid` is already equal to `host_pid`.

Even when GhostScope runs in the host PID view, the relationship is not a mechanical identity:

- If GhostScope runs in the host PID view, the user-entered `input_pid` is usually the PID seen in the host's `/proc`.
- But the target process may still run inside a private PID-namespace container, so the same target may still have a second container-local PID.

#### 3. Read `NSpid` and PID-Namespace Information for the Target

Depends on:

- `NSpid` in `/proc/<input_pid>/status`
- `/proc/<input_pid>/ns/pid`

These pieces of data mean different things:

- `NSpid`
  A PID chain showing the same process in multiple PID namespaces. For the scenarios GhostScope currently cares about, it is often enough to think of it as "the host-side PID and the container-side PID of the same process".
- `/proc/<pid>/ns/pid`
  The PID namespace object that the process currently belongs to. GhostScope reads its `dev` and `inode` not to get another PID, but to uniquely identify which PID namespace this is.

Example:

- If `/proc/<pid>/status` contains `NSpid: 81234 17`
- then it can be approximated as:
  - `81234` in the host / initial PID namespace
  - `17` in an inner PID namespace

The important distinction is:

- `NSpid` describes PID-number relationships for the same process across different views
- `/proc/<pid>/ns/pid` describes which PID namespace object the process belongs to

Result:

- `proc_pid`
  The PID used for `/proc/<pid>/maps` in the current `/proc` view. In the current implementation, this is usually the same as `input_pid`.
- `host_pid`
  The first element of `NSpid`, corresponding to the host / initial PID namespace.
- PID namespace `inode` / `dev`
- Whether `NSpid` exposes an explicit mapping

These outputs are used for different purposes:

- `proc_pid`
  For userspace access to `/proc/<pid>/maps`, `/proc/<pid>/status`, and similar files
- `host_pid`
  To align with the PID view returned by traditional `bpf_get_current_pid_tgid()`
- PID namespace `dev/inode`
  To pass into `bpf_get_ns_current_pid_tgid()`, telling eBPF to interpret the current task from that PID-namespace view
- Whether `NSpid` is explicit
  To decide whether fallback to host-side PID filtering is still reliable when helpers are unavailable

The most important thing about this step is not "we found another PID", but that GhostScope uses it to answer two questions:

- Is the PID seen in the current `/proc` view the same as the PID in the host / initial PID namespace?
- If not, which PID-namespace view should eBPF use when interpreting the current task?

This is the key step for distinguishing scenarios:

- If the target is in the initial PID namespace, the case is usually closer to scenarios 1, 2, or 4.
- If the target is not in the initial PID namespace but is still visible in the current `/proc`, the case is closer to scenarios 3 or 5.
- If `NSpid` is missing or incomplete, later fallback safety becomes much more sensitive.

#### 4. Probe Whether the Kernel Supports the Namespace-Aware Helper

Depends on:

- Whether the kernel supports `bpf_get_ns_current_pid_tgid`

Result:

- If the helper is available, GhostScope can retrieve PID/TGID in the requested PID namespace and perform safer filtering.
- If the helper is unavailable, GhostScope has to rely more on `NSpid`, current `/proc` visibility, and other namespace information.
- Traditional `bpf_get_current_pid_tgid()` returns `pid/tgid` in the kernel's default PID view. In container terms, this can be approximated as the host / initial PID namespace view rather than container-local PID values.

This step decides whether GhostScope can perform namespace-aware PID filtering directly.

#### 5. Choose a PID Filtering Strategy

Depends on:

- GhostScope's own runtime-environment classification
- Whether `NSpid` provides an explicit host mapping
- target PID-namespace information
- helper availability

Result:

- In the current implementation, GhostScope effectively chooses between two filter forms: a host-view TGID filter and a namespace-aware TGID filter.
- If the helper is available and GhostScope concludes that namespace-aware filtering is actually needed for this `-p` run, it uses the namespace-aware form.
- If namespace-aware filtering is not considered necessary for the current case, GhostScope may still keep using host-view PID filtering even when the helper is available.
- If the helper is unavailable, GhostScope considers falling back to host-view PID filtering.
- If the target is still in the initial PID namespace, for example in a `--pid=host` case, then host-view PID filtering is still safe even without the helper.
- GhostScope only fails fast when the environment looks container-like, the helper is unavailable, `NSpid` does not provide an explicit mapping, and the target is not in the initial PID namespace.

This is exactly where scenarios 2 and 3 tend to diverge:

- A `--pid=host` container still looks container-like, but the target may remain in the initial PID namespace.
- A private PID-namespace container usually needs more explicit namespace information or helper support.

#### 6. Keep Kernel-Event PID and `/proc` PID Aligned at Runtime

Depends on:

- `event_pid` from kernel events
- `proc_pid` from the current `/proc` view

Result:

- When inserting offsets, caching per-PID state, and cleaning up on exit, GhostScope must keep using the same PID-key semantics.
- If it writes using `proc_pid`, then it must be able to recover that same `proc_pid` later during cleanup, otherwise stale cache or stale offset entries remain behind.

This step does not decide which scenario the run belongs to, but it determines whether the PID meaning inferred earlier stays consistent throughout runtime.

### Common Misconceptions

#### Misconception 1: Users Should Always Enter the Host PID

No.

The correct rule is:

- Enter the PID visible where you are running `ghostscope -p`.

Do not manually convert it into a host PID. Do not manually convert it into a container-local PID either.

#### Misconception 2: If Something Runs in a Container, Its PID Must Differ from the Host

No.

If the container uses `--pid=host`, then the container and the host already share the same PID namespace.

#### Misconception 3: If GhostScope Knows the Target Runs in a Container, It Can Always Infer the Right Mapping

No.

What actually determines whether the mapping is reliable is:

- GhostScope's current PID-namespace view
- whether the target is visible in the current `/proc`
- whether the helper is available
- whether `NSpid` provides enough explicit mapping information

## Topic 2: `-t` Mode and sysmon

### What sysmon Is

`sysmon` is GhostScope's runtime pipeline for tracking process lifecycle state.

It mainly listens for:

- `exec`
- `fork`
- `exit`

In the current implementation, `-p` mode does not start this pipeline. `sysmon` mainly serves `-t` mode, especially when GhostScope needs to keep module offsets, allowlists, and exit cleanup up to date after the target starts.

### Which PID View sysmon Depends On

sysmon's kernel events come from tracepoints. The `event_pid` in those events is not read from the current `/proc` view. It is populated from `bpf_get_current_pid_tgid() >> 32`.

This means:

- `event_pid` aligns with the TGID in the host / initial PID namespace view
- in `-t` semantics, it aligns with the host / initial PID namespace PID language, not the current `/proc` view
- it cannot directly replace `proc_pid`

But the userspace side of sysmon still needs `proc_pid` for:

- reading `/proc/<pid>/maps`
- prefilling module offsets
- cleaning caches and pinned map entries keyed by `proc_pid`

So in `-t` mode, sysmon actually depends on two PID languages at the same time:

- `event_pid` on the kernel-event side
- `proc_pid` on the current `/proc` side

### Why `-t` Becomes Problematic in Containers

If GhostScope and the target stay in the same PID namespace, or if the current `/proc` view can reliably map `event_pid` back to the same `proc_pid`, then the pipeline can still work.

But when GhostScope and the target do not share the same PID view, problems appear:

- sysmon receives a host-view `event_pid` first
- userspace can only access the current environment's `proc_pid`
- those two values are not guaranteed to be the same

This directly affects:

- whether GhostScope can reliably find the right `/proc/<pid>/maps` after `exec` / `fork`
- whether offset insertion and exit cleanup still use the same PID key

So the core `-t` problem in cross-PID-namespace cases is not "did GhostScope receive events?" but:

- even when events arrive, the relationship between `event_pid` and `proc_pid` may not be recoverable in a stable way

Once that mapping cannot be recovered, the sysmon lifecycle pipeline breaks.

### Current Conclusion for `-t`

Today, `-t` can be understood in two broad categories:

- same-PID-namespace or mostly aligned PID-view cases, where sysmon is much more likely to work as intended
- cross-PID-namespace cases, especially private PID-namespace cases, where sysmon is not currently reliable; the weakness is not event collection itself, but the alignment between `event_pid` and `proc_pid`

That is why:

- `event_pid` can be aligned with the host / initial PID namespace view
- but it cannot directly replace `proc_pid`
- and `-t` cannot simply reuse the same PID semantics as `-p` in container-heavy environments

Current container e2e still does not truly cover the `-t` lifecycle-maintenance problem where GhostScope runs on the host and the target runs inside a private PID-namespace container. But it now includes both a dedicated `-p` validation path and a full container-e2e CI topology entry for the "outer container -> descendant / nested PID namespace target" case.

## Topic 3: WSL

GhostScope does not currently support WSL as a runtime target.

The problem is that WSL's PID semantics do not line up with GhostScope's assumptions:

- `bpf_get_current_pid_tgid()` may report a PID/TGID that does not match the PID visible inside the WSL distro.
- `bpf_get_ns_current_pid_tgid()` is also not a general fix for this on WSL.
- In current WSL + Docker container-topology validation, GhostScope teardown also hit kernel perf cleanup hangs after timeout, with stacks including `perf_event_detach_bpf_prog`, `perf_event_free_bpf_prog`, and `__fput`.

So this is currently a platform limitation, not a normal container-mapping case that GhostScope can reliably work around.

Relevant background:

- [WSL issue #12408](https://github.com/microsoft/WSL/issues/12408)
- [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115)

## Topic 4: Deployment Scope When GhostScope Itself Runs in a Container

GhostScope does not currently plan to support "run GhostScope in a container and observe arbitrary processes on the machine" as a deployment mode.

The main reason is observability scope:

- If GhostScope itself runs inside a container, it may simply be unable to see processes that live outside that container's PID namespace.
- The main exception is when GhostScope runs in a `--pid=host` container, because that container shares the host PID namespace.

So today's container support should be understood more narrowly:

- GhostScope can run on the host and observe target processes that happen to run inside containers on that host. This is the primary container story.
- GhostScope can run inside a container and observe processes in that same container PID namespace.
- Descendant / nested PID namespaces that remain visible from that container are still within the intended scope, and `-p` now has both a dedicated "outer container -> child container target" validation path and a full container-e2e CI topology. `-t` lifecycle maintenance is still a separate limitation.
- GhostScope can run inside a `--pid=host` container and observe host-visible processes because the PID view is shared with the host.

## Current Implementation Limitations Summary

The following limitations used to be scattered in `limitations.md`. They are now collected here:

- In `-p` mode, GhostScope currently decides in this order: runtime environment detection -> `NSpid` parsing -> helper probe -> filter strategy selection.
- The current implementation does not switch to namespace-aware PID filtering solely because helper `bpf_get_ns_current_pid_tgid` (id 120) is available.
- Instead, in `-p` mode GhostScope currently chooses between host-view TGID filtering and namespace-aware TGID filtering based on runtime-environment classification, resolved PID mapping, and helper availability together.
- If the helper is unavailable, GhostScope falls back to host PID mapping derived from `NSpid`, but only when that mapping is explicit enough to be trusted.
- `-p` must refer to a PID visible in the current PID namespace. If the PID is not visible in the current `/proc`, GhostScope fails immediately rather than guessing across namespaces.
- The current implementation is intentionally stricter in one more case: in a container-like environment, if the helper is unavailable and `NSpid` cannot provide an explicit host mapping, GhostScope fails instead of guessing, unless the target remains in the initial PID namespace.
- Scenario 6 (GhostScope in a private PID namespace container, target in a descendant / nested private PID namespace) is now separately validated for `-p`, and it is also part of the full container-e2e CI matrix. In particular, namespace-aware PID filtering must distinguish the current `/proc` PID view from the target's innermost `container_pid`; when that mapping cannot be established safely, GhostScope still fails fast.
- Scenario 7 (GhostScope in one private PID namespace, target outside that namespace) is not currently supported. `-p` should fail rather than attempting to guess a cross-namespace PID mapping.
- In container PID-namespace environments, if the helper is unavailable, `$pid/$tid` in scripts may reflect host-namespace values rather than the PID visible inside the container.
- `-t` depends on sysmon to maintain runtime process lifecycle state. sysmon's `event_pid` comes from `bpf_get_current_pid_tgid() >> 32` and aligns with host-view PID semantics. In cross-PID-namespace cases, alignment between `event_pid` and `proc_pid` is not currently reliable, so `-t` has a structural limitation in those scenarios.

These limitations do not change the user contract defined earlier. They describe what the current implementation can support reliably, and where it will deliberately refuse to guess.

## Other Related Docs

- Basic `-p` configuration entry points and rules: [configuration.md](configuration.md)
- `$pid/$tid` behavior under container PID namespaces: [scripting.md](scripting.md)
- A shorter limitations summary: [limitations.md](limitations.md)
