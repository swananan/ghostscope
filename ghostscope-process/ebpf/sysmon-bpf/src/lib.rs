#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_pidns_info,
    macros::{btf_tracepoint, map, raw_tracepoint, tracepoint},
    maps::{Array, HashMap, PerfEventArray, RingBuf},
    programs::{BtfTracePointContext, RawTracePointContext, TracePointContext},
    EbpfContext,
};

// ABI note:
// SysEvent is a shared event layout with userspace (see ghostscope-process/src/sysmon.rs).
// For now it is defined in two places to keep the BPF build isolated from the workspace.
// Keep repr(C), field order and sizes identical on both sides.
// Current layout (8 bytes): { tgid: u32, kind: u32 }.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SysEvent {
    pub tgid: u32,
    pub kind: u32, // 1=Exec,2=Fork,3=Exit,4=MapChange
}

const SYS_EVENT_EXEC: u32 = 1;
const SYS_EVENT_FORK: u32 = 2;
const SYS_EVENT_EXIT: u32 = 3;
const SYS_EVENT_MAP_CHANGE: u32 = 4;

const SYS_EVENT_MASK_EXEC: u32 = 1 << 0;
const SYS_EVENT_MASK_FORK: u32 = 1 << 1;
const SYS_EVENT_MASK_EXIT: u32 = 1 << 2;
const SYS_EVENT_MASK_MAP_CHANGE: u32 = 1 << 3;

#[map(name = "sysmon_events")]
static SYS_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // 1MB

#[map(name = "sysmon_events_perf")]
static SYS_EVENTS_PERF: PerfEventArray<SysEvent> = PerfEventArray::new(0);

// Allowed pids for -t mode: fork/exit events are only emitted when pid is present.
#[map(name = "allowed_pids")]
static ALLOWED_PIDS: HashMap<u32, u8> = HashMap::pinned(16384, 0);

// Optional comm filter for exec events (truncated basename, null-terminated).
#[map(name = "target_exec_comm")]
static TARGET_EXEC_COMM: Array<[u8; 16]> = Array::pinned(1, 0);

#[map(name = "sysmon_event_mask")]
static SYSMON_EVENT_MASK: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "sysmon_watched_pid")]
static SYSMON_WATCHED_PID: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "sysmon_watched_pid_ns_dev")]
static SYSMON_WATCHED_PID_NS_DEV: Array<u64> = Array::with_max_entries(1, 0);

#[map(name = "sysmon_watched_pid_ns_ino")]
static SYSMON_WATCHED_PID_NS_INO: Array<u64> = Array::with_max_entries(1, 0);

fn write_event<C: EbpfContext>(ctx: &C, ev: SysEvent) {
    if SYS_EVENTS.output::<SysEvent>(&ev, 0).is_err() {
        SYS_EVENTS_PERF.output(ctx, &ev, 0);
    }
}

#[inline(always)]
fn emit_exec<C: EbpfContext>(ctx: &C) -> u32 {
    if !event_enabled(SYS_EVENT_MASK_EXEC) {
        return 0;
    }
    let pid = current_filtered_tgid();
    if pid == 0 {
        return 0;
    }
    if !exec_comm_matches() {
        return 0;
    }
    // Emit exec only when filter (if present) passes; userspace handles mapping and allowlist.
    let ev = SysEvent {
        tgid: pid,
        kind: SYS_EVENT_EXEC,
    };
    write_event(ctx, ev);
    0
}

#[inline(always)]
fn emit_fork<C: EbpfContext>(ctx: &C) -> u32 {
    if !event_enabled(SYS_EVENT_MASK_FORK) {
        return 0;
    }
    let pid = current_filtered_tgid();
    if pid == 0 {
        return 0;
    }
    if ALLOWED_PIDS.get_ptr(&pid).is_none() {
        return 0;
    }
    let ev = SysEvent {
        tgid: pid,
        kind: SYS_EVENT_FORK,
    };
    write_event(ctx, ev);
    0
}

#[inline(always)]
fn emit_exit<C: EbpfContext>(ctx: &C) -> u32 {
    if !event_enabled(SYS_EVENT_MASK_EXIT) {
        return 0;
    }
    let pid = current_filtered_tgid();
    if pid == 0 {
        return 0;
    }
    if ALLOWED_PIDS.get_ptr(&pid).is_none() {
        return 0;
    }
    let ev = SysEvent {
        tgid: pid,
        kind: SYS_EVENT_EXIT,
    };
    write_event(ctx, ev);
    0
}

#[inline(always)]
fn emit_map_change<C: EbpfContext>(ctx: &C) -> u32 {
    if !event_enabled(SYS_EVENT_MASK_MAP_CHANGE) {
        return 0;
    }
    let pid = current_filtered_tgid();
    if pid == 0 {
        return 0;
    }
    if !watched_pid_configured() && ALLOWED_PIDS.get_ptr(&pid).is_none() {
        return 0;
    }
    let ev = SysEvent {
        tgid: pid,
        kind: SYS_EVENT_MAP_CHANGE,
    };
    write_event(ctx, ev);
    0
}

#[inline(always)]
fn current_host_tgid() -> u32 {
    // BPF helper: get_current_pid_tgid >> 32
    let v = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    (v >> 32) as u32
}

#[inline(always)]
fn event_enabled(bit: u32) -> bool {
    match SYSMON_EVENT_MASK.get(0) {
        Some(mask) => (*mask & bit) != 0,
        None => false,
    }
}

#[inline(always)]
fn watched_pid_configured() -> bool {
    match SYSMON_WATCHED_PID.get(0) {
        Some(watched) => *watched != 0,
        None => false,
    }
}

#[inline(always)]
fn current_filtered_tgid() -> u32 {
    let host_pid = current_host_tgid();
    let watched = match SYSMON_WATCHED_PID.get(0) {
        Some(watched) => *watched,
        None => 0,
    };
    if watched == 0 {
        return host_pid;
    }

    let ns_dev = match SYSMON_WATCHED_PID_NS_DEV.get(0) {
        Some(dev) => *dev,
        None => 0,
    };
    let ns_ino = match SYSMON_WATCHED_PID_NS_INO.get(0) {
        Some(ino) => *ino,
        None => 0,
    };

    if ns_dev != 0 && ns_ino != 0 {
        let mut nsdata = bpf_pidns_info { pid: 0, tgid: 0 };
        let ret = unsafe {
            aya_ebpf::helpers::generated::bpf_get_ns_current_pid_tgid(
                ns_dev,
                ns_ino,
                &mut nsdata,
                core::mem::size_of::<bpf_pidns_info>() as u32,
            )
        };
        if ret == 0 && nsdata.tgid == watched {
            return nsdata.tgid;
        }
        return 0;
    }

    if host_pid == watched {
        host_pid
    } else {
        0
    }
}

#[inline(always)]
fn exec_comm_matches() -> bool {
    let filter = match TARGET_EXEC_COMM.get_ptr(0) {
        Some(ptr) => {
            // SAFETY: get_ptr returned a valid pointer to the array value for this
            // helper invocation; [u8; 16] is Copy.
            unsafe { *ptr }
        }
        None => return true,
    };
    if filter[0] == 0 {
        return true;
    }
    let mut comm = [0u8; 16];
    let ret = unsafe {
        aya_ebpf::helpers::generated::bpf_get_current_comm(
            comm.as_mut_ptr().cast(),
            core::mem::size_of_val(&comm) as u32,
        )
    };
    if ret != 0 {
        return false;
    }
    let mut matched = true;
    for i in 0..16 {
        let expected = filter[i];
        if expected == 0 {
            break;
        }
        if expected != comm[i] {
            matched = false;
            break;
        }
    }
    matched
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    emit_exec(&ctx)
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    emit_fork(&ctx)
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    emit_exit(&ctx)
}

#[tracepoint(name = "sys_exit_mmap", category = "syscalls")]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    emit_map_change(&ctx)
}

#[tracepoint(name = "sys_exit_mprotect", category = "syscalls")]
pub fn sys_exit_mprotect(ctx: TracePointContext) -> u32 {
    emit_map_change(&ctx)
}

#[tracepoint(name = "sys_exit_munmap", category = "syscalls")]
pub fn sys_exit_munmap(ctx: TracePointContext) -> u32 {
    emit_map_change(&ctx)
}

#[tracepoint(name = "sys_exit_mremap", category = "syscalls")]
pub fn sys_exit_mremap(ctx: TracePointContext) -> u32 {
    emit_map_change(&ctx)
}

#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn raw_sched_process_exec(ctx: RawTracePointContext) -> u32 {
    emit_exec(&ctx)
}

#[raw_tracepoint(tracepoint = "sched_process_fork")]
pub fn raw_sched_process_fork(ctx: RawTracePointContext) -> u32 {
    emit_fork(&ctx)
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn raw_sched_process_exit(ctx: RawTracePointContext) -> u32 {
    emit_exit(&ctx)
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn btf_sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    emit_exec(&ctx)
}

#[btf_tracepoint(function = "sched_process_fork")]
pub fn btf_sched_process_fork(ctx: BtfTracePointContext) -> u32 {
    emit_fork(&ctx)
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn btf_sched_process_exit(ctx: BtfTracePointContext) -> u32 {
    emit_exit(&ctx)
}

// Required by aya-bpf for panic handling in no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: eBPF programs cannot unwind; this panic handler marks the path unreachable.
    unsafe { core::hint::unreachable_unchecked() }
}
