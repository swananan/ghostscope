#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerfEventArray, RingBuf},
    programs::TracePointContext,
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
    pub kind: u32, // 1=Exec,2=Fork,3=Exit
}

#[map(name = "sysmon_events")]
static mut SYS_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // 1MB

#[map(name = "sysmon_events_perf")]
static mut SYS_EVENTS_PERF: PerfEventArray<SysEvent> = PerfEventArray::new(0);

// Allowed pids for -t mode: fork/exit events are only emitted when pid is present.
#[map(name = "allowed_pids")]
static mut ALLOWED_PIDS: HashMap<u32, u8> = HashMap::pinned(16384, 0);

// Optional comm filter for exec events (truncated basename, null-terminated).
#[map(name = "target_exec_comm")]
static mut TARGET_EXEC_COMM: Array<[u8; 16]> = Array::pinned(1, 0);

fn write_event(ctx: &TracePointContext, mut ev: SysEvent) {
    // Prefer direct helper to avoid large memcpy/memmove codegen
    let size = core::mem::size_of::<SysEvent>() as u64;
    let map_ptr = unsafe { core::ptr::addr_of_mut!(SYS_EVENTS) } as *mut _;
    let data_ptr = &mut ev as *mut _ as *mut _;
    let ret = unsafe { aya_ebpf::helpers::bpf_ringbuf_output(map_ptr, data_ptr, size, 0) };
    if ret < 0 {
        // Fallback to perf event if ringbuf output fails
        let _ = unsafe { SYS_EVENTS_PERF.output(ctx, &mut ev, 0) };
    }
}

#[inline(always)]
fn current_tgid() -> u32 {
    // BPF helper: get_current_pid_tgid >> 32
    let v = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    (v >> 32) as u32
}

#[inline(always)]
fn exec_comm_matches() -> bool {
    let filter = match unsafe { TARGET_EXEC_COMM.get_ptr(0) } {
        Some(ptr) => unsafe { *ptr },
        None => return true,
    };
    if filter[0] == 0 {
        return true;
    }
    let comm = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(val) => val,
        Err(_) => return false,
    };
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
    if !exec_comm_matches() {
        return 0;
    }
    // Emit exec only when filter (if present) passes; userspace handles mapping and allowlist
    let ev = SysEvent { tgid: current_tgid(), kind: 1 };
    write_event(&ctx, ev);
    0
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let pid = current_tgid();
    unsafe {
        if ALLOWED_PIDS.get(&pid).is_none() {
            return 0;
        }
    }
    let ev = SysEvent { tgid: pid, kind: 2 };
    write_event(&ctx, ev);
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let pid = current_tgid();
    unsafe {
        if ALLOWED_PIDS.get(&pid).is_none() {
            return 0;
        }
    }
    let ev = SysEvent { tgid: pid, kind: 3 };
    write_event(&ctx, ev);
    0
}

// Required by aya-bpf for panic handling in no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
