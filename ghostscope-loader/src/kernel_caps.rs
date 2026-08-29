use aya::{
    maps::MapType,
    programs::ProgramType,
    sys::{is_helper_supported, is_map_supported, BpfHelper},
    util::KernelVersion,
};
use aya_obj::generated::{
    bpf_attr, bpf_cmd, bpf_insn, bpf_map_type, bpf_prog_type, BPF_ALU64, BPF_CALL, BPF_DW,
    BPF_EXIT, BPF_F_SLEEPABLE, BPF_IMM, BPF_JMP, BPF_K, BPF_LD, BPF_MOV, BPF_PSEUDO_MAP_FD,
};
use std::{fmt, io, mem, sync::OnceLock};
use tracing::{error, info, warn};

/// Global caches for hardware-backed kernel capability probe sets.
static KERNEL_CAPS: KernelCapabilityCache = KernelCapabilityCache::new();

#[derive(Debug)]
struct KernelCapabilityCache {
    base: OnceLock<KernelCapabilities>,
    full: OnceLock<KernelCapabilities>,
}

impl KernelCapabilityCache {
    const fn new() -> Self {
        Self {
            base: OnceLock::new(),
            full: OnceLock::new(),
        }
    }

    fn get_or_detect<F>(
        &self,
        probe_sleepable: bool,
        detect: F,
    ) -> Result<KernelCapabilities, KernelCapabilityError>
    where
        F: FnOnce() -> Result<KernelCapabilityDetection, KernelCapabilityError>,
    {
        let cache = if probe_sleepable {
            &self.full
        } else {
            &self.base
        };

        if let Some(capabilities) = cache.get() {
            return Ok(*capabilities);
        }

        let detection = detect()?;
        if detection.cacheable {
            let _ = cache.set(detection.capabilities);
            if let Some(capabilities) = cache.get() {
                return Ok(*capabilities);
            }
        } else {
            warn!("Kernel capability probe used fallback values; not caching this result");
        }

        Ok(detection.capabilities)
    }
}

#[derive(Debug, Clone)]
pub struct KernelCapabilityError {
    message: String,
}

impl KernelCapabilityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for KernelCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for KernelCapabilityError {}

/// Kernel eBPF capabilities detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCapabilities {
    /// Whether the kernel supports BPF_MAP_TYPE_RINGBUF (requires >= 5.8)
    pub supports_ringbuf: bool,
    /// Whether the kernel supports BPF_MAP_TYPE_PERF_EVENT_ARRAY (requires >= 4.3)
    pub supports_perf_event_array: bool,
    /// Whether bpf_get_ns_current_pid_tgid helper is supported for kprobe/uprobe class programs.
    pub supports_ns_current_pid_tgid_helper: bool,
    /// Whether the kernel supports the helpers required by GhostScope's sleepable
    /// uprobe mode (`bpf_get_current_task_btf` and `bpf_copy_from_user_task`,
    /// introduced in Linux 5.18).
    pub supports_sleepable_uprobe: bool,
    /// Whether sleepable KProbe-class programs can use a ProgramArray and
    /// `bpf_tail_call`. This is required for long DWARF backtraces.
    pub supports_sleepable_tail_calls: bool,
}

impl KernelCapabilities {
    /// Detect kernel capabilities for process startup without probing opt-in
    /// sleepable-uprobe support.
    pub fn detect_for_startup(force_perf_event_array: bool) -> Result<Self, KernelCapabilityError> {
        Self::detect_for_startup_with_options(force_perf_event_array, false)
    }

    /// Detect kernel capabilities for process startup, including opt-in
    /// sleepable-uprobe support.
    pub fn detect_for_startup_with_sleepable_uprobe(
        force_perf_event_array: bool,
    ) -> Result<Self, KernelCapabilityError> {
        Self::detect_for_startup_with_options(force_perf_event_array, true)
    }

    fn detect_for_startup_with_options(
        force_perf_event_array: bool,
        sleepable_uprobe: bool,
    ) -> Result<Self, KernelCapabilityError> {
        detect_for_startup_with_detectors(
            force_perf_event_array,
            sleepable_uprobe,
            || Self::get_for_startup(sleepable_uprobe),
            || detect_perf_only_capabilities(sleepable_uprobe),
        )
    }

    /// Get global kernel capabilities (detected once on first cacheable call)
    /// Returns an error if neither RingBuf nor PerfEventArray support can be verified.
    pub fn get() -> Result<Self, KernelCapabilityError> {
        KERNEL_CAPS.get_or_detect(true, || detect_full_capabilities(true))
    }

    /// Detect kernel capabilities with PerfEventArray-only startup semantics.
    /// This intentionally bypasses the global cache because force-perf mode is a
    /// runtime policy override, not the kernel's complete hardware capability set.
    pub fn get_perf_only() -> Result<Self, KernelCapabilityError> {
        detect_perf_only_capabilities(false)
    }

    /// Check if RingBuf is supported (convenience method)
    pub fn ringbuf_supported() -> bool {
        Self::get()
            .map(|caps| caps.supports_ringbuf)
            .unwrap_or(false)
    }

    /// Check if PerfEventArray is supported (convenience method)
    pub fn perf_event_array_supported() -> bool {
        Self::get()
            .map(|caps| caps.supports_perf_event_array)
            .unwrap_or(false)
    }

    /// Check if bpf_get_ns_current_pid_tgid helper is supported.
    pub fn ns_current_pid_tgid_helper_supported() -> bool {
        Self::get()
            .map(|caps| caps.supports_ns_current_pid_tgid_helper)
            .unwrap_or(false)
    }

    fn get_for_startup(probe_sleepable: bool) -> Result<Self, KernelCapabilityError> {
        KERNEL_CAPS.get_or_detect(probe_sleepable, || {
            detect_full_capabilities(probe_sleepable)
        })
    }
}

fn detect_for_startup_with_detectors<F, P>(
    force_perf_event_array: bool,
    sleepable_uprobe: bool,
    detect_full: F,
    detect_perf_only: P,
) -> Result<KernelCapabilities, KernelCapabilityError>
where
    F: FnOnce() -> Result<KernelCapabilities, KernelCapabilityError>,
    P: FnOnce() -> Result<KernelCapabilities, KernelCapabilityError>,
{
    let capabilities = if force_perf_event_array {
        warn!("⚠️  TESTING MODE: force_perf_event_array=true - will use PerfEventArray");
        detect_perf_only().map_err(|err| {
            KernelCapabilityError::new(format!(
                "{err}\nGhostScope requires Linux kernel >= 4.3 with PerfEventArray enabled."
            ))
        })?
    } else {
        detect_full().map_err(|err| {
            KernelCapabilityError::new(format!(
                "{err}\nHint: ensure CONFIG_BPF, CONFIG_BPF_SYSCALL and CONFIG_UPROBE_EVENTS are enabled in your kernel."
            ))
        })?
    };

    if sleepable_uprobe {
        info!(
            "Kernel eBPF startup summary: ringbuf_supported={} perf_event_array_supported={} helper_ns_current_pid_tgid={} sleepable_uprobe={} sleepable_tail_calls={}",
            capabilities.supports_ringbuf,
            capabilities.supports_perf_event_array,
            capabilities.supports_ns_current_pid_tgid_helper,
            capabilities.supports_sleepable_uprobe,
            capabilities.supports_sleepable_tail_calls,
        );
    } else {
        info!(
            "Kernel eBPF startup summary: ringbuf_supported={} perf_event_array_supported={} helper_ns_current_pid_tgid={}",
            capabilities.supports_ringbuf,
            capabilities.supports_perf_event_array,
            capabilities.supports_ns_current_pid_tgid_helper,
        );
    }

    Ok(capabilities)
}

#[derive(Debug, Clone, Copy)]
struct KernelCapabilityDetection {
    capabilities: KernelCapabilities,
    cacheable: bool,
}

#[derive(Debug, Clone, Copy)]
struct CapabilityProbe {
    supported: bool,
    cacheable: bool,
}

impl CapabilityProbe {
    fn cacheable(supported: bool) -> Self {
        Self {
            supported,
            cacheable: true,
        }
    }

    fn uncacheable_unsupported() -> Self {
        Self {
            supported: false,
            cacheable: false,
        }
    }
}

fn detect_full_capabilities(
    probe_sleepable: bool,
) -> Result<KernelCapabilityDetection, KernelCapabilityError> {
    let supports_ringbuf = detect_ringbuf_support();
    let supports_perf_event_array = if !supports_ringbuf.supported {
        detect_perf_event_array_support()
    } else {
        CapabilityProbe::cacheable(true)
    };

    if supports_ringbuf.supported {
        info!("✓ Kernel supports RingBuf (>= 5.8)");
    } else if supports_perf_event_array.supported {
        warn!("⚠️  Kernel does not support RingBuf (< 5.8)");
        warn!("⚠️  Will use PerfEventArray as fallback");
        info!("✓ Kernel supports PerfEventArray (>= 4.3)");
    } else {
        if !supports_ringbuf.cacheable || !supports_perf_event_array.cacheable {
            error!("❌ Unable to verify kernel eBPF event output support");
            return Err(KernelCapabilityError::new(
                "Unable to verify RingBuf or PerfEventArray support because one or more \
                 eBPF capability probes failed. Check privileges and kernel BPF settings.",
            ));
        }

        error!("❌ Kernel supports neither RingBuf nor PerfEventArray");
        error!("❌ GhostScope requires kernel >= 4.3 for eBPF event output");
        error!("❌ Current kernel appears to be older or eBPF is disabled");
        return Err(KernelCapabilityError::new(
            "Kernel lacks both RingBuf (>=5.8) and PerfEventArray (>=4.3) support. \
             Please upgrade the kernel or enable eBPF features.",
        ));
    }

    let supports_ns_current_pid_tgid_helper = detect_ns_current_pid_tgid_helper_support();
    if supports_ns_current_pid_tgid_helper.supported {
        info!("✓ Kernel supports helper bpf_get_ns_current_pid_tgid (id=120)");
    } else {
        warn!("⚠️  Kernel does not support helper bpf_get_ns_current_pid_tgid (id=120)");
    }

    let (supports_sleepable_uprobe, supports_sleepable_tail_calls) =
        detect_sleepable_capabilities(probe_sleepable);

    Ok(KernelCapabilityDetection {
        capabilities: KernelCapabilities {
            supports_ringbuf: supports_ringbuf.supported,
            supports_perf_event_array: supports_perf_event_array.supported,
            supports_ns_current_pid_tgid_helper: supports_ns_current_pid_tgid_helper.supported,
            supports_sleepable_uprobe: supports_sleepable_uprobe.supported,
            supports_sleepable_tail_calls: supports_sleepable_tail_calls.supported,
        },
        cacheable: supports_ringbuf.cacheable
            && supports_perf_event_array.cacheable
            && supports_ns_current_pid_tgid_helper.cacheable
            && supports_sleepable_uprobe.cacheable
            && supports_sleepable_tail_calls.cacheable,
    })
}

fn detect_perf_only_capabilities(
    probe_sleepable: bool,
) -> Result<KernelCapabilities, KernelCapabilityError> {
    info!("Testing mode: Only detecting PerfEventArray support");
    let supports_perf_event_array = detect_perf_event_array_support();

    if !supports_perf_event_array.supported {
        if !supports_perf_event_array.cacheable {
            error!("❌ Unable to verify PerfEventArray support");
            return Err(KernelCapabilityError::new(
                "Unable to verify PerfEventArray support because the eBPF capability probe \
                 failed. Check privileges and kernel BPF settings.",
            ));
        }

        error!("❌ Kernel does not support PerfEventArray");
        error!("❌ GhostScope requires kernel >= 4.3 for eBPF event output");
        return Err(KernelCapabilityError::new(
            "Kernel lacks PerfEventArray support (>=4.3 required). \
             Please upgrade the kernel or enable eBPF features.",
        ));
    }

    info!("✓ Kernel supports PerfEventArray (>= 4.3)");

    let supports_ns_current_pid_tgid_helper = detect_ns_current_pid_tgid_helper_support();
    if supports_ns_current_pid_tgid_helper.supported {
        info!("✓ Kernel supports helper bpf_get_ns_current_pid_tgid (id=120)");
    } else {
        warn!("⚠️  Kernel does not support helper bpf_get_ns_current_pid_tgid (id=120)");
    }

    let (supports_sleepable_uprobe, supports_sleepable_tail_calls) =
        detect_sleepable_capabilities(probe_sleepable);

    Ok(KernelCapabilities {
        supports_ringbuf: false,
        supports_perf_event_array: supports_perf_event_array.supported,
        supports_ns_current_pid_tgid_helper: supports_ns_current_pid_tgid_helper.supported,
        supports_sleepable_uprobe: supports_sleepable_uprobe.supported,
        supports_sleepable_tail_calls: supports_sleepable_tail_calls.supported,
    })
}

/// Detect RingBuf support by attempting to create a minimal map
fn detect_ringbuf_support() -> CapabilityProbe {
    detect_map_support(
        MapType::RingBuf,
        "RingBuf",
        "this is normal on kernels < 5.8",
    )
}

/// Detect PerfEventArray support by attempting to create a minimal map
fn detect_perf_event_array_support() -> CapabilityProbe {
    detect_map_support(
        MapType::PerfEventArray,
        "PerfEventArray",
        "kernel may be older than 4.3",
    )
}

fn detect_map_support(
    map_type: MapType,
    label: &str,
    unsupported_context: &str,
) -> CapabilityProbe {
    info!("Probing kernel {label} support via aya::sys::is_map_supported...");

    match is_map_supported(map_type) {
        Ok(true) => {
            info!("{label} map support probe succeeded - {label} is supported");
            CapabilityProbe::cacheable(true)
        }
        Ok(false) => {
            info!("{label} map support probe reported unsupported ({unsupported_context})");
            CapabilityProbe::cacheable(false)
        }
        Err(err) => {
            warn!("{label} map support probe failed unexpectedly: {err}");
            CapabilityProbe::uncacheable_unsupported()
        }
    }
}

fn detect_ns_current_pid_tgid_helper_support() -> CapabilityProbe {
    info!(
        "Probing kernel bpf_get_ns_current_pid_tgid helper support via aya::sys::is_helper_supported..."
    );

    match is_helper_supported(
        ProgramType::KProbe,
        BpfHelper::BPF_FUNC_get_ns_current_pid_tgid,
    ) {
        Ok(true) => {
            info!(
                "bpf_get_ns_current_pid_tgid helper support probe succeeded - helper is supported"
            );
            CapabilityProbe::cacheable(true)
        }
        Ok(false) => {
            info!("bpf_get_ns_current_pid_tgid helper support probe reported unsupported");
            CapabilityProbe::cacheable(false)
        }
        Err(err) => {
            warn!("bpf_get_ns_current_pid_tgid helper support probe failed unexpectedly: {err}");
            CapabilityProbe::uncacheable_unsupported()
        }
    }
}

fn detect_sleepable_capabilities(probe_sleepable: bool) -> (CapabilityProbe, CapabilityProbe) {
    detect_sleepable_capabilities_with_detectors(
        probe_sleepable,
        detect_sleepable_uprobe_support,
        detect_sleepable_tail_call_support,
    )
}

fn detect_sleepable_capabilities_with_detectors<U, T>(
    probe_sleepable: bool,
    detect_uprobe: U,
    detect_tail_calls: T,
) -> (CapabilityProbe, CapabilityProbe)
where
    U: FnOnce() -> CapabilityProbe,
    T: FnOnce() -> CapabilityProbe,
{
    if !probe_sleepable {
        return (
            CapabilityProbe::cacheable(false),
            CapabilityProbe::cacheable(false),
        );
    }

    let supports_sleepable_uprobe = detect_uprobe();
    if supports_sleepable_uprobe.supported {
        info!(
            "✓ Kernel supports GhostScope sleepable uprobe mode (bpf_get_current_task_btf and bpf_copy_from_user_task)"
        );
    } else {
        warn!(
            "⚠️  Kernel does not support GhostScope sleepable uprobe mode (requires Linux 5.18+)"
        );
    }

    let supports_sleepable_tail_calls = if supports_sleepable_uprobe.supported {
        detect_tail_calls()
    } else {
        CapabilityProbe::cacheable(false)
    };
    if supports_sleepable_tail_calls.supported {
        info!("✓ Kernel supports sleepable uprobe tail calls");
    }

    (supports_sleepable_uprobe, supports_sleepable_tail_calls)
}

fn detect_sleepable_uprobe_support() -> CapabilityProbe {
    info!(
        "Probing helpers required for sleepable uprobes; bpf_copy_from_user_task is probed with BPF_F_SLEEPABLE..."
    );

    let task_btf = is_helper_supported(
        ProgramType::KProbe,
        BpfHelper::BPF_FUNC_get_current_task_btf,
    );
    let copy_from_user_task =
        probe_sleepable_kprobe_helper_support(BpfHelper::BPF_FUNC_copy_from_user_task);

    match (task_btf, copy_from_user_task) {
        (Ok(true), Ok(true)) => CapabilityProbe::cacheable(true),
        (Ok(false), _) => {
            info!("bpf_get_current_task_btf helper support probe reported unsupported");
            CapabilityProbe::cacheable(false)
        }
        (_, Ok(false)) => {
            info!("bpf_copy_from_user_task helper support probe reported unsupported");
            CapabilityProbe::cacheable(false)
        }
        (Err(task_err), _) => {
            warn!("bpf_get_current_task_btf helper support probe failed unexpectedly: {task_err}");
            CapabilityProbe::uncacheable_unsupported()
        }
        (_, Err(copy_err)) => {
            warn!("bpf_copy_from_user_task helper support probe failed unexpectedly: {copy_err}");
            CapabilityProbe::uncacheable_unsupported()
        }
    }
}

fn detect_sleepable_tail_call_support() -> CapabilityProbe {
    info!(
        "Probing sleepable tail-call support with a sleepable KProbe caller, callee, and ProgramArray..."
    );

    match probe_sleepable_tail_call_support() {
        Ok(true) => CapabilityProbe::cacheable(true),
        Ok(false) => {
            info!("sleepable tail-call capability probe reported unsupported");
            CapabilityProbe::cacheable(false)
        }
        Err(err) => {
            warn!("sleepable tail-call capability probe failed unexpectedly: {err}");
            CapabilityProbe::uncacheable_unsupported()
        }
    }
}

/// Probe one KProbe-class helper under the same sleepable program flag that
/// Aya uses for an `uprobe.s` section.
///
/// `bpf_copy_from_user_task` is reported as an invalid helper by a regular
/// KProbe on kernels where it is intentionally restricted to sleepable
/// programs. The public Aya helper probe cannot set BPF program load flags.
// TODO(aya): Replace these raw probes after Aya exposes semantic sleepable
// uprobe capability probes, including support for sleepable tail calls.
fn probe_sleepable_kprobe_helper_support(helper: BpfHelper) -> Result<bool, io::Error> {
    let call = sleepable_helper_probe_instruction((BPF_JMP | BPF_CALL) as u8, helper as i32);
    let exit = sleepable_helper_probe_instruction((BPF_JMP | BPF_EXIT) as u8, 0);
    let instructions = [call, exit];
    match load_sleepable_kprobe_program(&instructions) {
        Ok(fd) => {
            close_bpf_fd(fd);
            Ok(true)
        }
        Err(failure) => match classify_sleepable_helper_probe_failure(
            failure.error.raw_os_error(),
            failure.verifier_log.as_ref(),
        ) {
            Some(supported) => Ok(supported),
            None => Err(failure.error),
        },
    }
}

/// Probe the complete kernel feature sequence used by a long sleepable `bt`:
/// load a sleepable callee, load a sleepable caller referencing a ProgramArray
/// and `bpf_tail_call`, then put the callee in that array.
fn probe_sleepable_tail_call_support() -> Result<bool, io::Error> {
    let map_fd = match create_program_array() {
        Ok(fd) => fd,
        Err(error) => return classify_sleepable_tail_call_syscall_failure(error),
    };

    let outcome = (|| {
        let callee = [
            bpf_instruction((BPF_ALU64 | BPF_MOV | BPF_K) as u8, 0, 0, 0),
            bpf_instruction((BPF_JMP | BPF_EXIT) as u8, 0, 0, 0),
        ];
        let callee_fd = match load_sleepable_kprobe_program(&callee) {
            Ok(fd) => fd,
            Err(failure) => return classify_sleepable_tail_call_load_failure(failure),
        };

        let outcome = (|| {
            let caller = sleepable_tail_call_probe_caller(map_fd);
            let caller_fd = match load_sleepable_kprobe_program(&caller) {
                Ok(fd) => fd,
                Err(failure) => return classify_sleepable_tail_call_load_failure(failure),
            };
            close_bpf_fd(caller_fd);

            match update_program_array(map_fd, callee_fd) {
                Ok(()) => Ok(true),
                Err(error) => classify_sleepable_tail_call_syscall_failure(error),
            }
        })();

        close_bpf_fd(callee_fd);
        outcome
    })();

    close_bpf_fd(map_fd);
    outcome
}

fn create_program_array() -> Result<libc::c_int, io::Error> {
    // SAFETY: bpf_attr is a C ABI union and zero initialization is valid for
    // the fields not used by a BPF_MAP_CREATE request.
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: __bindgen_anon_1 is the BPF_MAP_CREATE member of bpf_attr.
    let create = unsafe { &mut attr.__bindgen_anon_1 };
    create.map_type = bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY as u32;
    create.key_size = std::mem::size_of::<u32>() as u32;
    create.value_size = std::mem::size_of::<u32>() as u32;
    create.max_entries = 1;
    bpf_syscall(bpf_cmd::BPF_MAP_CREATE, &mut attr)
}

fn update_program_array(map_fd: libc::c_int, program_fd: libc::c_int) -> Result<(), io::Error> {
    let key = 0u32;
    let value = program_fd as u32;
    // SAFETY: bpf_attr is a C ABI union and zero initialization is valid for
    // the fields not used by a BPF_MAP_UPDATE_ELEM request.
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: __bindgen_anon_2 is the BPF_MAP_UPDATE_ELEM member of bpf_attr.
    let update = unsafe { &mut attr.__bindgen_anon_2 };
    update.map_fd = map_fd as u32;
    update.key = std::ptr::addr_of!(key) as u64;
    update.__bindgen_anon_1.value = std::ptr::addr_of!(value) as u64;

    bpf_syscall(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr).map(|_| ())
}

fn sleepable_tail_call_probe_caller(map_fd: libc::c_int) -> [bpf_insn; 6] {
    [
        bpf_instruction(
            (BPF_LD | BPF_DW | BPF_IMM) as u8,
            2,
            BPF_PSEUDO_MAP_FD as u8,
            map_fd,
        ),
        bpf_instruction(0, 0, 0, 0),
        bpf_instruction((BPF_ALU64 | BPF_MOV | BPF_K) as u8, 3, 0, 0),
        bpf_instruction(
            (BPF_JMP | BPF_CALL) as u8,
            0,
            0,
            BpfHelper::BPF_FUNC_tail_call as i32,
        ),
        bpf_instruction((BPF_ALU64 | BPF_MOV | BPF_K) as u8, 0, 0, 0),
        bpf_instruction((BPF_JMP | BPF_EXIT) as u8, 0, 0, 0),
    ]
}

struct SleepableProgramLoadFailure {
    error: io::Error,
    verifier_log: Box<[u8; 4096]>,
}

fn load_sleepable_kprobe_program(
    instructions: &[bpf_insn],
) -> Result<libc::c_int, SleepableProgramLoadFailure> {
    let mut verifier_log = [0u8; 4096];

    // SAFETY: bpf_attr and bpf_insn are C ABI structs. Zero initialization is
    // valid for the fields left unset in a BPF_PROG_LOAD request.
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: __bindgen_anon_3 is the BPF_PROG_LOAD member of bpf_attr.
    let load = unsafe { &mut attr.__bindgen_anon_3 };
    load.prog_type = bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32;
    load.insn_cnt = instructions.len() as u32;
    load.insns = instructions.as_ptr() as u64;
    load.license = c"GPL".as_ptr() as u64;
    load.log_level = 1;
    load.log_size = verifier_log.len() as u32;
    load.log_buf = verifier_log.as_mut_ptr() as u64;
    load.kern_version = KernelVersion::current().map_or(0, KernelVersion::code);
    load.prog_flags = BPF_F_SLEEPABLE;

    bpf_syscall(bpf_cmd::BPF_PROG_LOAD, &mut attr).map_err(|error| SleepableProgramLoadFailure {
        error,
        verifier_log: Box::new(verifier_log),
    })
}

fn bpf_syscall(command: bpf_cmd, attr: &mut bpf_attr) -> Result<libc::c_int, io::Error> {
    // SAFETY: the command-specific bpf_attr member was initialized by the
    // caller and the supplied size is the full ABI union size expected by the
    // BPF syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command as libc::c_long,
            attr as *mut bpf_attr,
            mem::size_of::<bpf_attr>(),
        )
    };
    if result >= 0 {
        Ok(result as libc::c_int)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn close_bpf_fd(fd: libc::c_int) {
    // SAFETY: successful BPF syscalls return an owned file descriptor.
    unsafe { libc::close(fd) };
}

fn bpf_instruction(code: u8, dst: u8, src: u8, imm: i32) -> bpf_insn {
    let mut instruction = sleepable_helper_probe_instruction(code, imm);
    instruction.set_dst_reg(dst);
    instruction.set_src_reg(src);
    instruction
}

fn classify_sleepable_tail_call_syscall_failure(error: io::Error) -> Result<bool, io::Error> {
    if is_sleepable_tail_call_unsupported_errno(error.raw_os_error()) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn classify_sleepable_tail_call_load_failure(
    failure: SleepableProgramLoadFailure,
) -> Result<bool, io::Error> {
    if is_sleepable_tail_call_unsupported_errno(failure.error.raw_os_error())
        || verifier_log_mentions_sleepable_tail_call_rejection(failure.verifier_log.as_ref())
    {
        Ok(false)
    } else {
        Err(failure.error)
    }
}

fn is_sleepable_tail_call_unsupported_errno(error_code: Option<i32>) -> bool {
    matches!(error_code, Some(code) if code == libc::EINVAL || code == libc::EOPNOTSUPP)
}

fn verifier_log_mentions_sleepable_tail_call_rejection(verifier_log: &[u8]) -> bool {
    let verifier_log = verifier_log
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or(verifier_log);
    [
        b"sleepable".as_slice(),
        b"tail call",
        b"prog_array",
        b"program array",
    ]
    .iter()
    .any(|diagnostic| {
        verifier_log
            .windows(diagnostic.len())
            .any(|window| window.eq_ignore_ascii_case(diagnostic))
    })
}

fn sleepable_helper_probe_instruction(code: u8, imm: i32) -> bpf_insn {
    // SAFETY: bpf_insn is a C ABI instruction structure; its zero value is a
    // valid baseline before the opcode and immediate are assigned.
    let mut instruction = unsafe { mem::zeroed::<bpf_insn>() };
    instruction.code = code;
    instruction.imm = imm;
    instruction
}

fn classify_sleepable_helper_probe_failure(
    error_code: Option<i32>,
    verifier_log: &[u8],
) -> Option<bool> {
    const UNSUPPORTED_HELPER_DIAGNOSTICS: &[&[u8]] = &[
        b"invalid func ",
        b"unknown func ",
        b"program of this type cannot use helper ",
    ];

    let verifier_log = verifier_log
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or(verifier_log);
    if verifier_log.is_empty() {
        return match error_code {
            Some(libc::EINVAL | libc::E2BIG) => Some(false),
            _ => None,
        };
    }

    if UNSUPPORTED_HELPER_DIAGNOSTICS.iter().any(|diagnostic| {
        verifier_log
            .windows(diagnostic.len())
            .any(|window| window == *diagnostic)
    }) {
        Some(false)
    } else {
        // The helper was recognized. Invalid arguments are expected because
        // this deliberately minimal probe supplies no helper arguments.
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(
        supports_ringbuf: bool,
        supports_perf_event_array: bool,
        supports_ns_current_pid_tgid_helper: bool,
        supports_sleepable_uprobe: bool,
        supports_sleepable_tail_calls: bool,
    ) -> KernelCapabilities {
        KernelCapabilities {
            supports_ringbuf,
            supports_perf_event_array,
            supports_ns_current_pid_tgid_helper,
            supports_sleepable_uprobe,
            supports_sleepable_tail_calls,
        }
    }

    fn detection(capabilities: KernelCapabilities, cacheable: bool) -> KernelCapabilityDetection {
        KernelCapabilityDetection {
            capabilities,
            cacheable,
        }
    }

    #[test]
    fn forced_perf_startup_does_not_populate_full_capabilities_cache() {
        let cache = KernelCapabilityCache::new();
        let perf_only_caps = caps(false, true, true, true, true);
        let full_caps = caps(true, true, true, true, true);

        let forced = detect_for_startup_with_detectors(
            true,
            false,
            || -> Result<KernelCapabilities, KernelCapabilityError> {
                panic!("full detector should not run for forced perf startup")
            },
            || Ok(perf_only_caps),
        )
        .expect("forced perf startup detection");

        assert_eq!(forced, perf_only_caps);

        let normal = detect_for_startup_with_detectors(
            false,
            true,
            || cache.get_or_detect(true, || Ok(detection(full_caps, true))),
            || -> Result<KernelCapabilities, KernelCapabilityError> {
                panic!("perf-only detector should not run for normal startup")
            },
        )
        .expect("normal startup detection");

        assert_eq!(normal, full_caps);
        assert_eq!(
            cache
                .get_or_detect(true, || {
                    panic!("full detector should not rerun after cacheable detection")
                })
                .expect("cached full capabilities"),
            full_caps
        );
    }

    #[test]
    fn startup_api_preserves_one_argument_entry_point() {
        let _: fn(bool) -> Result<KernelCapabilities, KernelCapabilityError> =
            KernelCapabilities::detect_for_startup;
        let _: fn(bool) -> Result<KernelCapabilities, KernelCapabilityError> =
            KernelCapabilities::detect_for_startup_with_sleepable_uprobe;
    }

    #[test]
    fn uncacheable_full_probe_result_is_not_cached() {
        let cache = KernelCapabilityCache::new();
        let uncacheable_caps = caps(false, true, false, false, false);
        let cacheable_caps = caps(true, true, true, true, true);

        let first = cache
            .get_or_detect(true, || Ok(detection(uncacheable_caps, false)))
            .expect("uncacheable startup result");
        assert_eq!(first, uncacheable_caps);

        let second = cache
            .get_or_detect(true, || Ok(detection(cacheable_caps, true)))
            .expect("cacheable startup result");
        assert_eq!(second, cacheable_caps);

        assert_eq!(
            cache
                .get_or_detect(true, || {
                    panic!("full detector should not rerun after cacheable detection")
                })
                .expect("cached full capabilities"),
            cacheable_caps
        );
    }

    #[test]
    fn base_capability_cache_does_not_hide_later_sleepable_detection() {
        let cache = KernelCapabilityCache::new();
        let base_caps = caps(true, true, true, false, false);
        let sleepable_caps = caps(true, true, true, true, true);

        assert_eq!(
            cache
                .get_or_detect(false, || Ok(detection(base_caps, true)))
                .expect("base capabilities"),
            base_caps
        );
        assert_eq!(
            cache
                .get_or_detect(true, || Ok(detection(sleepable_caps, true)))
                .expect("sleepable capabilities"),
            sleepable_caps
        );
    }

    #[test]
    fn disabled_sleepable_mode_skips_all_sleepable_probes() {
        let (uprobe, tail_calls) = detect_sleepable_capabilities_with_detectors(
            false,
            || panic!("sleepable uprobe probe should not run when the mode is disabled"),
            || panic!("sleepable tail-call probe should not run when the mode is disabled"),
        );

        assert!(!uprobe.supported);
        assert!(!tail_calls.supported);
        assert!(uprobe.cacheable);
        assert!(tail_calls.cacheable);
    }

    #[test]
    fn sleepable_helper_probe_classifies_verifier_results() {
        assert_eq!(
            classify_sleepable_helper_probe_failure(Some(libc::EPERM), b"invalid func 191\0"),
            Some(false)
        );
        assert_eq!(
            classify_sleepable_helper_probe_failure(
                Some(libc::EPERM),
                b"R4 type=scalar expected=ptr_\0"
            ),
            Some(true)
        );
        assert_eq!(
            classify_sleepable_helper_probe_failure(Some(libc::EINVAL), b"\0"),
            Some(false)
        );
        assert_eq!(
            classify_sleepable_helper_probe_failure(Some(libc::EPERM), b"\0"),
            None
        );
    }

    #[test]
    fn sleepable_tail_call_probe_classifies_kernel_rejections() {
        assert!(is_sleepable_tail_call_unsupported_errno(Some(libc::EINVAL)));
        assert!(is_sleepable_tail_call_unsupported_errno(Some(
            libc::EOPNOTSUPP
        )));
        assert!(!is_sleepable_tail_call_unsupported_errno(Some(libc::EPERM)));

        assert!(verifier_log_mentions_sleepable_tail_call_rejection(
            b"sleepable programs cannot use prog_array\0"
        ));
        assert!(verifier_log_mentions_sleepable_tail_call_rejection(
            b"Tail call is not allowed here\0"
        ));
        assert!(!verifier_log_mentions_sleepable_tail_call_rejection(
            b"R1 type=scalar expected=ctx\0"
        ));
    }
}
