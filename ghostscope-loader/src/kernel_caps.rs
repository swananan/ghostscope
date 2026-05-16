use aya::{maps::MapType, sys::is_map_supported};
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_insn, bpf_prog_type};
use libc::SYS_bpf;
use std::{fmt, sync::OnceLock};
use tracing::{error, info, warn};

/// Global kernel capabilities cache
static KERNEL_CAPS: OnceLock<Result<KernelCapabilities, KernelCapabilityError>> = OnceLock::new();

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
#[derive(Debug, Clone, Copy)]
pub struct KernelCapabilities {
    /// Whether the kernel supports BPF_MAP_TYPE_RINGBUF (requires >= 5.8)
    pub supports_ringbuf: bool,
    /// Whether the kernel supports BPF_MAP_TYPE_PERF_EVENT_ARRAY (requires >= 4.3)
    pub supports_perf_event_array: bool,
    /// Whether bpf_get_ns_current_pid_tgid helper is supported for kprobe/uprobe class programs.
    pub supports_ns_current_pid_tgid_helper: bool,
}

impl KernelCapabilities {
    /// Detect kernel capabilities for process startup, including startup-oriented logs and
    /// user-facing error context.
    pub fn detect_for_startup(
        force_perf_event_array: bool,
    ) -> Result<&'static Self, KernelCapabilityError> {
        let capabilities = if force_perf_event_array {
            warn!("⚠️  TESTING MODE: force_perf_event_array=true - will use PerfEventArray");
            Self::get_perf_only().map_err(|err| {
                KernelCapabilityError::new(format!(
                    "{err}\nGhostScope requires Linux kernel >= 4.3 with PerfEventArray enabled."
                ))
            })?
        } else {
            Self::get().map_err(|err| {
                KernelCapabilityError::new(format!(
                    "{err}\nHint: ensure CONFIG_BPF, CONFIG_BPF_SYSCALL and CONFIG_UPROBE_EVENTS are enabled in your kernel."
                ))
            })?
        };

        info!(
            "Kernel eBPF startup summary: ringbuf_supported={} perf_event_array_supported={} helper_ns_current_pid_tgid={}",
            capabilities.supports_ringbuf,
            capabilities.supports_perf_event_array,
            capabilities.supports_ns_current_pid_tgid_helper
        );

        Ok(capabilities)
    }

    /// Get global kernel capabilities (detected once on first call)
    /// Returns an error if neither RingBuf nor PerfEventArray is supported
    pub fn get() -> Result<&'static Self, KernelCapabilityError> {
        match KERNEL_CAPS.get_or_init(detect_full_capabilities) {
            Ok(capabilities) => Ok(capabilities),
            Err(err) => Err(err.clone()),
        }
    }

    /// Get kernel capabilities with PerfEventArray-only detection (for testing mode)
    /// Skips RingBuf detection and only validates PerfEventArray support
    /// Returns an error if PerfEventArray is not supported
    pub fn get_perf_only() -> Result<&'static Self, KernelCapabilityError> {
        match KERNEL_CAPS.get_or_init(detect_perf_only_capabilities) {
            Ok(capabilities) => Ok(capabilities),
            Err(err) => Err(err.clone()),
        }
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
}

fn detect_full_capabilities() -> Result<KernelCapabilities, KernelCapabilityError> {
    let supports_ringbuf = detect_ringbuf_support();
    let supports_perf_event_array = if !supports_ringbuf {
        detect_perf_event_array_support()
    } else {
        true
    };

    if supports_ringbuf {
        info!("✓ Kernel supports RingBuf (>= 5.8)");
    } else if supports_perf_event_array {
        warn!("⚠️  Kernel does not support RingBuf (< 5.8)");
        warn!("⚠️  Will use PerfEventArray as fallback");
        info!("✓ Kernel supports PerfEventArray (>= 4.3)");
    } else {
        error!("❌ Kernel supports neither RingBuf nor PerfEventArray");
        error!("❌ GhostScope requires kernel >= 4.3 for eBPF event output");
        error!("❌ Current kernel appears to be older or eBPF is disabled");
        return Err(KernelCapabilityError::new(
            "Kernel lacks both RingBuf (>=5.8) and PerfEventArray (>=4.3) support. \
             Please upgrade the kernel or enable eBPF features.",
        ));
    }

    let supports_ns_current_pid_tgid_helper = detect_ns_current_pid_tgid_helper_support();
    if supports_ns_current_pid_tgid_helper {
        info!("✓ Kernel supports helper bpf_get_ns_current_pid_tgid (id=120)");
    } else {
        warn!("⚠️  Kernel does not support helper bpf_get_ns_current_pid_tgid (id=120)");
    }

    Ok(KernelCapabilities {
        supports_ringbuf,
        supports_perf_event_array,
        supports_ns_current_pid_tgid_helper,
    })
}

fn detect_perf_only_capabilities() -> Result<KernelCapabilities, KernelCapabilityError> {
    info!("Testing mode: Only detecting PerfEventArray support");
    let supports_perf_event_array = detect_perf_event_array_support();

    if !supports_perf_event_array {
        error!("❌ Kernel does not support PerfEventArray");
        error!("❌ GhostScope requires kernel >= 4.3 for eBPF event output");
        return Err(KernelCapabilityError::new(
            "Kernel lacks PerfEventArray support (>=4.3 required). \
             Please upgrade the kernel or enable eBPF features.",
        ));
    }

    info!("✓ Kernel supports PerfEventArray (>= 4.3)");

    let supports_ns_current_pid_tgid_helper = detect_ns_current_pid_tgid_helper_support();
    if supports_ns_current_pid_tgid_helper {
        info!("✓ Kernel supports helper bpf_get_ns_current_pid_tgid (id=120)");
    } else {
        warn!("⚠️  Kernel does not support helper bpf_get_ns_current_pid_tgid (id=120)");
    }

    Ok(KernelCapabilities {
        supports_ringbuf: false,
        supports_perf_event_array,
        supports_ns_current_pid_tgid_helper,
    })
}

/// Detect RingBuf support by attempting to create a minimal map
fn detect_ringbuf_support() -> bool {
    detect_map_support(
        MapType::RingBuf,
        "RingBuf",
        "this is normal on kernels < 5.8",
    )
}

/// Detect PerfEventArray support by attempting to create a minimal map
fn detect_perf_event_array_support() -> bool {
    detect_map_support(
        MapType::PerfEventArray,
        "PerfEventArray",
        "kernel may be older than 4.3",
    )
}

fn detect_map_support(map_type: MapType, label: &str, unsupported_context: &str) -> bool {
    info!("Probing kernel {label} support via aya::sys::is_map_supported...");

    match is_map_supported(map_type) {
        Ok(true) => {
            info!("{label} map support probe succeeded - {label} is supported");
            true
        }
        Ok(false) => {
            info!("{label} map support probe reported unsupported ({unsupported_context})");
            false
        }
        Err(err) => {
            warn!("{label} map support probe failed unexpectedly: {err}");
            false
        }
    }
}

fn detect_ns_current_pid_tgid_helper_support() -> bool {
    const BPF_FUNC_GET_NS_CURRENT_PID_TGID: i32 = 120;

    let insns = [
        make_bpf_insn(0x85, 0, 0, 0, BPF_FUNC_GET_NS_CURRENT_PID_TGID),
        make_bpf_insn(0x95, 0, 0, 0, 0),
    ];

    let license = b"GPL\0";
    let mut log_buf = [0u8; 4096];
    let mut attr = unsafe { std::mem::zeroed::<bpf_attr>() };
    unsafe {
        let u = &mut attr.__bindgen_anon_3;
        u.prog_type = bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32;
        u.insn_cnt = insns.len() as u32;
        u.insns = insns.as_ptr() as u64;
        u.license = license.as_ptr() as u64;
        u.log_level = 1;
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.len() as u32;
    }

    let ret = unsafe {
        libc::syscall(
            SYS_bpf as libc::c_long,
            bpf_cmd::BPF_PROG_LOAD as libc::c_long,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<bpf_attr>(),
        )
    };

    if ret >= 0 {
        let fd = ret as libc::c_int;
        let _ = unsafe { libc::close(fd) };
        return true;
    }

    let log = String::from_utf8_lossy(&log_buf);
    if log.contains("invalid func ")
        || log.contains("unknown func ")
        || log.contains("program of this type cannot use helper ")
    {
        return false;
    }

    // If verifier produced any non-empty diagnostics but not "unknown helper" patterns,
    // treat it as supported (typically argument/type mismatch with a known helper).
    let has_any_log = !log.trim_matches(char::from(0)).trim().is_empty();
    has_any_log
}

fn make_bpf_insn(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> bpf_insn {
    let mut insn = unsafe { std::mem::zeroed::<bpf_insn>() };
    insn.code = code;
    insn.set_dst_reg(dst_reg);
    insn.set_src_reg(src_reg);
    insn.off = off;
    insn.imm = imm;
    insn
}
