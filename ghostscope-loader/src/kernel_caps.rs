use aya::{
    maps::MapType,
    programs::ProgramType,
    sys::{is_helper_supported, is_map_supported, BpfHelper},
};
use std::{fmt, sync::OnceLock};
use tracing::{error, info, warn};

/// Global cache for complete, hardware-backed kernel capability probes.
static KERNEL_CAPS: KernelCapabilityCache = KernelCapabilityCache::new();

#[derive(Debug)]
struct KernelCapabilityCache {
    full: OnceLock<KernelCapabilities>,
}

impl KernelCapabilityCache {
    const fn new() -> Self {
        Self {
            full: OnceLock::new(),
        }
    }

    fn get_or_detect<F>(&self, detect: F) -> Result<KernelCapabilities, KernelCapabilityError>
    where
        F: FnOnce() -> Result<KernelCapabilityDetection, KernelCapabilityError>,
    {
        if let Some(capabilities) = self.full.get() {
            return Ok(*capabilities);
        }

        let detection = detect()?;
        if detection.cacheable {
            let _ = self.full.set(detection.capabilities);
            if let Some(capabilities) = self.full.get() {
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
}

impl KernelCapabilities {
    /// Detect kernel capabilities for process startup, including startup-oriented logs and
    /// user-facing error context.
    pub fn detect_for_startup(force_perf_event_array: bool) -> Result<Self, KernelCapabilityError> {
        detect_for_startup_with_detectors(force_perf_event_array, Self::get, Self::get_perf_only)
    }

    /// Get global kernel capabilities (detected once on first cacheable call)
    /// Returns an error if neither RingBuf nor PerfEventArray support can be verified.
    pub fn get() -> Result<Self, KernelCapabilityError> {
        KERNEL_CAPS.get_or_detect(detect_full_capabilities)
    }

    /// Detect kernel capabilities with PerfEventArray-only startup semantics.
    /// This intentionally bypasses the global cache because force-perf mode is a
    /// runtime policy override, not the kernel's complete hardware capability set.
    pub fn get_perf_only() -> Result<Self, KernelCapabilityError> {
        detect_perf_only_capabilities()
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

fn detect_for_startup_with_detectors<F, P>(
    force_perf_event_array: bool,
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

    info!(
        "Kernel eBPF startup summary: ringbuf_supported={} perf_event_array_supported={} helper_ns_current_pid_tgid={}",
        capabilities.supports_ringbuf,
        capabilities.supports_perf_event_array,
        capabilities.supports_ns_current_pid_tgid_helper
    );

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

fn detect_full_capabilities() -> Result<KernelCapabilityDetection, KernelCapabilityError> {
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

    Ok(KernelCapabilityDetection {
        capabilities: KernelCapabilities {
            supports_ringbuf: supports_ringbuf.supported,
            supports_perf_event_array: supports_perf_event_array.supported,
            supports_ns_current_pid_tgid_helper: supports_ns_current_pid_tgid_helper.supported,
        },
        cacheable: supports_ringbuf.cacheable
            && supports_perf_event_array.cacheable
            && supports_ns_current_pid_tgid_helper.cacheable,
    })
}

fn detect_perf_only_capabilities() -> Result<KernelCapabilities, KernelCapabilityError> {
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

    Ok(KernelCapabilities {
        supports_ringbuf: false,
        supports_perf_event_array: supports_perf_event_array.supported,
        supports_ns_current_pid_tgid_helper: supports_ns_current_pid_tgid_helper.supported,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(
        supports_ringbuf: bool,
        supports_perf_event_array: bool,
        supports_ns_current_pid_tgid_helper: bool,
    ) -> KernelCapabilities {
        KernelCapabilities {
            supports_ringbuf,
            supports_perf_event_array,
            supports_ns_current_pid_tgid_helper,
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
        let perf_only_caps = caps(false, true, true);
        let full_caps = caps(true, true, true);

        let forced = detect_for_startup_with_detectors(
            true,
            || -> Result<KernelCapabilities, KernelCapabilityError> {
                panic!("full detector should not run for forced perf startup")
            },
            || Ok(perf_only_caps),
        )
        .expect("forced perf startup detection");

        assert_eq!(forced, perf_only_caps);

        let normal = detect_for_startup_with_detectors(
            false,
            || cache.get_or_detect(|| Ok(detection(full_caps, true))),
            || -> Result<KernelCapabilities, KernelCapabilityError> {
                panic!("perf-only detector should not run for normal startup")
            },
        )
        .expect("normal startup detection");

        assert_eq!(normal, full_caps);
        assert_eq!(
            cache
                .get_or_detect(|| {
                    panic!("full detector should not rerun after cacheable detection")
                })
                .expect("cached full capabilities"),
            full_caps
        );
    }

    #[test]
    fn uncacheable_full_probe_result_is_not_cached() {
        let cache = KernelCapabilityCache::new();
        let uncacheable_caps = caps(false, true, false);
        let cacheable_caps = caps(true, true, true);

        let first = cache
            .get_or_detect(|| Ok(detection(uncacheable_caps, false)))
            .expect("uncacheable startup result");
        assert_eq!(first, uncacheable_caps);

        let second = cache
            .get_or_detect(|| Ok(detection(cacheable_caps, true)))
            .expect("cacheable startup result");
        assert_eq!(second, cacheable_caps);

        assert_eq!(
            cache
                .get_or_detect(|| {
                    panic!("full detector should not rerun after cacheable detection")
                })
                .expect("cached full capabilities"),
            cacheable_caps
        );
    }
}
