use aya::maps::MapData;
use aya_obj::{
    generated::bpf_map_type::{BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_MAP_TYPE_RINGBUF},
    maps::PinningType,
    EbpfSectionKind, Map,
};
use std::sync::OnceLock;
use tracing::{error, info, warn};

/// Global kernel capabilities cache
static KERNEL_CAPS: OnceLock<KernelCapabilities> = OnceLock::new();

/// Kernel eBPF capabilities detection
#[derive(Debug, Clone, Copy)]
pub struct KernelCapabilities {
    /// Whether the kernel supports BPF_MAP_TYPE_RINGBUF (requires >= 5.8)
    pub supports_ringbuf: bool,
    /// Whether the kernel supports BPF_MAP_TYPE_PERF_EVENT_ARRAY (requires >= 4.3)
    pub supports_perf_event_array: bool,
}

impl KernelCapabilities {
    /// Get global kernel capabilities (detected once on first call)
    /// Panics if neither RingBuf nor PerfEventArray is supported
    pub fn get() -> &'static Self {
        KERNEL_CAPS.get_or_init(|| {
            let supports_ringbuf = detect_ringbuf_support();
            let supports_perf_event_array = if !supports_ringbuf {
                // Only check PerfEventArray if RingBuf failed
                detect_perf_event_array_support()
            } else {
                // Assume PerfEventArray is supported if RingBuf is (5.8 > 4.3)
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
                panic!(
                    "Unsupported kernel: Neither RingBuf nor PerfEventArray is available. \
                     Please upgrade to Linux kernel >= 4.3 or enable eBPF support."
                );
            }

            Self {
                supports_ringbuf,
                supports_perf_event_array,
            }
        })
    }

    /// Get kernel capabilities with PerfEventArray-only detection (for testing mode)
    /// Skips RingBuf detection and only validates PerfEventArray support
    /// Panics if PerfEventArray is not supported
    pub fn get_perf_only() -> &'static Self {
        KERNEL_CAPS.get_or_init(|| {
            info!("Testing mode: Only detecting PerfEventArray support");
            let supports_perf_event_array = detect_perf_event_array_support();

            if !supports_perf_event_array {
                error!("❌ Kernel does not support PerfEventArray");
                error!("❌ GhostScope requires kernel >= 4.3 for eBPF event output");
                panic!(
                    "Unsupported kernel: PerfEventArray is not available. \
                     Please upgrade to Linux kernel >= 4.3 or enable eBPF support."
                );
            }

            info!("✓ Kernel supports PerfEventArray (>= 4.3)");

            Self {
                supports_ringbuf: false, // Not detected in testing mode
                supports_perf_event_array,
            }
        })
    }

    /// Check if RingBuf is supported (convenience method)
    pub fn ringbuf_supported() -> bool {
        Self::get().supports_ringbuf
    }

    /// Check if PerfEventArray is supported (convenience method)
    pub fn perf_event_array_supported() -> bool {
        Self::get().supports_perf_event_array
    }
}

/// Detect RingBuf support by attempting to create a minimal map
fn detect_ringbuf_support() -> bool {
    info!("Probing kernel RingBuf support by attempting map creation...");

    // Create a minimal RingBuf map definition (4KB)
    let obj_map = Map::Legacy(aya_obj::maps::LegacyMap {
        section_index: 0,
        section_kind: EbpfSectionKind::Maps,
        symbol_index: None,
        def: aya_obj::maps::bpf_map_def {
            map_type: BPF_MAP_TYPE_RINGBUF as u32,
            key_size: 0,       // RingBuf doesn't use key
            value_size: 0,     // RingBuf doesn't use value
            max_entries: 4096, // 4KB minimal size
            map_flags: 0,
            id: 0,
            pinning: PinningType::None,
        },
        data: Vec::new(),
    });

    // Try to create the map
    match MapData::create(obj_map, "probe_ringbuf", None) {
        Ok(_map) => {
            // Map was created successfully, RingBuf is supported
            // The map will be automatically dropped and closed
            info!("RingBuf map creation succeeded - RingBuf is supported");
            true
        }
        Err(e) => {
            // Map creation failed, likely due to unsupported map type
            info!(
                "RingBuf map creation failed (this is normal on kernels < 5.8): {}",
                e
            );
            false
        }
    }
}

/// Detect PerfEventArray support by attempting to create a minimal map
fn detect_perf_event_array_support() -> bool {
    info!("Probing kernel PerfEventArray support by attempting map creation...");

    // Create a minimal PerfEventArray map definition
    let obj_map = Map::Legacy(aya_obj::maps::LegacyMap {
        section_index: 0,
        section_kind: EbpfSectionKind::Maps,
        symbol_index: None,
        def: aya_obj::maps::bpf_map_def {
            map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32,
            key_size: 4,    // key is u32
            value_size: 4,  // value is u32 (file descriptor)
            max_entries: 0, // 0 means auto-detect number of CPUs
            map_flags: 0,
            id: 0,
            pinning: PinningType::None,
        },
        data: Vec::new(),
    });

    // Try to create the map
    match MapData::create(obj_map, "probe_perf_event_array", None) {
        Ok(_map) => {
            // Map was created successfully, PerfEventArray is supported
            // The map will be automatically dropped and closed
            info!("PerfEventArray map creation succeeded - PerfEventArray is supported");
            true
        }
        Err(e) => {
            // Map creation failed, likely due to unsupported map type
            error!(
                "PerfEventArray map creation failed (kernel may be older than 4.3): {}",
                e
            );
            false
        }
    }
}
