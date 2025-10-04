/// Key for proc_module_offsets map
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcModuleKey {
    pub pid: u32,
    pub pad: u32,
    pub cookie_lo: u32,
    pub cookie_hi: u32,
}

/// Value for proc_module_offsets map - section offsets for a module
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcModuleOffsetsValue {
    pub text: u64,
    pub rodata: u64,
    pub data: u64,
    pub bss: u64,
}

unsafe impl aya::Pod for ProcModuleKey {}
unsafe impl aya::Pod for ProcModuleOffsetsValue {}

impl ProcModuleOffsetsValue {
    pub fn new(text: u64, rodata: u64, data: u64, bss: u64) -> Self {
        Self {
            text,
            rodata,
            data,
            bss,
        }
    }
}
