/// Platform-specific register mappings and utilities for eBPF code generation
///
/// This module handles the mapping between DWARF register numbers and platform-specific
/// register layouts (like pt_regs) for different architectures.
use tracing::warn;

/// pt_regs indices for x86_64 architecture
///
/// These indices are used to access pt_regs structure fields as a u64 array.
/// The indices are calculated by dividing the field offset by the size of u64,
/// which gives us the array index for accessing pt_regs as a u64 array.
pub mod pt_regs_indices {
    use aya_ebpf_bindings::bindings::pt_regs;

    // Size of u64 in bytes for array index calculation
    const U64_SIZE: usize = core::mem::size_of::<u64>();

    // Core registers - calculated from pt_regs structure layout
    pub const R15: usize = core::mem::offset_of!(pt_regs, r15) / U64_SIZE;
    pub const R14: usize = core::mem::offset_of!(pt_regs, r14) / U64_SIZE;
    pub const R13: usize = core::mem::offset_of!(pt_regs, r13) / U64_SIZE;
    pub const R12: usize = core::mem::offset_of!(pt_regs, r12) / U64_SIZE;
    pub const RBP: usize = core::mem::offset_of!(pt_regs, rbp) / U64_SIZE; // Frame pointer
    pub const RBX: usize = core::mem::offset_of!(pt_regs, rbx) / U64_SIZE;
    pub const R11: usize = core::mem::offset_of!(pt_regs, r11) / U64_SIZE;
    pub const R10: usize = core::mem::offset_of!(pt_regs, r10) / U64_SIZE;
    pub const R9: usize = core::mem::offset_of!(pt_regs, r9) / U64_SIZE;
    pub const R8: usize = core::mem::offset_of!(pt_regs, r8) / U64_SIZE;
    pub const RAX: usize = core::mem::offset_of!(pt_regs, rax) / U64_SIZE; // Return value
    pub const RCX: usize = core::mem::offset_of!(pt_regs, rcx) / U64_SIZE; // 4th argument
    pub const RDX: usize = core::mem::offset_of!(pt_regs, rdx) / U64_SIZE; // 3rd argument
    pub const RSI: usize = core::mem::offset_of!(pt_regs, rsi) / U64_SIZE; // 2nd argument
    pub const RDI: usize = core::mem::offset_of!(pt_regs, rdi) / U64_SIZE; // 1st argument

    // Special registers
    pub const ORIG_RAX: usize = core::mem::offset_of!(pt_regs, orig_rax) / U64_SIZE; // Original syscall number
    pub const RIP: usize = core::mem::offset_of!(pt_regs, rip) / U64_SIZE; // Instruction pointer
    pub const CS: usize = core::mem::offset_of!(pt_regs, cs) / U64_SIZE; // Code segment
    pub const EFLAGS: usize = core::mem::offset_of!(pt_regs, eflags) / U64_SIZE; // Flags register
    pub const RSP: usize = core::mem::offset_of!(pt_regs, rsp) / U64_SIZE; // Stack pointer
    pub const SS: usize = core::mem::offset_of!(pt_regs, ss) / U64_SIZE; // Stack segment
}

/// Convert DWARF register number to pt_regs byte offset for x86_64
///
/// This function maps DWARF register numbers to the correct byte offset
/// within the pt_regs structure for x86_64 architecture.
///
/// Reference: https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/ptrace.h
/// pt_regs structure layout on x86_64:
/// ```c
/// struct pt_regs {
///     unsigned long r15;    // offset 0
///     unsigned long r14;    // offset 8
///     unsigned long r13;    // offset 16
///     unsigned long r12;    // offset 24
///     unsigned long bp;     // offset 32  (RBP)
///     unsigned long bx;     // offset 40  (RBX)
///     unsigned long r11;    // offset 48
///     unsigned long r10;    // offset 56
///     unsigned long r9;     // offset 64
///     unsigned long r8;     // offset 72
///     unsigned long ax;     // offset 80  (RAX)
///     unsigned long cx;     // offset 88  (RCX)
///     unsigned long dx;     // offset 96  (RDX)
///     unsigned long si;     // offset 104 (RSI)
///     unsigned long di;     // offset 112 (RDI)
///     unsigned long orig_ax;// offset 120
///     unsigned long ip;     // offset 128 (RIP)
///     unsigned long cs;     // offset 136
///     unsigned long flags;  // offset 144
///     unsigned long sp;     // offset 152 (RSP)
///     unsigned long ss;     // offset 160
/// };
/// ```
pub fn dwarf_reg_to_pt_regs_byte_offset_x86_64(dwarf_reg: u16) -> Option<usize> {
    const U64_SIZE: usize = core::mem::size_of::<u64>();
    match dwarf_reg {
        // x86_64 DWARF register mappings to pt_regs indices (converted to byte offsets)
        0 => Some(pt_regs_indices::RAX * U64_SIZE), // DWARF 0 = RAX
        1 => Some(pt_regs_indices::RDX * U64_SIZE), // DWARF 1 = RDX
        2 => Some(pt_regs_indices::RCX * U64_SIZE), // DWARF 2 = RCX
        3 => Some(pt_regs_indices::RBX * U64_SIZE), // DWARF 3 = RBX
        4 => Some(pt_regs_indices::RSI * U64_SIZE), // DWARF 4 = RSI
        5 => Some(pt_regs_indices::RDI * U64_SIZE), // DWARF 5 = RDI
        6 => Some(pt_regs_indices::RBP * U64_SIZE), // DWARF 6 = RBP
        7 => Some(pt_regs_indices::RSP * U64_SIZE), // DWARF 7 = RSP
        8 => Some(pt_regs_indices::R8 * U64_SIZE),  // DWARF 8 = R8
        9 => Some(pt_regs_indices::R9 * U64_SIZE),  // DWARF 9 = R9
        10 => Some(pt_regs_indices::R10 * U64_SIZE), // DWARF 10 = R10
        11 => Some(pt_regs_indices::R11 * U64_SIZE), // DWARF 11 = R11
        12 => Some(pt_regs_indices::R12 * U64_SIZE), // DWARF 12 = R12
        13 => Some(pt_regs_indices::R13 * U64_SIZE), // DWARF 13 = R13
        14 => Some(pt_regs_indices::R14 * U64_SIZE), // DWARF 14 = R14
        15 => Some(pt_regs_indices::R15 * U64_SIZE), // DWARF 15 = R15
        16 => Some(pt_regs_indices::RIP * U64_SIZE), // DWARF 16 = RIP
        _ => {
            warn!("Unknown DWARF register {} for x86_64", dwarf_reg);
            None
        }
    }
}

/// Convert DWARF register number to register name for x86_64
///
/// Maps DWARF register numbers to human-readable register names
/// for debugging and display purposes.
pub fn dwarf_reg_to_name_x86_64(dwarf_reg: u16) -> Option<&'static str> {
    match dwarf_reg {
        0 => Some("RAX"),  // DWARF 0 = RAX
        1 => Some("RDX"),  // DWARF 1 = RDX
        2 => Some("RCX"),  // DWARF 2 = RCX
        3 => Some("RBX"),  // DWARF 3 = RBX
        4 => Some("RSI"),  // DWARF 4 = RSI
        5 => Some("RDI"),  // DWARF 5 = RDI
        6 => Some("RBP"),  // DWARF 6 = RBP
        7 => Some("RSP"),  // DWARF 7 = RSP
        8 => Some("R8"),   // DWARF 8 = R8
        9 => Some("R9"),   // DWARF 9 = R9
        10 => Some("R10"), // DWARF 10 = R10
        11 => Some("R11"), // DWARF 11 = R11
        12 => Some("R12"), // DWARF 12 = R12
        13 => Some("R13"), // DWARF 13 = R13
        14 => Some("R14"), // DWARF 14 = R14
        15 => Some("R15"), // DWARF 15 = R15
        16 => Some("RIP"), // DWARF 16 = RIP
        _ => None,
    }
}

/// Convert DWARF register number to register name
///
/// Currently only supports x86_64. This function can be extended
/// to support other architectures in the future.
pub fn dwarf_reg_to_name(dwarf_reg: u16) -> Option<&'static str> {
    // For now, we only support x86_64
    // TODO: Add support for other architectures (ARM64, RISC-V, etc.)
    dwarf_reg_to_name_x86_64(dwarf_reg)
}

/// Convert DWARF register number to pt_regs byte offset
///
/// Currently only supports x86_64. This function can be extended
/// to support other architectures in the future.
pub fn dwarf_reg_to_pt_regs_byte_offset(dwarf_reg: u16) -> Option<usize> {
    // For now, we only support x86_64
    // TODO: Add support for other architectures (ARM64, RISC-V, etc.)
    dwarf_reg_to_pt_regs_byte_offset_x86_64(dwarf_reg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64_dwarf_to_pt_regs_mapping() {
        // Test key registers
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(0), Some(80)); // RAX
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(6), Some(32)); // RBP
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(7), Some(152)); // RSP
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(16), Some(128)); // RIP

        // Test invalid register
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(99), None);
    }

    #[test]
    fn test_x86_64_dwarf_to_name_mapping() {
        // Test core registers
        assert_eq!(dwarf_reg_to_name_x86_64(0), Some("RAX"));
        assert_eq!(dwarf_reg_to_name_x86_64(1), Some("RDX"));
        assert_eq!(dwarf_reg_to_name_x86_64(4), Some("RSI"));
        assert_eq!(dwarf_reg_to_name_x86_64(5), Some("RDI"));
        assert_eq!(dwarf_reg_to_name_x86_64(6), Some("RBP"));
        assert_eq!(dwarf_reg_to_name_x86_64(7), Some("RSP"));

        // Test extended registers
        assert_eq!(dwarf_reg_to_name_x86_64(8), Some("R8"));
        assert_eq!(dwarf_reg_to_name_x86_64(13), Some("R13"));
        assert_eq!(dwarf_reg_to_name_x86_64(15), Some("R15"));

        // Test special registers
        assert_eq!(dwarf_reg_to_name_x86_64(16), Some("RIP"));

        // Test invalid register
        assert_eq!(dwarf_reg_to_name_x86_64(99), None);
    }

    #[test]
    fn test_dwarf_reg_to_name_generic() {
        // Test the generic function (currently just calls x86_64)
        assert_eq!(dwarf_reg_to_name(0), Some("RAX"));
        assert_eq!(dwarf_reg_to_name(5), Some("RDI"));
        assert_eq!(dwarf_reg_to_name(13), Some("R13"));
        assert_eq!(dwarf_reg_to_name(99), None);
    }

    #[test]
    fn test_dwarf_reg_to_pt_regs_byte_offset_generic() {
        // Test the generic function (currently just calls x86_64)
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset(0), Some(80)); // RAX
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset(5), Some(112)); // RDI
        assert_eq!(dwarf_reg_to_pt_regs_byte_offset(99), None);
    }
}
