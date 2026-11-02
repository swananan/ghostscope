//! Target ABI facts shared by DWARF analysis and runtime code generation.
//!
//! Describing an ABI does not imply that the runtime can execute on that target.
//! Keep the runtime build guard and target ELF validation independent.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    Aarch64,
    Unknown,
}

/// DWARF register roles. The return-address register need not be the PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwarfRegisterRoles {
    pub stack_pointer: u16,
    pub frame_pointer: u16,
    pub return_address: u16,
}

/// Register numbers used by the current x86_64 BPF unwind implementation.
pub mod x86_64 {
    pub const RIP: u16 = 16;
    pub const RBP: u16 = 6;
    pub const RSP: u16 = 7;
}

/// Registers exposed by the probe context independently of DWARF numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRegister {
    Pc,
    Sp,
}

impl TargetArch {
    pub const fn probe_register_byte_offset(self, register: ProbeRegister) -> Option<usize> {
        match (self, register) {
            (Self::X86_64, ProbeRegister::Pc) => Some(crate::pt_regs_indices::RIP * 8),
            (Self::X86_64, ProbeRegister::Sp) => Some(crate::pt_regs_indices::RSP * 8),
            (Self::Aarch64, ProbeRegister::Pc) => Some(256),
            (Self::Aarch64, ProbeRegister::Sp) => Some(248),
            (Self::Unknown, _) => None,
        }
    }

    pub const fn current() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::Unknown
        }
    }

    pub const fn dwarf_register_roles(self) -> Option<DwarfRegisterRoles> {
        match self {
            Self::X86_64 => Some(DwarfRegisterRoles {
                stack_pointer: x86_64::RSP,
                frame_pointer: x86_64::RBP,
                return_address: x86_64::RIP,
            }),
            // AADWARF64: X29 = FP, X30 = LR, register 31 = SP.
            // https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst
            Self::Aarch64 => Some(DwarfRegisterRoles {
                stack_pointer: 31,
                frame_pointer: 29,
                return_address: 30,
            }),
            Self::Unknown => None,
        }
    }

    /// General-purpose registers preserved across a call. SP is recovered via CFA.
    /// SIMD registers are deliberately excluded: their preservation can be partial.
    pub const fn is_callee_saved_gpr(self, register: u16) -> bool {
        match self {
            Self::X86_64 => matches!(register, 3 | 6 | 12..=15),
            // AAPCS64 preserves X19-X29; X18 is platform-specific, X30 is LR.
            // https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
            Self::Aarch64 => matches!(register, 19..=29),
            Self::Unknown => false,
        }
    }

    /// Offset from CFA to the stack pointer on function entry.
    pub const fn entry_sp_cfa_offset(self, address_size: u8) -> Option<i64> {
        match (self, address_size) {
            (Self::X86_64, 8) => Some(-8), // CALL pushes the return address.
            (Self::Aarch64, 8) => Some(0), // BL stores the return address in LR.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_pc_has_its_own_context_location_on_arm64() {
        assert_eq!(
            TargetArch::Aarch64.probe_register_byte_offset(ProbeRegister::Pc),
            Some(256)
        );
        assert_eq!(
            TargetArch::Aarch64.probe_register_byte_offset(ProbeRegister::Sp),
            Some(248)
        );
        assert_eq!(
            TargetArch::Aarch64.dwarf_register_byte_offset(16),
            Some(128)
        );
        assert_eq!(TargetArch::Aarch64.dwarf_register_byte_offset(32), None);
        assert_eq!(
            TargetArch::Unknown.probe_register_byte_offset(ProbeRegister::Pc),
            None
        );
    }

    #[test]
    fn abi_recovery_distinguishes_stack_return_addresses_from_link_registers() {
        let x86 = TargetArch::X86_64;
        let arm = TargetArch::Aarch64;
        assert_eq!(x86.entry_sp_cfa_offset(8), Some(-8));
        assert_eq!(arm.entry_sp_cfa_offset(8), Some(0));
        assert_eq!(arm.dwarf_register_roles().unwrap().return_address, 30);
        assert_eq!(arm.dwarf_register_roles().unwrap().stack_pointer, 31);
        for register in 0..=32 {
            assert_eq!(
                x86.is_callee_saved_gpr(register),
                [3, 6, 12, 13, 14, 15].contains(&register)
            );
            assert_eq!(
                arm.is_callee_saved_gpr(register),
                (19..=29).contains(&register)
            );
        }
    }

    #[test]
    fn unsupported_abis_do_not_inherit_host_recovery_rules() {
        assert_eq!(TargetArch::Unknown.dwarf_register_roles(), None);
        assert_eq!(TargetArch::Unknown.entry_sp_cfa_offset(8), None);
        assert!(!TargetArch::Unknown.is_callee_saved_gpr(6));
        for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
            assert_eq!(arch.entry_sp_cfa_offset(4), None);
        }
    }
}
