//! Linux AArch64 probe context and conservative instruction-prefix validation.

use crate::PlatformError;

/// Mask for Linux userspace instruction addresses on the running ARM64 kernel.
/// XPACLRI uses the configured VA width and needs no access to the tracee's keys.
/// Its HINT encoding is a NOP on CPUs without pointer authentication.
pub fn native_instruction_address_mask() -> Option<u64> {
    #[cfg(target_arch = "aarch64")]
    {
        // Bit 55 selects the upper/lower address range. Linux userspace uses
        // the lower range; top-byte tags are not part of a symbol's address.
        let mut mask = 0x007f_ffff_ffff_ffffu64;
        // SAFETY: this changes only the declared register, with no memory or
        // stack access. HINT #7 is available even without FEAT_PAuth.
        unsafe {
            core::arch::asm!("hint #7", inout("x30") mask, options(nomem, nostack, preserves_flags));
        }
        Some(mask)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        None
    }
}

/// Linux `user_pt_regs` is the prefix of `pt_regs`: X0-X30, SP, PC, PSTATE.
/// https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/ptrace.h
pub fn dwarf_register_byte_offset(register: u16) -> Option<usize> {
    match register {
        0..=31 => Some(usize::from(register) * 8),
        // DWARF register 32 is reserved, not the saved PC. SIMD registers
        // are not present in the uprobe general-purpose register context.
        _ => None,
    }
}

pub fn dwarf_register_name(register: u16) -> Option<&'static str> {
    const NAMES: [&str; 32] = [
        "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13",
        "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26",
        "X27", "X28", "X29", "X30", "SP",
    ];
    const SIMD_NAMES: [&str; 32] = [
        "V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13",
        "V14", "V15", "V16", "V17", "V18", "V19", "V20", "V21", "V22", "V23", "V24", "V25", "V26",
        "V27", "V28", "V29", "V30", "V31",
    ];
    match register {
        64..=95 => SIMD_NAMES.get(usize::from(register - 64)).copied(),
        _ => NAMES.get(usize::from(register)).copied(),
    }
}

/// Validate a little-endian A64 prefix before moving an entry probe.
/// Only known straight-line data-processing and load/store classes are accepted.
/// Unknown instructions (including all branches, calls, returns and traps)
/// keep the probe at entry; this is deliberately not a general A64 decoder.
pub fn validate_probe_prefix(code: &[u8], start: u64) -> Result<(), PlatformError> {
    let fail = |detail: String| PlatformError::PrologueAnalysisFailed(detail);
    if !start.is_multiple_of(4) || !code.len().is_multiple_of(4) {
        return Err(fail("unaligned or truncated A64 instruction prefix".into()));
    }
    start
        .checked_add(code.len() as u64)
        .ok_or_else(|| fail("A64 instruction prefix address overflow".into()))?;
    for (index, bytes) in code.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes(*bytes);
        // These instruction classes cannot branch or call. Prologues also
        // compute aligned local addresses, load stack canaries, and move
        // indirect argument pointers into callee-saved registers.
        // PACIASP/PACIBSP sign LR without changing control flow or the
        // argument registers. They commonly precede the parameter spills.
        let hint = matches!(
            word,
            0xd503201f | 0xd503245f | 0xd503249f | 0xd50324df | 0xd503233f | 0xd503237f
        );
        let immediate = matches!(word & 0x1f00_0000, 0x1000_0000 | 0x1100_0000)
            || matches!(
                word & 0x1f80_0000,
                0x1200_0000 | 0x1280_0000 | 0x1300_0000 | 0x1380_0000
            );
        let register = matches!(
            word & 0x1f00_0000,
            0x0a00_0000 | 0x0b00_0000 | 0x1a00_0000 | 0x1b00_0000
        );
        let load_store = matches!(word & 0x3b00_0000, 0x1800_0000 | 0x3800_0000 | 0x3900_0000)
            || word & 0x3a00_0000 == 0x2800_0000;
        if !(hint || immediate || register || load_store) {
            return Err(fail(format!(
                "unsupported A64 instruction 0x{word:08x} at 0x{:x}",
                start + (index * 4) as u64
            )));
        }
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
const _: () = {
    use aya_ebpf_bindings::bindings::user_pt_regs;
    assert!(core::mem::offset_of!(user_pt_regs, regs) == 0);
    assert!(core::mem::offset_of!(user_pt_regs, sp) == 248);
    assert!(core::mem::offset_of!(user_pt_regs, pc) == 256);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn native_mask_strips_both_return_address_keys() {
        let mask = native_instruction_address_mask().unwrap();
        let address = native_mask_strips_both_return_address_keys as *const () as u64;
        for key_b in [false, true] {
            let mut signed = address;
            // SAFETY: HINTs sign only the declared LR; no branch uses it.
            unsafe {
                if key_b {
                    core::arch::asm!("hint #27", inout("x30") signed, options(nomem, nostack, preserves_flags));
                } else {
                    core::arch::asm!("hint #25", inout("x30") signed, options(nomem, nostack, preserves_flags));
                }
            }
            assert_eq!(signed & mask, address);
            let mut stripped = signed;
            // SAFETY: XPACLRI modifies only the declared register.
            unsafe {
                core::arch::asm!("hint #7", inout("x30") stripped, options(nomem, nostack, preserves_flags));
            }
            assert_eq!(signed & mask, stripped);
        }
    }

    #[test]
    fn accepts_llvm_assembled_stack_setup_and_argument_spills() {
        // Encodings checked with LLVM 22 llvm-mc -triple=aarch64 -show-encoding.
        let words = [
            0xd503245fu32, // BTI c
            0xd503233f,    // PACIASP
            0xd503237f,    // PACIBSP
            0xa9be7bfd,    // STP X29,X30,[SP,#-32]!
            0x910003fd,    // MOV X29,SP
            0xd10103ff,    // SUB SP,SP,#64
            0xf90007e0,    // STR X0,[SP,#8]
            0xb90007e1,    // STR W1,[SP,#4]
            0xf81f83a2,    // STUR X2,[X29,#-8]
            0xb81fc3a3,    // STUR W3,[X29,#-4]
            0xa90153f3,    // STP X19,X20,[SP,#16]
            0xf81d0ffe,    // STR X30,[SP,#-48]!
            0xaa0003f3,    // MOV X19,X0 (indirect aggregate argument)
            0x910243e0,    // ADD X0,SP,#144 (aligned local buffer)
            0xd1020000,    // SUB X0,X0,#128
            0xd346fc00,    // LSR X0,X0,#6
            0xd37ae400,    // LSL X0,X0,#6
            0xf9400022,    // LDR X2,[X1] (stack canary)
            0xd503201f,    // NOP
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        validate_probe_prefix(&code, 0x1000).unwrap();
        for length in 1..code.len() {
            assert_eq!(
                validate_probe_prefix(&code[..length], 0x1000).is_ok(),
                length.is_multiple_of(4)
            );
        }
    }

    #[test]
    fn context_maps_gprs_and_sp_but_not_reserved_or_simd_registers() {
        assert_eq!(dwarf_register_byte_offset(0), Some(0));
        assert_eq!(dwarf_register_byte_offset(29), Some(232));
        assert_eq!(dwarf_register_byte_offset(30), Some(240));
        assert_eq!(dwarf_register_byte_offset(31), Some(248));
        assert_eq!(dwarf_register_name(31), Some("SP"));
        assert_eq!(dwarf_register_name(64), Some("V0"));
        assert_eq!(dwarf_register_name(95), Some("V31"));
        for register in [32, 33, 64, 95, u16::MAX] {
            assert_eq!(dwarf_register_byte_offset(register), None);
        }
        for register in [32, 33, u16::MAX] {
            assert_eq!(dwarf_register_name(register), None);
        }
    }

    #[test]
    fn rejects_control_flow_unknown_words_and_misalignment() {
        for word in [
            0x14000000u32,
            0x94000000,
            0x54000000,
            0xb4000000,
            0x36000000,
            0xd61f0000,
            0xd63f0000,
            0xd65f03c0,
            0xd4000001,
            0xd4200000,
            0,
            0xffffffff,
        ] {
            assert!(
                validate_probe_prefix(&word.to_le_bytes(), 0x1000).is_err(),
                "{word:x}"
            );
        }
        assert!(validate_probe_prefix(&[0; 3], 0x1000).is_err());
        assert!(validate_probe_prefix(&0xd503201fu32.to_le_bytes(), 0x1001).is_err());
        assert!(validate_probe_prefix(&0xd503201fu32.to_le_bytes(), u64::MAX - 3).is_err());
    }
}
