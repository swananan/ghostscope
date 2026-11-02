use crate::types::{CodeReader, PlatformError};
use tracing::{debug, warn};

/// Platform-specific calling convention and prologue analysis
pub trait CallingConvention {
    /// Get the register number for a parameter at the given index
    fn get_parameter_register(param_index: usize) -> Option<u16>;

    /// Maximum number of parameters passed in registers
    fn max_register_parameters() -> usize;

    /// Skip function prologue and return the address where the function body starts
    fn skip_prologue<R: CodeReader>(
        function_start: u64,
        code_reader: &R,
    ) -> Result<u64, PlatformError>;

    /// Check if we're currently in the function prologue
    fn is_in_prologue<R: CodeReader>(pc: u64, function_start: u64, code_reader: &R) -> bool {
        match Self::skip_prologue(function_start, code_reader) {
            Ok(prologue_end) => pc < prologue_end,
            Err(_) => false, // Conservative: assume not in prologue if we can't determine
        }
    }
}

/// x86-64 System V ABI calling convention
pub struct X86_64SystemV;

impl CallingConvention for X86_64SystemV {
    fn get_parameter_register(param_index: usize) -> Option<u16> {
        // System V ABI parameter registers (DWARF register numbers)
        const PARAMETER_REGISTERS: [u16; 6] = [
            5, // RDI (DWARF register 5) - 1st parameter
            4, // RSI (DWARF register 4) - 2nd parameter
            1, // RDX (DWARF register 1) - 3rd parameter
            2, // RCX (DWARF register 2) - 4th parameter
            8, // R8  (DWARF register 8) - 5th parameter
            9, // R9  (DWARF register 9) - 6th parameter
        ];

        PARAMETER_REGISTERS.get(param_index).copied()
    }

    fn max_register_parameters() -> usize {
        6
    }

    fn skip_prologue<R: CodeReader>(
        function_start: u64,
        code_reader: &R,
    ) -> Result<u64, PlatformError> {
        debug!(
            "Analyzing prologue for function starting at 0x{:x}",
            function_start
        );

        // 1. Try DWARF line information first
        if let Some(prologue_end) = find_prologue_end_from_line_info(function_start, code_reader) {
            debug!(
                "Found prologue end from DWARF line info: 0x{:x}",
                prologue_end
            );
            return Ok(prologue_end);
        }

        // 2. Fall back to instruction pattern analysis
        if let Some(prologue_end) =
            analyze_x86_64_prologue_instructions(function_start, code_reader)
        {
            debug!(
                "Found prologue end from instruction analysis: 0x{:x}",
                prologue_end
            );
            return Ok(prologue_end);
        }

        // 3. Cannot determine prologue end
        warn!(
            "Cannot determine prologue end for function at 0x{:x}",
            function_start
        );
        Err(PlatformError::PrologueAnalysisFailed(
            "Cannot determine prologue end - parameters may be optimized".to_string(),
        ))
    }
}

/// AAPCS64 integer/pointer register slots. The index is the ABI GPR slot,
/// not a source parameter index for mixed, aggregate, or indirect arguments.
pub struct Aarch64Aapcs;

impl CallingConvention for Aarch64Aapcs {
    fn get_parameter_register(param_index: usize) -> Option<u16> {
        (param_index < 8).then_some(param_index as u16)
    }

    fn max_register_parameters() -> usize {
        8
    }

    fn skip_prologue<R: CodeReader>(
        function_start: u64,
        code_reader: &R,
    ) -> Result<u64, PlatformError> {
        let error = || {
            PlatformError::PrologueAnalysisFailed(
                "no validated AArch64 statement boundary after entry".into(),
            )
        };
        let candidate = code_reader
            .find_next_stmt_address(function_start)
            .ok_or_else(error)?;
        let size = candidate
            .checked_sub(function_start)
            .filter(|size| *size > 0 && *size <= 4096)
            .ok_or_else(error)? as usize;
        let code = code_reader
            .read_code_bytes(function_start, size)
            .ok_or_else(error)?;
        if code.len() != size {
            return Err(error());
        }
        crate::aarch64::validate_probe_prefix(&code, function_start)?;
        Ok(candidate)
    }
}

/// Find prologue end using DWARF line number information
fn find_prologue_end_from_line_info<R: CodeReader>(
    function_start: u64,
    code_reader: &R,
) -> Option<u64> {
    debug!("Trying to find prologue end from DWARF line info");

    // Try to find the next is_stmt=true instruction after function start
    // This follows GDB's approach for prologue detection
    if let Some(prologue_end) = code_reader.find_next_stmt_address(function_start) {
        debug!(
            "Found next is_stmt=true instruction at 0x{:x} (offset +{} from function start 0x{:x})",
            prologue_end,
            prologue_end - function_start,
            function_start
        );
        Some(prologue_end)
    } else {
        debug!(
            "No next is_stmt=true instruction found after function start 0x{:x}",
            function_start
        );
        None
    }
}

/// Analyze x86-64 instruction patterns to find prologue end
fn analyze_x86_64_prologue_instructions<R: CodeReader>(
    function_start: u64,
    code_reader: &R,
) -> Option<u64> {
    debug!(
        "Analyzing x86-64 prologue instructions starting at 0x{:x}",
        function_start
    );

    let mut pc = function_start;

    // Skip endbr64 instruction if present (0xf3 0x0f 0x1e 0xfa)
    if let Some(bytes) = code_reader.read_code_bytes(pc, 4) {
        if bytes.len() >= 4 && bytes == [0xf3, 0x0f, 0x1e, 0xfa] {
            debug!("Found endbr64 at 0x{:x}, skipping", pc);
            pc += 4;
        }
    }

    // Look for push %rbp (0x55)
    if let Some(bytes) = code_reader.read_code_bytes(pc, 1) {
        if !bytes.is_empty() && bytes[0] == 0x55 {
            debug!("Found push %%rbp at 0x{:x}", pc);
            pc += 1;

            // Look for mov %rsp,%rbp patterns
            if let Some(mov_bytes) = code_reader.read_code_bytes(pc, 3) {
                if mov_bytes.len() >= 3 {
                    // Pattern 1: 0x48 0x89 0xe5 (mov %rsp,%rbp)
                    // Pattern 2: 0x48 0x8b 0xec (mov %rsp,%rbp - alternative encoding)
                    if mov_bytes == [0x48, 0x89, 0xe5] || mov_bytes == [0x48, 0x8b, 0xec] {
                        debug!("Found mov %%rsp,%%rbp at 0x{:x}", pc);
                        pc += 3;

                        // Skip optional stack allocation: sub $imm,%rsp
                        pc = skip_stack_allocation(pc, code_reader);

                        debug!("Prologue analysis complete, body starts at 0x{:x}", pc);
                        return Some(pc);
                    }
                }
            }

            // Check for 32-bit mov %esp,%ebp patterns
            if let Some(mov_bytes) = code_reader.read_code_bytes(pc, 2) {
                if mov_bytes.len() >= 2 {
                    // Pattern: 0x89 0xe5 (mov %esp,%ebp)
                    // Pattern: 0x8b 0xec (mov %esp,%ebp - alternative)
                    if mov_bytes == [0x89, 0xe5] || mov_bytes == [0x8b, 0xec] {
                        debug!("Found 32-bit mov %%esp,%%ebp at 0x{:x}", pc);
                        pc += 2;
                        pc = skip_stack_allocation(pc, code_reader);
                        return Some(pc);
                    }
                }
            }
        }
    }

    // Check for frameless function (no %rbp setup)
    // Look for immediate stack allocation: sub $imm,%rsp
    let allocation_end = skip_stack_allocation(function_start, code_reader);
    if allocation_end > function_start {
        debug!("Found frameless function with stack allocation");
        return Some(allocation_end);
    }

    // If no prologue pattern found, assume function starts immediately
    debug!("No standard prologue pattern found, assuming function body starts immediately");
    Some(function_start)
}

/// Skip stack allocation instructions and return the address after them
fn skip_stack_allocation<R: CodeReader>(pc: u64, code_reader: &R) -> u64 {
    let mut current_pc = pc;

    // Look for sub $imm,%rsp patterns
    if let Some(bytes) = code_reader.read_code_bytes(current_pc, 4) {
        if bytes.len() >= 4 {
            // Pattern 1: 0x48 0x83 0xec 0xXX (sub $imm8,%rsp)
            if bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xec {
                debug!("Found sub $0x{:x},%%rsp at 0x{:x}", bytes[3], current_pc);
                current_pc += 4;
            }
            // Pattern 2: 0x48 0x81 0xec (sub $imm32,%rsp) - need to read more bytes
            else if bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xec {
                if let Some(extended_bytes) = code_reader.read_code_bytes(current_pc, 7) {
                    if extended_bytes.len() >= 7 {
                        let imm32 = u32::from_le_bytes([
                            extended_bytes[3],
                            extended_bytes[4],
                            extended_bytes[5],
                            extended_bytes[6],
                        ]);
                        debug!("Found sub $0x{:x},%%rsp at 0x{:x}", imm32, current_pc);
                        current_pc += 7;
                    }
                }
            }
        }
    }

    current_pc
}

/// Check if a parameter should be accessed via register in the current context
/// Returns the register number if parameter should be in register, None otherwise
pub fn get_parameter_register_in_context<R: CodeReader>(
    param_index: usize,
    param_name: &str,
    pc: u64,
    function_start: u64,
    code_reader: &R,
) -> Result<Option<u16>, PlatformError> {
    get_parameter_register_for_target(
        crate::TargetArch::current(),
        param_index,
        param_name,
        pc,
        function_start,
        code_reader,
    )
}

/// Resolve a scalar GPR argument slot using an explicit target ABI.
pub fn get_parameter_register_for_target<R: CodeReader>(
    architecture: crate::TargetArch,
    param_index: usize,
    param_name: &str,
    pc: u64,
    function_start: u64,
    code_reader: &R,
) -> Result<Option<u16>, PlatformError> {
    match architecture {
        crate::TargetArch::X86_64 => parameter_register::<X86_64SystemV, R>(
            param_index,
            param_name,
            pc,
            function_start,
            code_reader,
        ),
        crate::TargetArch::Aarch64 => parameter_register::<Aarch64Aapcs, R>(
            param_index,
            param_name,
            pc,
            function_start,
            code_reader,
        ),
        crate::TargetArch::Unknown => Err(PlatformError::UnsupportedArchitecture(
            "unknown target ABI".into(),
        )),
    }
}

fn parameter_register<C: CallingConvention, R: CodeReader>(
    param_index: usize,
    param_name: &str,
    pc: u64,
    function_start: u64,
    code_reader: &R,
) -> Result<Option<u16>, PlatformError> {
    debug!(
        "Checking parameter '{}' (index={}) register access at PC 0x{:x}, function_start=0x{:x}",
        param_name, param_index, pc, function_start
    );

    if C::is_in_prologue(pc, function_start, code_reader) {
        debug!("PC 0x{:x} is in prologue, checking register parameter", pc);

        // In prologue, parameter is in register
        if let Some(reg) = C::get_parameter_register(param_index) {
            debug!("Parameter '{}' is in register {}", param_name, reg);
            Ok(Some(reg))
        } else {
            Err(PlatformError::ParameterOptimized(format!(
                "Parameter '{param_name}' (slot {param_index}) exceeds {} GPR argument slots",
                C::max_register_parameters()
            )))
        }
    } else {
        debug!(
            "PC 0x{:x} is after prologue, parameter should be on stack",
            pc
        );

        // After prologue, parameter should be on stack
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ArmCode {
        candidate: Option<u64>,
        code: Vec<u8>,
    }

    impl CodeReader for ArmCode {
        fn read_code_bytes(&self, _address: u64, size: usize) -> Option<Vec<u8>> {
            self.code.get(..size).map(<[u8]>::to_vec)
        }
        fn get_source_location_slow(&self, _address: u64) -> Option<crate::SourceLocation> {
            None
        }
        fn find_next_stmt_address(&self, _start: u64) -> Option<u64> {
            self.candidate
        }
    }

    #[test]
    fn arm_parameter_slots_require_a_validated_statement_boundary() {
        // LLVM llvm-mc -triple=aarch64: STP X29,X30,[SP,#-32]!; MOV X29,SP.
        let mut reader = ArmCode {
            candidate: Some(0x1008),
            code: vec![0xfd, 0x7b, 0xbe, 0xa9, 0xfd, 0x03, 0x00, 0x91],
        };
        assert_eq!(
            Aarch64Aapcs::skip_prologue(0x1000, &reader).unwrap(),
            0x1008
        );
        for slot in 0..8 {
            assert_eq!(
                get_parameter_register_for_target(
                    crate::TargetArch::Aarch64,
                    slot,
                    "arg",
                    0x1000,
                    0x1000,
                    &reader
                )
                .unwrap(),
                Some(slot as u16)
            );
        }
        assert_eq!(Aarch64Aapcs::get_parameter_register(8), None);
        assert_eq!(Aarch64Aapcs::get_parameter_register(usize::MAX), None);
        assert_eq!(
            get_parameter_register_for_target(
                crate::TargetArch::Aarch64,
                0,
                "arg",
                0x1008,
                0x1000,
                &reader
            )
            .unwrap(),
            None
        );
        for candidate in [None, Some(0xffc), Some(0x1000), Some(0x1006), Some(0x2004)] {
            reader.candidate = candidate;
            assert!(Aarch64Aapcs::skip_prologue(0x1000, &reader).is_err());
        }
        reader.candidate = Some(0x1008);
        reader.code[..4].copy_from_slice(&0x94000000u32.to_le_bytes()); // BL
        assert!(Aarch64Aapcs::skip_prologue(0x1000, &reader).is_err());
    }

    #[test]
    fn test_x86_64_parameter_registers() {
        assert_eq!(X86_64SystemV::get_parameter_register(0), Some(5)); // RDI
        assert_eq!(X86_64SystemV::get_parameter_register(1), Some(4)); // RSI
        assert_eq!(X86_64SystemV::get_parameter_register(2), Some(1)); // RDX
        assert_eq!(X86_64SystemV::get_parameter_register(3), Some(2)); // RCX
        assert_eq!(X86_64SystemV::get_parameter_register(4), Some(8)); // R8
        assert_eq!(X86_64SystemV::get_parameter_register(5), Some(9)); // R9
        assert_eq!(X86_64SystemV::get_parameter_register(6), None); // Beyond registers

        assert_eq!(X86_64SystemV::max_register_parameters(), 6);
    }
}
