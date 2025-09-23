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
    debug!(
        "Checking parameter '{}' (index={}) register access at PC 0x{:x}, function_start=0x{:x}",
        param_name, param_index, pc, function_start
    );

    // Use x86-64 System V ABI for now
    // TODO: Detect platform and use appropriate calling convention

    if X86_64SystemV::is_in_prologue(pc, function_start, code_reader) {
        debug!("PC 0x{:x} is in prologue, checking register parameter", pc);

        // In prologue, parameter is in register
        if let Some(reg) = X86_64SystemV::get_parameter_register(param_index) {
            debug!("Parameter '{}' is in register {}", param_name, reg);
            Ok(Some(reg))
        } else {
            // Parameter index >= 6, likely optimized away
            Err(PlatformError::ParameterOptimized(format!(
                "Parameter '{param_name}' (index {param_index}) likely optimized away (>6 parameters)"
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
