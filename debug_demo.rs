#!/usr/bin/env cargo +nightly -Zscript

//! Demo script to showcase the new EvaluationResult Debug traits
//! Run with: `cargo +nightly -Zscript debug_demo.rs`

use ghostscope_binary::expression::*;

fn main() {
    println!("🎪 New EvaluationResult Debug Trait Demo\n");

    // Example 1: DirectValue variants
    println!("📊 DirectValue Examples:");
    
    let constant = EvaluationResult::DirectValue(
        DirectValueResult::Constant(42)
    );
    println!("  Constant:      {:?}", constant);
    
    let big_constant = EvaluationResult::DirectValue(
        DirectValueResult::Constant(0x12345678)
    );
    println!("  Big Constant:  {:?}", big_constant);
    
    let reg_value = EvaluationResult::DirectValue(
        DirectValueResult::RegisterValue(5) // RDI
    );
    println!("  Register Val:  {:?}", reg_value);
    
    let implicit = EvaluationResult::DirectValue(
        DirectValueResult::ImplicitValue(vec![42, 0, 0, 0])
    );
    println!("  Implicit:      {:?}", implicit);
    
    // Example 2: Complex computed value (like your (RDI * RSI) + 42 example)
    let complex_value = EvaluationResult::DirectValue(
        DirectValueResult::ComputedValue {
            steps: vec![
                AccessStep::LoadRegister(5), // RDI
                AccessStep::LoadRegister(4), // RSI  
                AccessStep::ArithmeticOp(ArithOp::Mul),
                AccessStep::AddConstant(42),
            ],
            requires_registers: vec![4, 5], // RSI, RDI
            requires_frame_base: false,
            requires_cfa: false,
        }
    );
    println!("  Complex Value: {:?}", complex_value);
    
    println!("\n🏠 MemoryLocation Examples:");
    
    // Example 3: Memory locations
    let addr = EvaluationResult::MemoryLocation(
        LocationResult::Address(0x7fff12345678)
    );
    println!("  Address:       {:?}", addr);
    
    let reg_addr = EvaluationResult::MemoryLocation(
        LocationResult::RegisterAddress { 
            register: 6, // RBP
            offset: Some(-8),
            size: Some(4),
        }
    );
    println!("  Reg Address:   {:?}", reg_addr);
    
    let frame_offset = EvaluationResult::MemoryLocation(
        LocationResult::FrameOffset(-16)
    );
    println!("  Frame Offset:  {:?}", frame_offset);
    
    // Example 4: Complex computed location
    let complex_location = EvaluationResult::MemoryLocation(
        LocationResult::ComputedLocation {
            steps: vec![
                AccessStep::LoadRegister(6), // RBP
                AccessStep::AddConstant(-8),
                AccessStep::LoadRegister(5), // RDI
                AccessStep::ArithmeticOp(ArithOp::Add),
            ],
            requires_registers: vec![5, 6], // RDI, RBP
            requires_frame_base: false,
            requires_cfa: false,
        }
    );
    println!("  Complex Loc:   {:?}", complex_location);
    
    println!("\n🔧 Special Cases:");
    
    let optimized = EvaluationResult::Optimized;
    println!("  Optimized:     {:?}", optimized);
    
    let composite = EvaluationResult::Composite(vec![
        EvaluationResult::DirectValue(DirectValueResult::Constant(1)),
        EvaluationResult::MemoryLocation(LocationResult::Address(0x1000)),
    ]);
    println!("  Composite:     {:?}", composite);
    
    println!("\n✨ Compare with old messy approach:");
    println!("  Old way would need runtime checks like:");
    println!("  if matches!(result, EvaluationResult::Register(ref r) if !r.dereference)");
    println!("  Now it's just: DirectValue vs MemoryLocation!");
    
    println!("\n🎯 Key Benefits:");
    println!("  • Type safety: DirectValue can't be dereferenced by mistake");
    println!("  • Clear semantics: Value vs Location is explicit"); 
    println!("  • Better Debug: See exactly what each expression represents");
    println!("  • No runtime checks: Compiler enforces correct usage");
}