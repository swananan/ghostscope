use ghostscope_compiler;

pub fn hello() -> String {
    format!("Frontend: {}", ghostscope_compiler::hello())
}

/// Compiles a source code string in our small language and returns the LLVM IR
pub fn compile(source: &str) -> Result<String, String> {
    match ghostscope_compiler::compile_to_llvm_ir(source) {
        Ok(llvm_ir) => Ok(llvm_ir),
        Err(e) => Err(format!("Compilation error: {}", e)),
    }
}

/// A simple example of our small language features
pub fn example_code() -> &'static str {
    r#"
    // Define some variables
    a = 10;
    b = 20;
    c = a + b * 2;
    
    // Print variable values
    print a;
    print b;
    print c;
    
    // Print calculations
    print a + b;
    print a * b;
    
    // Show backtrace
    backtrace;
    
    // Pointer example (simplified)
    ptr = &a;  // Not fully implemented
    print *ptr;
    
    // Struct access (simplified)
    person.name = "John";  // Not fully implemented
    print person.name;
    "#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "Frontend: Hello from ghostscope-compiler!");
    }

    #[test]
    fn test_compile() {
        let result = compile("print 42;");
        assert!(result.is_ok());
    }
}
