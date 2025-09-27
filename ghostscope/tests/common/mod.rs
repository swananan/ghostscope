#![allow(clippy::uninlined_format_args)]
#![allow(dead_code)]

//! Common test utilities shared across integration tests

use lazy_static::lazy_static;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();
static COMPILE: Once = Once::new();

/// Initialize logging for tests (call once per test)
pub fn init() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("off")
            .try_init()
            .ok();
    });
}

static COMPILE_OPTIMIZED: Once = Once::new();

/// Optimization level for test program compilation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OptimizationLevel {
    Debug, // -O0 (default)
    #[allow(dead_code)]
    O1, // -O1
    O2,    // -O2
    #[allow(dead_code)]
    O3, // -O3
}

impl OptimizationLevel {
    fn as_make_target(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "sample_program",
            OptimizationLevel::O1 => "sample_program_o1",
            OptimizationLevel::O2 => "sample_program_o2",
            OptimizationLevel::O3 => "sample_program_o3",
        }
    }

    fn as_binary_name(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "sample_program",
            OptimizationLevel::O1 => "sample_program_o1",
            OptimizationLevel::O2 => "sample_program_o2",
            OptimizationLevel::O3 => "sample_program_o3",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "Debug (O0)",
            OptimizationLevel::O1 => "Optimized (O1)",
            OptimizationLevel::O2 => "Optimized (O2)",
            OptimizationLevel::O3 => "Highly Optimized (O3)",
        }
    }
}

/// Compile test program (call once for all tests)
pub fn ensure_test_program_compiled() -> anyhow::Result<()> {
    ensure_test_program_compiled_with_opt(OptimizationLevel::Debug)
}

/// Compile test program with specific optimization level
pub fn ensure_test_program_compiled_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let mut result = Ok(());

    let compile_fn = || {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let sample_program_dir = fixtures_path.join("sample_program");

        println!(
            "Compiling sample_program {} in {:?}",
            opt_level.description(),
            sample_program_dir
        );

        // Clean first (only for debug builds to avoid conflicts)
        if opt_level == OptimizationLevel::Debug {
            let clean_output = Command::new("make")
                .arg("clean")
                .current_dir(&sample_program_dir)
                .output();

            match clean_output {
                Ok(_) => println!("✓ Cleaned sample_program build directory"),
                Err(e) => {
                    result = Err(anyhow::anyhow!("Failed to clean sample_program: {}", e));
                    return;
                }
            }
        }

        // Compile specific optimization level
        let compile_output = Command::new("make")
            .arg(opt_level.as_make_target())
            .current_dir(&sample_program_dir)
            .output();

        match compile_output {
            Ok(output) => {
                if output.status.success() {
                    println!(
                        "✓ Successfully compiled sample_program {}",
                        opt_level.description()
                    );
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    result = Err(anyhow::anyhow!(
                        "Failed to compile sample_program {}: {}",
                        opt_level.description(),
                        stderr
                    ));
                }
            }
            Err(e) => {
                result = Err(anyhow::anyhow!(
                    "Failed to run make for sample_program {}: {}",
                    opt_level.description(),
                    e
                ));
            }
        }
    };

    match opt_level {
        OptimizationLevel::Debug => {
            COMPILE.call_once(compile_fn);
        }
        _ => {
            COMPILE_OPTIMIZED.call_once(compile_fn);
        }
    }

    result
}

static COMPILE_COMPLEX_DEBUG: Once = Once::new();
static COMPILE_COMPLEX_OPT: Once = Once::new();

fn ensure_complex_program_compiled_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let mut result = Ok(());
    let compile_fn = || {
        let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let program_dir = fixtures_path.join("complex_types_program");

        println!(
            "Compiling complex_types_program {} in {:?}",
            opt_level.description(),
            program_dir
        );

        // Clean first for debug builds
        if opt_level == OptimizationLevel::Debug {
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(&program_dir)
                .output();
        }

        let target = match opt_level {
            OptimizationLevel::Debug => "complex_types_program",
            OptimizationLevel::O1 => "complex_types_program_o1",
            OptimizationLevel::O2 => "complex_types_program_o2",
            OptimizationLevel::O3 => "complex_types_program_o3",
        };

        let compile_output = Command::new("make")
            .arg(target)
            .current_dir(&program_dir)
            .output();

        match compile_output {
            Ok(output) => {
                if output.status.success() {
                    println!(
                        "✓ Successfully compiled complex_types_program {}",
                        opt_level.description()
                    );
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    result = Err(anyhow::anyhow!(
                        "Failed to compile complex_types_program {}: {}",
                        opt_level.description(),
                        stderr
                    ));
                }
            }
            Err(e) => {
                result = Err(anyhow::anyhow!(
                    "Failed to run make for complex_types_program {}: {}",
                    opt_level.description(),
                    e
                ));
            }
        }
    };

    match opt_level {
        OptimizationLevel::Debug => COMPILE_COMPLEX_DEBUG.call_once(compile_fn),
        _ => COMPILE_COMPLEX_OPT.call_once(compile_fn),
    }

    result
}

/// Test fixtures manager
pub struct TestFixtures {
    base_path: PathBuf,
}

impl TestFixtures {
    pub fn new() -> Self {
        let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        Self { base_path }
    }

    pub fn get_test_binary(&self, name: &str) -> anyhow::Result<PathBuf> {
        self.get_test_binary_with_opt(name, OptimizationLevel::Debug)
    }

    pub fn get_test_binary_with_opt(
        &self,
        name: &str,
        opt_level: OptimizationLevel,
    ) -> anyhow::Result<PathBuf> {
        let binary_path = if name == "sample_program" {
            // Ensure compilation happens before getting binary path
            ensure_test_program_compiled_with_opt(opt_level)?;
            self.base_path
                .join("sample_program")
                .join(opt_level.as_binary_name())
        } else if name == "complex_types_program" {
            ensure_complex_program_compiled_with_opt(opt_level)?;
            let bin_name = match opt_level {
                OptimizationLevel::Debug => "complex_types_program",
                OptimizationLevel::O1 => "complex_types_program_o1",
                OptimizationLevel::O2 => "complex_types_program_o2",
                OptimizationLevel::O3 => "complex_types_program_o3",
            };
            self.base_path.join("complex_types_program").join(bin_name)
        } else {
            // Fallback to old binaries directory (debug only)
            self.base_path.join("binaries").join(name).join(name)
        };

        if !binary_path.exists() {
            anyhow::bail!(
                "Test binary not found: {} ({})",
                binary_path.display(),
                opt_level.description()
            );
        }

        Ok(binary_path)
    }
}

lazy_static! {
    pub static ref FIXTURES: TestFixtures = TestFixtures::new();
}
