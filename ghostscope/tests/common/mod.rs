//! Common test utilities shared across integration tests
//!
//! This module also exposes a small async runner (`runner`) to invoke the
//! `ghostscope` CLI in a consistent way across tests (PID/target attach,
//! timeout/read/drain behavior, and common flags). Prefer using it instead
//! of re-implementing process management in each test file.

use lazy_static::lazy_static;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::Once;

static INIT: Once = Once::new();
static COMPILE: Once = Once::new();
static REGISTER_CLEANUP: Once = Once::new();

lazy_static! {
    static ref COMPILE_DEBUG_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_OPT_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_STRIPPED_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_COMPLEX_DEBUG_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_COMPLEX_OPT_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_COMPLEX_NOPIE_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_LATE_GLOBALS_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_INLINE_CALLSITE_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_STATIC_SCOPE_DEFAULT_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_STATIC_SCOPE_CLANG_DWARF5_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
}

#[derive(Debug, Clone, Copy)]
enum CleanupCommand {
    Make,
    Cargo,
}

#[derive(Debug, Clone, Copy)]
enum RegisteredFixtureKind {
    Sample,
    ComplexTypes,
    Globals,
    LateGlobals,
    RustGlobal,
    InlineCallsite,
    CppComplex,
    StaticScope,
}

#[derive(Debug, Clone, Copy)]
struct RegisteredFixture {
    name: &'static str,
    directory: &'static str,
    cleanup: CleanupCommand,
    kind: RegisteredFixtureKind,
}

// TODO: Replace this string-keyed registry with a strongly typed FixtureId enum
// and move the per-fixture behavior behind impl methods. This table is an
// intermediate step to remove scattered name-based special cases.
const REGISTERED_FIXTURES: &[RegisteredFixture] = &[
    RegisteredFixture {
        name: "sample_program",
        directory: "sample_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::Sample,
    },
    RegisteredFixture {
        name: "complex_types_program",
        directory: "complex_types_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::ComplexTypes,
    },
    RegisteredFixture {
        name: "globals_program",
        directory: "globals_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::Globals,
    },
    RegisteredFixture {
        name: "late_globals_program",
        directory: "late_globals_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::LateGlobals,
    },
    RegisteredFixture {
        name: "rust_global_program",
        directory: "rust_global_program",
        cleanup: CleanupCommand::Cargo,
        kind: RegisteredFixtureKind::RustGlobal,
    },
    RegisteredFixture {
        name: "inline_callsite_program",
        directory: "inline_callsite_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::InlineCallsite,
    },
    RegisteredFixture {
        name: "cpp_complex_program",
        directory: "cpp_complex_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::CppComplex,
    },
    RegisteredFixture {
        name: "static_scope_program",
        directory: "static_scope_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::StaticScope,
    },
];

fn registered_fixture(name: &str) -> Option<&'static RegisteredFixture> {
    REGISTERED_FIXTURES
        .iter()
        .find(|fixture| fixture.name == name)
}

#[allow(dead_code)]
pub(crate) fn host_pid_is_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).is_dir()
}

/// Initialize logging for tests (call once per test)
pub fn init() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("off")
            .try_init()
            .ok();

        // Touch rarely-used symbols so they aren't considered dead code
        // in test binaries that don't exercise every helper.
        let _ = &COMPILE_COMPLEX_NOPIE;
        let _use_method_ptr: fn(&TestFixtures) -> anyhow::Result<PathBuf> =
            TestFixtures::get_test_binary_complex_nopie;
        let _use_method_ptr2: fn(&TestFixtures, &str) -> anyhow::Result<PathBuf> =
            TestFixtures::get_test_binary;
        let _use_method_ptr3: fn(&TestFixtures, &str, FixtureCompiler) -> anyhow::Result<PathBuf> =
            TestFixtures::get_test_binary_with_compiler;

        // Reference all OptimizationLevel variants so clippy does not flag
        // them as dead code in bins that don't use some levels.
        let _ = OptimizationLevel::O1;
        let _ = OptimizationLevel::O2;
        let _ = OptimizationLevel::O3;
        let _ = OptimizationLevel::Stripped;
        let _ = FixtureCompiler::Default;
        let _ = FixtureCompiler::ClangDwarf5;

        // Exercise runner builder methods so they are referenced in all bins.
        let _ = runner::GhostscopeRunner::new()
            .with_target("/")
            .force_perf_event_array(false)
            .enable_sysmon_shared_lib(false);

        let _use_pid_check: fn(u32) -> bool = host_pid_is_running;
        let _use_compiler_check: fn(FixtureCompiler) -> bool = fixture_compiler_available;
        let _use_static_scope_compile: fn(FixtureCompiler) -> anyhow::Result<()> =
            ensure_static_scope_program_compiled;
    });

    // Register an atexit cleanup to remove built fixtures after all tests
    REGISTER_CLEANUP.call_once(|| unsafe {
        extern "C" fn cleanup_fixtures() {
            // Best-effort cleanup; ignore errors
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            for fixture in REGISTERED_FIXTURES {
                fixture.cleanup(&base);
            }
        }
        libc::atexit(cleanup_fixtures);
    });
}

static COMPILE_OPTIMIZED: Once = Once::new();
static COMPILE_STRIPPED: Once = Once::new();

/// Optimization level for test program compilation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptimizationLevel {
    Debug,    // -O0 (default)
    O1,       // -O1
    O2,       // -O2
    O3,       // -O3
    Stripped, // -O0 with separate debug file (.gnu_debuglink)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureCompiler {
    Default,
    ClangDwarf5,
}

impl FixtureCompiler {
    fn binary_name(&self, base: &str) -> String {
        match self {
            FixtureCompiler::Default => base.to_string(),
            FixtureCompiler::ClangDwarf5 => format!("{base}_clang_dwarf5"),
        }
    }

    fn object_name(&self, base: &str) -> String {
        format!("{}.o", self.binary_name(base))
    }

    fn description(&self) -> &'static str {
        match self {
            FixtureCompiler::Default => "default toolchain",
            FixtureCompiler::ClangDwarf5 => "clang -gdwarf-5",
        }
    }

    fn apply_to_c_make(&self, cmd: &mut Command, base: &str) {
        cmd.arg("all")
            .arg(format!("BINARY={}", self.binary_name(base)))
            .arg(format!("OBJ={}", self.object_name(base)));

        if matches!(self, FixtureCompiler::ClangDwarf5) {
            cmd.arg("CC=clang")
                .arg("CFLAGS=-Wall -Wextra -gdwarf-5 -O0");
        }
    }
}

impl RegisteredFixture {
    fn dir(&self, fixtures_base: &std::path::Path) -> PathBuf {
        fixtures_base.join(self.directory)
    }

    fn cleanup(&self, fixtures_base: &std::path::Path) {
        let dir = self.dir(fixtures_base);
        let mut cmd = match self.cleanup {
            CleanupCommand::Make => {
                let mut cmd = Command::new("make");
                cmd.arg("clean");
                cmd
            }
            CleanupCommand::Cargo => {
                let mut cmd = Command::new("cargo");
                cmd.arg("clean");
                cmd
            }
        };
        let _ = cmd.current_dir(dir).status().is_ok();
    }

    fn binary_path_with_opt(
        &self,
        fixtures_base: &std::path::Path,
        opt_level: OptimizationLevel,
    ) -> anyhow::Result<PathBuf> {
        let dir = self.dir(fixtures_base);
        match self.kind {
            RegisteredFixtureKind::Sample => {
                ensure_test_program_compiled_with_opt(opt_level)?;
                Ok(dir.join(opt_level.as_binary_name()))
            }
            RegisteredFixtureKind::ComplexTypes => {
                ensure_complex_program_compiled_with_opt(opt_level)?;
                let bin_name = match opt_level {
                    OptimizationLevel::Debug => "complex_types_program",
                    OptimizationLevel::O1 => "complex_types_program_o1",
                    OptimizationLevel::O2 => "complex_types_program_o2",
                    OptimizationLevel::O3 => "complex_types_program_o3",
                    OptimizationLevel::Stripped => {
                        anyhow::bail!(
                            "Stripped optimization level not supported for complex_types_program"
                        )
                    }
                };
                Ok(dir.join(bin_name))
            }
            RegisteredFixtureKind::Globals => {
                ensure_globals_program_compiled()?;
                Ok(dir.join("globals_program"))
            }
            RegisteredFixtureKind::LateGlobals => {
                ensure_late_globals_program_compiled()?;
                Ok(dir.join("late_globals_program"))
            }
            RegisteredFixtureKind::RustGlobal => {
                ensure_rust_global_program_compiled()?;
                Ok(dir.join("target").join("debug").join("rust_global_program"))
            }
            RegisteredFixtureKind::InlineCallsite => {
                ensure_inline_callsite_program_compiled()?;
                Ok(dir.join("inline_callsite_program"))
            }
            RegisteredFixtureKind::CppComplex => {
                ensure_cpp_complex_program_compiled()?;
                Ok(dir.join("cpp_complex_program"))
            }
            RegisteredFixtureKind::StaticScope => {
                ensure_static_scope_program_compiled(FixtureCompiler::Default)?;
                Ok(dir.join(FixtureCompiler::Default.binary_name(self.name)))
            }
        }
    }

    fn binary_path_with_compiler(
        &self,
        fixtures_base: &std::path::Path,
        compiler: FixtureCompiler,
    ) -> anyhow::Result<PathBuf> {
        match self.kind {
            RegisteredFixtureKind::StaticScope => {
                ensure_static_scope_program_compiled(compiler)?;
                Ok(self
                    .dir(fixtures_base)
                    .join(compiler.binary_name(self.name)))
            }
            _ if matches!(compiler, FixtureCompiler::Default) => {
                self.binary_path_with_opt(fixtures_base, OptimizationLevel::Debug)
            }
            _ => anyhow::bail!(
                "Compiler override {} is not wired for fixture '{}'",
                compiler.description(),
                self.name
            ),
        }
    }
}

pub fn fixture_compiler_available(compiler: FixtureCompiler) -> bool {
    match compiler {
        FixtureCompiler::Default => true,
        FixtureCompiler::ClangDwarf5 => Command::new("clang")
            .arg("--version")
            .status()
            .map(|status| status.success())
            .unwrap_or(false),
    }
}

impl OptimizationLevel {
    fn as_make_target(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "sample_program",
            OptimizationLevel::O1 => "sample_program_o1",
            OptimizationLevel::O2 => "sample_program_o2",
            OptimizationLevel::O3 => "sample_program_o3",
            OptimizationLevel::Stripped => "sample_program_stripped",
        }
    }

    fn as_binary_name(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "sample_program",
            OptimizationLevel::O1 => "sample_program_o1",
            OptimizationLevel::O2 => "sample_program_o2",
            OptimizationLevel::O3 => "sample_program_o3",
            OptimizationLevel::Stripped => "sample_program_stripped",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            OptimizationLevel::Debug => "Debug (O0)",
            OptimizationLevel::O1 => "Optimized (O1)",
            OptimizationLevel::O2 => "Optimized (O2)",
            OptimizationLevel::O3 => "Highly Optimized (O3)",
            OptimizationLevel::Stripped => "Stripped with .gnu_debuglink",
        }
    }
}

/// Compile test program with specific optimization level
pub fn ensure_test_program_compiled_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    match opt_level {
        OptimizationLevel::Debug => {
            COMPILE.call_once(|| {
                let compile_result = compile_sample_program(opt_level);
                *COMPILE_DEBUG_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_DEBUG_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
        OptimizationLevel::Stripped => {
            COMPILE_STRIPPED.call_once(|| {
                let compile_result = compile_sample_program(opt_level);
                *COMPILE_STRIPPED_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_STRIPPED_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
        _ => {
            COMPILE_OPTIMIZED.call_once(|| {
                let compile_result = compile_sample_program(opt_level);
                *COMPILE_OPT_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_OPT_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
    }
}

fn compile_sample_program(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let sample_program_dir = fixtures_path.join("sample_program");

    println!(
        "Compiling sample_program {} in {sample_program_dir:?}",
        opt_level.description()
    );

    // Compile specific optimization level
    let output = Command::new("make")
        .arg(opt_level.as_make_target())
        .current_dir(sample_program_dir)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run make for sample_program {}: {}",
                opt_level.description(),
                e
            )
        })?;

    if output.status.success() {
        println!(
            "✓ Successfully compiled sample_program {}",
            opt_level.description()
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile sample_program {}: {}",
            opt_level.description(),
            stderr
        ))
    }
}

static COMPILE_COMPLEX_DEBUG: Once = Once::new();
static COMPILE_COMPLEX_OPT: Once = Once::new();
static COMPILE_COMPLEX_NOPIE: Once = Once::new();

fn ensure_complex_program_compiled_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    match opt_level {
        OptimizationLevel::Debug => {
            COMPILE_COMPLEX_DEBUG.call_once(|| {
                let compile_result = compile_complex_program(opt_level);
                *COMPILE_COMPLEX_DEBUG_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_COMPLEX_DEBUG_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
        _ => {
            COMPILE_COMPLEX_OPT.call_once(|| {
                let compile_result = compile_complex_program(opt_level);
                *COMPILE_COMPLEX_OPT_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_COMPLEX_OPT_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
    }
}

fn compile_complex_program(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let program_dir = fixtures_path.join("complex_types_program");

    println!(
        "Compiling complex_types_program {} in {program_dir:?}",
        opt_level.description()
    );

    let target = match opt_level {
        OptimizationLevel::Debug => "complex_types_program",
        OptimizationLevel::O1 => "complex_types_program_o1",
        OptimizationLevel::O2 => "complex_types_program_o2",
        OptimizationLevel::O3 => "complex_types_program_o3",
        OptimizationLevel::Stripped => {
            anyhow::bail!("Stripped optimization level not supported for complex_types_program")
        }
    };

    let output = Command::new("make")
        .arg(target)
        .current_dir(program_dir)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run make for complex_types_program {}: {}",
                opt_level.description(),
                e
            )
        })?;

    if output.status.success() {
        println!(
            "✓ Successfully compiled complex_types_program {}",
            opt_level.description()
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile complex_types_program {}: {}",
            opt_level.description(),
            stderr
        ))
    }
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

    pub fn get_test_binary_with_compiler(
        &self,
        name: &str,
        compiler: FixtureCompiler,
    ) -> anyhow::Result<PathBuf> {
        let binary_path = if let Some(fixture) = registered_fixture(name) {
            fixture.binary_path_with_compiler(&self.base_path, compiler)?
        } else if matches!(compiler, FixtureCompiler::Default) {
            self.base_path.join("binaries").join(name).join(name)
        } else {
            anyhow::bail!(
                "Compiler override {} is not wired for fixture '{}'",
                compiler.description(),
                name
            );
        };

        if !binary_path.exists() {
            anyhow::bail!(
                "Test binary not found: {} ({})",
                binary_path.display(),
                compiler.description()
            );
        }

        Ok(binary_path)
    }

    pub fn get_test_binary_with_opt(
        &self,
        name: &str,
        opt_level: OptimizationLevel,
    ) -> anyhow::Result<PathBuf> {
        let binary_path = if let Some(fixture) = registered_fixture(name) {
            fixture.binary_path_with_opt(&self.base_path, opt_level)?
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

    /// Build and return the non-PIE variant of complex_types_program
    pub fn get_test_binary_complex_nopie(&self) -> anyhow::Result<PathBuf> {
        let program_dir = self.base_path.join("complex_types_program");

        COMPILE_COMPLEX_NOPIE.call_once(|| {
            let compile_result = (|| -> anyhow::Result<()> {
                println!("Compiling complex_types_program Non-PIE (ET_EXEC) in {program_dir:?}");

                let output = Command::new("make")
                    .arg("complex_types_program_nopie")
                    .current_dir(program_dir.clone())
                    .output()
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to run make for complex_types_program Non-PIE: {}",
                            e
                        )
                    })?;

                if output.status.success() {
                    println!("✓ Successfully compiled complex_types_program Non-PIE");
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(anyhow::anyhow!(
                        "Failed to compile complex_types_program Non-PIE: {}",
                        stderr
                    ))
                }
            })();

            *COMPILE_COMPLEX_NOPIE_RESULT.lock().unwrap() = Some(compile_result);
        });

        // Check compilation result
        match COMPILE_COMPLEX_NOPIE_RESULT.lock().unwrap().as_ref() {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(anyhow::anyhow!("{e}")),
            None => panic!("Compilation result should be set after call_once"),
        }

        let bin_path = program_dir.join("complex_types_program_nopie");
        if !bin_path.exists() {
            anyhow::bail!("Non-PIE binary not found: {}", bin_path.display());
        }
        Ok(bin_path)
    }
}

lazy_static! {
    pub static ref FIXTURES: TestFixtures = TestFixtures::new();
}

// Re-export the shared runner for convenience in tests
pub mod runner;
pub mod sandbox;
pub mod targets;
pub mod termination;

static COMPILE_GLOBALS: Once = Once::new();
static COMPILE_LATE_GLOBALS: Once = Once::new();
static COMPILE_RUST_GLOBAL: Once = Once::new();
static COMPILE_INLINE_CALLSITE: Once = Once::new();
static COMPILE_CPP_COMPLEX: Once = Once::new();
static COMPILE_STATIC_SCOPE_DEFAULT: Once = Once::new();
static COMPILE_STATIC_SCOPE_CLANG_DWARF5: Once = Once::new();

fn ensure_globals_program_compiled() -> anyhow::Result<()> {
    let mut result = Ok(());
    COMPILE_GLOBALS.call_once(|| {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/globals_program");
        println!("Compiling globals_program (Debug) in {base:?}");
        let _ = Command::new("make")
            .arg("clean")
            .current_dir(base.clone())
            .status()
            .is_ok();
        match Command::new("make").arg("all").current_dir(base).output() {
            Ok(out) => {
                if out.status.success() {
                    println!("✓ Successfully compiled globals_program and libgvars.so");
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    result = Err(anyhow::anyhow!(
                        "Failed to compile globals_program: {}",
                        stderr
                    ));
                }
            }
            Err(e) => {
                result = Err(anyhow::anyhow!(
                    "Failed to run make for globals_program: {}",
                    e
                ));
            }
        }
    });
    result
}

fn ensure_late_globals_program_compiled() -> anyhow::Result<()> {
    COMPILE_LATE_GLOBALS.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/late_globals_program");
            println!("Compiling late_globals_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled late_globals_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile late_globals_program: {}",
                    stderr
                ))
            }
        })();
        *COMPILE_LATE_GLOBALS_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_LATE_GLOBALS_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_rust_global_program_compiled() -> anyhow::Result<()> {
    let mut result = Ok(());
    COMPILE_RUST_GLOBAL.call_once(|| {
        let base =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_global_program");
        println!("Compiling rust_global_program (Debug) in {base:?}");
        match Command::new("cargo")
            .arg("build")
            .current_dir(base)
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    println!("✓ Successfully compiled rust_global_program");
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    result = Err(anyhow::anyhow!(
                        "Failed to compile rust_global_program: {}",
                        stderr
                    ));
                }
            }
            Err(e) => {
                result = Err(anyhow::anyhow!(
                    "Failed to run make for rust_global_program: {}",
                    e
                ));
            }
        }
    });
    result
}

fn ensure_inline_callsite_program_compiled() -> anyhow::Result<()> {
    COMPILE_INLINE_CALLSITE.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/inline_callsite_program");
            println!("Compiling inline_callsite_program (Optimized O2) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled inline_callsite_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile inline_callsite_program: {}",
                    stderr
                ))
            }
        })();
        *COMPILE_INLINE_CALLSITE_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_INLINE_CALLSITE_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_cpp_complex_program_compiled() -> anyhow::Result<()> {
    let mut result = Ok(());
    COMPILE_CPP_COMPLEX.call_once(|| {
        let base =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpp_complex_program");
        println!("Compiling cpp_complex_program (Debug) in {base:?}");
        let _ = Command::new("make")
            .arg("clean")
            .current_dir(base.clone())
            .status()
            .is_ok();
        match Command::new("make").arg("all").current_dir(base).output() {
            Ok(out) => {
                if out.status.success() {
                    println!("✓ Successfully compiled cpp_complex_program");
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    result = Err(anyhow::anyhow!(
                        "Failed to compile cpp_complex_program: {}",
                        stderr
                    ));
                }
            }
            Err(e) => {
                result = Err(anyhow::anyhow!(
                    "Failed to run make for cpp_complex_program: {}",
                    e
                ));
            }
        }
    });
    result
}

fn ensure_static_scope_program_compiled(compiler: FixtureCompiler) -> anyhow::Result<()> {
    let (once, slot): (&Once, &Mutex<Option<anyhow::Result<()>>>) = match compiler {
        FixtureCompiler::Default => (
            &COMPILE_STATIC_SCOPE_DEFAULT,
            &*COMPILE_STATIC_SCOPE_DEFAULT_RESULT,
        ),
        FixtureCompiler::ClangDwarf5 => (
            &COMPILE_STATIC_SCOPE_CLANG_DWARF5,
            &*COMPILE_STATIC_SCOPE_CLANG_DWARF5_RESULT,
        ),
    };

    once.call_once(|| {
        let compile_result = compile_static_scope_program(compiler);
        *slot.lock().unwrap() = Some(compile_result);
    });

    match slot.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn compile_static_scope_program(compiler: FixtureCompiler) -> anyhow::Result<()> {
    let base =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static_scope_program");
    println!(
        "Compiling static_scope_program {} in {base:?}",
        compiler.description()
    );

    let mut cmd = Command::new("make");
    compiler.apply_to_c_make(&mut cmd, "static_scope_program");
    let output = cmd.current_dir(base).output().map_err(|e| {
        anyhow::anyhow!(
            "Failed to run make for static_scope_program {}: {}",
            compiler.description(),
            e
        )
    })?;

    if output.status.success() {
        println!(
            "✓ Successfully compiled static_scope_program {}",
            compiler.description()
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile static_scope_program {}: {}",
            compiler.description(),
            stderr
        ))
    }
}
