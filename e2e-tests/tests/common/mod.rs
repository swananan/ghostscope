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
    static ref COMPILE_MEMBER_POINTER_DEBUG_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_MEMBER_POINTER_OPTIMIZED_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_GLOBALS_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_GLOBALS_OPTIMIZED_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_LATE_GLOBALS_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_SHORT_LIVED_LONG_COMM_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_C_MULTITHREAD_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_BACKTRACE_HOT_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_BACKTRACE_CROSS_MODULE_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_BACKTRACE_DLOPEN_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_SCALAR_TYPES_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_SCALAR_TYPES_OPTIMIZED_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_CAST_TYPES_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_RUST_GLOBAL_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_INLINE_CALLSITE_DEFAULT_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_INLINE_CALLSITE_CLANG_DWARF5_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_INLINE_CALL_VALUE_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_PARTITIONED_RANGES_DEFAULT_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_PARTITIONED_RANGES_GCC_DWARF5_FUNCTION_SECTIONS_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_PARTITIONED_RANGES_CLANG_DWARF5_RNGLISTX_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_CPP_COMPLEX_RESULT: Mutex<Option<anyhow::Result<()>>> = Mutex::new(None);
    static ref COMPILE_STATIC_SCOPE_DEFAULT_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_STATIC_SCOPE_CLANG_DWARF5_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_ENTRY_VALUE_RECOVERY_DEFAULT_RESULT: Mutex<Option<anyhow::Result<()>>> =
        Mutex::new(None);
    static ref COMPILE_ENTRY_VALUE_RECOVERY_CLANG_DWARF5_RESULT: Mutex<Option<anyhow::Result<()>>> =
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
    MemberPointer,
    Globals,
    LateGlobals,
    ShortLivedLongComm,
    CMultithread,
    BacktraceHot,
    BacktraceCrossModule,
    BacktraceDlopen,
    ScalarTypes,
    CastTypes,
    RustGlobal,
    InlineCallsite,
    InlineCallValue,
    PartitionedRanges,
    CppComplex,
    StaticScope,
    EntryValueRecovery,
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
//
// Keep CI fixture-cache discovery in e2e-tests/cache-fixtures.sh aligned with
// this registry and the fixture build outputs. Most C/C++ fixtures are cached
// by executable outputs directly under tests/fixtures/*_program; rust_global is
// the explicit target/debug exception.
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
        name: "member_pointer_program",
        directory: "member_pointer_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::MemberPointer,
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
        name: "short_lived_long_comm_program",
        directory: "short_lived_long_comm_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::ShortLivedLongComm,
    },
    RegisteredFixture {
        name: "c_multithread_program",
        directory: "c_multithread_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::CMultithread,
    },
    RegisteredFixture {
        name: "backtrace_hot_program",
        directory: "backtrace_hot_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::BacktraceHot,
    },
    RegisteredFixture {
        name: "backtrace_cross_module_program",
        directory: "backtrace_cross_module_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::BacktraceCrossModule,
    },
    RegisteredFixture {
        name: "backtrace_dlopen_program",
        directory: "backtrace_dlopen_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::BacktraceDlopen,
    },
    RegisteredFixture {
        name: "scalar_types_program",
        directory: "scalar_types_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::ScalarTypes,
    },
    RegisteredFixture {
        name: "cast_types_program",
        directory: "cast_types_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::CastTypes,
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
        name: "inline_call_value_program",
        directory: "inline_call_value_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::InlineCallValue,
    },
    RegisteredFixture {
        name: "partitioned_ranges_program",
        directory: "partitioned_ranges_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::PartitionedRanges,
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
    RegisteredFixture {
        name: "entry_value_recovery_program",
        directory: "entry_value_recovery_program",
        cleanup: CleanupCommand::Make,
        kind: RegisteredFixtureKind::EntryValueRecovery,
    },
];

fn registered_fixture(name: &str) -> Option<&'static RegisteredFixture> {
    REGISTERED_FIXTURES
        .iter()
        .find(|fixture| fixture.name == name)
}

fn fixture_cargo_target_dir(fixture_dir: &std::path::Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(target_dir) => {
            let target_dir = PathBuf::from(target_dir);
            if target_dir.is_absolute() {
                target_dir
            } else {
                fixture_dir.join(target_dir)
            }
        }
        None => fixture_dir.join("target"),
    }
}

#[allow(dead_code)]
pub(crate) fn host_pid_is_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).is_dir()
}

fn preserve_precompiled_fixtures() -> bool {
    std::env::var_os("GHOSTSCOPE_PRESERVE_PRECOMPILED_FIXTURES").is_some()
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
        let _ = FixtureCompiler::GccDwarf5FunctionSections;
        let _ = FixtureCompiler::ClangDwarf5Rnglistx;

        // Exercise runner builder methods so they are referenced in all bins.
        let _ = runner::GhostscopeRunner::new()
            .with_target("/")
            .with_cli_args([std::ffi::OsString::from("--help")])
            .force_perf_event_array(false)
            .enable_sysmon_for_target(false);

        let _use_pid_check: fn(u32) -> bool = host_pid_is_running;
        let _use_compiler_check: fn(FixtureCompiler) -> bool = fixture_compiler_available;
        let _use_static_scope_compile: fn(FixtureCompiler) -> anyhow::Result<()> =
            ensure_static_scope_program_compiled;
    });

    // Register an atexit cleanup to remove built fixtures after all tests
    REGISTER_CLEANUP.call_once(|| {
        extern "C" fn cleanup_fixtures() {
            if preserve_precompiled_fixtures() {
                return;
            }
            // Best-effort cleanup; ignore errors
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            for fixture in REGISTERED_FIXTURES {
                fixture.cleanup(&base);
            }
        }
        // SAFETY: cleanup_fixtures has C ABI, captures no Rust references, and
        // remains available for the process lifetime.
        unsafe {
            libc::atexit(cleanup_fixtures);
        }
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
    GccDwarf5FunctionSections,
    ClangDwarf5Rnglistx,
}

impl FixtureCompiler {
    pub(crate) fn binary_name(&self, base: &str) -> String {
        match self {
            FixtureCompiler::Default => base.to_string(),
            FixtureCompiler::ClangDwarf5 => format!("{base}_clang_dwarf5"),
            FixtureCompiler::GccDwarf5FunctionSections => format!("{base}_gcc_dwarf5_sections"),
            FixtureCompiler::ClangDwarf5Rnglistx => format!("{base}_clang_dwarf5_rnglistx"),
        }
    }

    fn object_name(&self, base: &str) -> String {
        format!("{}.o", self.binary_name(base))
    }

    fn description(&self) -> &'static str {
        match self {
            FixtureCompiler::Default => "default toolchain",
            FixtureCompiler::ClangDwarf5 => "clang -gdwarf-5",
            FixtureCompiler::GccDwarf5FunctionSections => "gcc -gdwarf-5 -ffunction-sections",
            FixtureCompiler::ClangDwarf5Rnglistx => {
                "clang -gdwarf-5 -ffunction-sections -fbasic-block-sections=all"
            }
        }
    }

    fn apply_to_c_make(&self, cmd: &mut Command, base: &str, compiler_cflags: &str) {
        cmd.arg("all")
            .arg(format!("BINARY={}", self.binary_name(base)))
            .arg(format!("OBJ={}", self.object_name(base)));

        match self {
            FixtureCompiler::Default => {}
            FixtureCompiler::ClangDwarf5 | FixtureCompiler::ClangDwarf5Rnglistx => {
                let clang = preferred_clang_binary().unwrap_or_else(|| "clang".to_string());
                cmd.arg(format!("CC={clang}"))
                    .arg(format!("CFLAGS={compiler_cflags}"));
            }
            FixtureCompiler::GccDwarf5FunctionSections => {
                let gcc = preferred_gcc_binary().unwrap_or_else(|| "gcc".to_string());
                cmd.arg(format!("CC={gcc}"))
                    .arg(format!("CFLAGS={compiler_cflags}"));
            }
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
            RegisteredFixtureKind::MemberPointer => {
                ensure_member_pointer_program_compiled_with_opt(opt_level)?;
                let bin_name = match opt_level {
                    OptimizationLevel::Debug => "member_pointer_program",
                    OptimizationLevel::O1 => "member_pointer_program_o1",
                    OptimizationLevel::O2 => "member_pointer_program_o2",
                    OptimizationLevel::O3 => "member_pointer_program_o3",
                    OptimizationLevel::Stripped => {
                        anyhow::bail!(
                            "Stripped optimization level not supported for member_pointer_program"
                        )
                    }
                };
                Ok(dir.join(bin_name))
            }
            RegisteredFixtureKind::Globals => {
                let bin_name = match opt_level {
                    OptimizationLevel::Debug => {
                        ensure_globals_program_compiled()?;
                        "globals_program"
                    }
                    OptimizationLevel::O1 => {
                        ensure_globals_program_optimized_variants_compiled()?;
                        "globals_program_o1"
                    }
                    OptimizationLevel::O2 => {
                        ensure_globals_program_optimized_variants_compiled()?;
                        "globals_program_o2"
                    }
                    OptimizationLevel::O3 => {
                        ensure_globals_program_optimized_variants_compiled()?;
                        "globals_program_o3"
                    }
                    OptimizationLevel::Stripped => {
                        anyhow::bail!(
                            "Stripped optimization level not supported for globals_program"
                        )
                    }
                };
                Ok(dir.join(bin_name))
            }
            RegisteredFixtureKind::LateGlobals => {
                ensure_late_globals_program_compiled()?;
                Ok(dir.join("late_globals_program"))
            }
            RegisteredFixtureKind::ShortLivedLongComm => {
                ensure_short_lived_long_comm_program_compiled()?;
                Ok(dir.join("short_lived_long_comm_program"))
            }
            RegisteredFixtureKind::CMultithread => {
                ensure_c_multithread_program_compiled()?;
                Ok(dir.join("c_multithread_program"))
            }
            RegisteredFixtureKind::BacktraceHot => {
                ensure_backtrace_hot_program_compiled()?;
                Ok(dir.join("backtrace_hot_program"))
            }
            RegisteredFixtureKind::BacktraceCrossModule => {
                ensure_backtrace_cross_module_program_compiled()?;
                Ok(dir.join("backtrace_cross_module_program"))
            }
            RegisteredFixtureKind::BacktraceDlopen => {
                ensure_backtrace_dlopen_program_compiled()?;
                Ok(dir.join("backtrace_dlopen_program"))
            }
            RegisteredFixtureKind::ScalarTypes => {
                let bin_name = match opt_level {
                    OptimizationLevel::Debug => {
                        ensure_scalar_types_program_compiled()?;
                        "scalar_types_program"
                    }
                    OptimizationLevel::O1 => {
                        ensure_scalar_types_program_optimized_variants_compiled()?;
                        "scalar_types_program_o1"
                    }
                    OptimizationLevel::O2 => {
                        ensure_scalar_types_program_optimized_variants_compiled()?;
                        "scalar_types_program_o2"
                    }
                    OptimizationLevel::O3 => {
                        ensure_scalar_types_program_optimized_variants_compiled()?;
                        "scalar_types_program_o3"
                    }
                    OptimizationLevel::Stripped => {
                        anyhow::bail!(
                            "Stripped optimization level not supported for scalar_types_program"
                        )
                    }
                };
                Ok(dir.join(bin_name))
            }
            RegisteredFixtureKind::CastTypes => {
                if !matches!(opt_level, OptimizationLevel::Debug) {
                    anyhow::bail!(
                        "{} optimization level not supported for cast_types_program",
                        opt_level.description()
                    );
                }
                ensure_cast_types_program_compiled()?;
                Ok(dir.join("cast_types_program"))
            }
            RegisteredFixtureKind::RustGlobal => {
                ensure_rust_global_program_compiled()?;
                Ok(fixture_cargo_target_dir(&dir)
                    .join("debug")
                    .join("rust_global_program"))
            }
            RegisteredFixtureKind::InlineCallsite => {
                ensure_inline_callsite_program_compiled(FixtureCompiler::Default)?;
                Ok(dir.join(FixtureCompiler::Default.binary_name(self.name)))
            }
            RegisteredFixtureKind::InlineCallValue => {
                ensure_inline_call_value_program_compiled()?;
                Ok(dir.join("inline_call_value_program"))
            }
            RegisteredFixtureKind::PartitionedRanges => {
                ensure_partitioned_ranges_program_compiled(FixtureCompiler::Default)?;
                Ok(dir.join(FixtureCompiler::Default.binary_name(self.name)))
            }
            RegisteredFixtureKind::CppComplex => {
                ensure_cpp_complex_program_compiled()?;
                Ok(dir.join("cpp_complex_program"))
            }
            RegisteredFixtureKind::StaticScope => {
                ensure_static_scope_program_compiled(FixtureCompiler::Default)?;
                Ok(dir.join(FixtureCompiler::Default.binary_name(self.name)))
            }
            RegisteredFixtureKind::EntryValueRecovery => {
                ensure_entry_value_recovery_program_compiled(FixtureCompiler::Default)?;
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
            RegisteredFixtureKind::InlineCallsite => {
                ensure_inline_callsite_program_compiled(compiler)?;
                Ok(self
                    .dir(fixtures_base)
                    .join(compiler.binary_name(self.name)))
            }
            RegisteredFixtureKind::StaticScope => {
                ensure_static_scope_program_compiled(compiler)?;
                Ok(self
                    .dir(fixtures_base)
                    .join(compiler.binary_name(self.name)))
            }
            RegisteredFixtureKind::PartitionedRanges => {
                ensure_partitioned_ranges_program_compiled(compiler)?;
                Ok(self
                    .dir(fixtures_base)
                    .join(compiler.binary_name(self.name)))
            }
            RegisteredFixtureKind::EntryValueRecovery => {
                ensure_entry_value_recovery_program_compiled(compiler)?;
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

pub(crate) fn fixture_compiler_available(compiler: FixtureCompiler) -> bool {
    match compiler {
        FixtureCompiler::Default => true,
        FixtureCompiler::ClangDwarf5 => {
            preferred_clang_binary().is_some()
                || precompiled_outputs_available(&[
                    fixture_binary_path(
                        "inline_callsite_program",
                        &FixtureCompiler::ClangDwarf5.binary_name("inline_callsite_program"),
                    ),
                    fixture_binary_path(
                        "static_scope_program",
                        &FixtureCompiler::ClangDwarf5.binary_name("static_scope_program"),
                    ),
                    fixture_binary_path(
                        "entry_value_recovery_program",
                        &FixtureCompiler::ClangDwarf5.binary_name("entry_value_recovery_program"),
                    ),
                ])
        }
        FixtureCompiler::GccDwarf5FunctionSections => {
            preferred_gcc_binary().is_some()
                || precompiled_outputs_available(&[fixture_binary_path(
                    "partitioned_ranges_program",
                    &FixtureCompiler::GccDwarf5FunctionSections
                        .binary_name("partitioned_ranges_program"),
                )])
        }
        FixtureCompiler::ClangDwarf5Rnglistx => {
            preferred_clang_binary().is_some()
                || precompiled_outputs_available(&[fixture_binary_path(
                    "partitioned_ranges_program",
                    &FixtureCompiler::ClangDwarf5Rnglistx.binary_name("partitioned_ranges_program"),
                )])
        }
    }
}

fn command_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn preferred_clang_binary() -> Option<String> {
    preferred_compiler_binary("CLANG_BIN", &["clang-18", "clang"])
}

fn preferred_gcc_binary() -> Option<String> {
    preferred_compiler_binary("GCC_BIN", &["gcc"])
}

fn preferred_compiler_binary(env_var: &str, candidates: &[&str]) -> Option<String> {
    if let Some(override_bin) = std::env::var_os(env_var) {
        let override_bin = override_bin.to_string_lossy().trim().to_string();
        if !override_bin.is_empty() {
            return command_available(&override_bin).then_some(override_bin);
        }
    }

    candidates
        .iter()
        .copied()
        .find(|name| command_available(name))
        .map(str::to_string)
}

fn fixture_binary_path(fixture_name: &str, binary_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_name)
        .join(binary_name)
}

fn precompiled_outputs_available(outputs: &[PathBuf]) -> bool {
    outputs.iter().all(|path| path.exists())
}

fn use_precompiled_outputs(label: &str, outputs: &[PathBuf]) -> Option<anyhow::Result<()>> {
    if precompiled_outputs_available(outputs) {
        let rendered = outputs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("Using precompiled {label}: {rendered}");
        Some(Ok(()))
    } else {
        None
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
                let compile_result = compile_sample_program_variants(&[
                    OptimizationLevel::O1,
                    OptimizationLevel::O2,
                    OptimizationLevel::O3,
                ]);
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

fn compile_sample_program_variants(opt_levels: &[OptimizationLevel]) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let sample_program_dir = fixtures_path.join("sample_program");
    let outputs = opt_levels
        .iter()
        .map(|opt_level| sample_program_dir.join(opt_level.as_binary_name()))
        .collect::<Vec<_>>();
    if let Some(result) = use_precompiled_outputs("sample_program variants", &outputs) {
        return result;
    }

    let requested = opt_levels
        .iter()
        .map(OptimizationLevel::description)
        .collect::<Vec<_>>()
        .join(", ");
    println!("Compiling sample_program variants [{requested}] in {sample_program_dir:?}");

    let mut command = Command::new("make");
    for opt_level in opt_levels {
        command.arg(opt_level.as_make_target());
    }

    let output = command
        .current_dir(sample_program_dir)
        .output()
        .map_err(|e| {
            anyhow::anyhow!("Failed to run make for sample_program variants [{requested}]: {e}")
        })?;

    if output.status.success() {
        println!("✓ Successfully compiled sample_program variants [{requested}]");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile sample_program variants [{requested}]: {stderr}"
        ))
    }
}

fn compile_sample_program(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let sample_program_dir = fixtures_path.join("sample_program");
    let mut outputs = vec![sample_program_dir.join(opt_level.as_binary_name())];
    if matches!(opt_level, OptimizationLevel::Stripped) {
        outputs.push(sample_program_dir.join("sample_program_stripped.debug"));
    }
    if let Some(result) = use_precompiled_outputs("sample_program", &outputs) {
        return result;
    }

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
static COMPILE_MEMBER_POINTER_DEBUG: Once = Once::new();
static COMPILE_MEMBER_POINTER_OPTIMIZED: Once = Once::new();

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
                let compile_result = compile_complex_program_variants(&[
                    OptimizationLevel::O1,
                    OptimizationLevel::O2,
                    OptimizationLevel::O3,
                ]);
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

fn complex_program_binary_name(opt_level: OptimizationLevel) -> anyhow::Result<&'static str> {
    match opt_level {
        OptimizationLevel::Debug => Ok("complex_types_program"),
        OptimizationLevel::O1 => Ok("complex_types_program_o1"),
        OptimizationLevel::O2 => Ok("complex_types_program_o2"),
        OptimizationLevel::O3 => Ok("complex_types_program_o3"),
        OptimizationLevel::Stripped => {
            anyhow::bail!("Stripped optimization level not supported for complex_types_program")
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

    let target = complex_program_binary_name(opt_level)?;
    if let Some(result) =
        use_precompiled_outputs("complex_types_program", &[program_dir.join(target)])
    {
        return result;
    }

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

fn compile_complex_program_variants(opt_levels: &[OptimizationLevel]) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let program_dir = fixtures_path.join("complex_types_program");
    let outputs = opt_levels
        .iter()
        .map(|opt_level| {
            Ok::<_, anyhow::Error>(program_dir.join(complex_program_binary_name(*opt_level)?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some(result) = use_precompiled_outputs("complex_types_program variants", &outputs) {
        return result;
    }

    let requested = opt_levels
        .iter()
        .map(OptimizationLevel::description)
        .collect::<Vec<_>>()
        .join(", ");
    println!("Compiling complex_types_program variants [{requested}] in {program_dir:?}");

    let mut command = Command::new("make");
    for opt_level in opt_levels {
        command.arg(complex_program_binary_name(*opt_level)?);
    }

    let output = command.current_dir(program_dir).output().map_err(|e| {
        anyhow::anyhow!("Failed to run make for complex_types_program variants [{requested}]: {e}")
    })?;

    if output.status.success() {
        println!("✓ Successfully compiled complex_types_program variants [{requested}]");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile complex_types_program variants [{requested}]: {stderr}"
        ))
    }
}

fn ensure_member_pointer_program_compiled_with_opt(
    opt_level: OptimizationLevel,
) -> anyhow::Result<()> {
    match opt_level {
        OptimizationLevel::Debug => {
            COMPILE_MEMBER_POINTER_DEBUG.call_once(|| {
                let compile_result = compile_member_pointer_program(opt_level);
                *COMPILE_MEMBER_POINTER_DEBUG_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_MEMBER_POINTER_DEBUG_RESULT.lock().unwrap().as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
        _ => {
            COMPILE_MEMBER_POINTER_OPTIMIZED.call_once(|| {
                let compile_result = compile_member_pointer_program_variants(&[
                    OptimizationLevel::O1,
                    OptimizationLevel::O2,
                    OptimizationLevel::O3,
                ]);
                *COMPILE_MEMBER_POINTER_OPTIMIZED_RESULT.lock().unwrap() = Some(compile_result);
            });
            match COMPILE_MEMBER_POINTER_OPTIMIZED_RESULT
                .lock()
                .unwrap()
                .as_ref()
            {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => panic!("Compilation result should be set after call_once"),
            }
        }
    }
}

fn compile_member_pointer_program(opt_level: OptimizationLevel) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let program_dir = fixtures_path.join("member_pointer_program");

    println!(
        "Compiling member_pointer_program {} in {program_dir:?}",
        opt_level.description()
    );

    let target = match opt_level {
        OptimizationLevel::Debug => "member_pointer_program",
        OptimizationLevel::O1 => "member_pointer_program_o1",
        OptimizationLevel::O2 => "member_pointer_program_o2",
        OptimizationLevel::O3 => "member_pointer_program_o3",
        OptimizationLevel::Stripped => {
            anyhow::bail!("Stripped optimization level not supported for member_pointer_program")
        }
    };
    if let Some(result) =
        use_precompiled_outputs("member_pointer_program", &[program_dir.join(target)])
    {
        return result;
    }

    let output = Command::new("make")
        .arg(target)
        .current_dir(program_dir)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run make for member_pointer_program {}: {}",
                opt_level.description(),
                e
            )
        })?;

    if output.status.success() {
        println!(
            "✓ Successfully compiled member_pointer_program {}",
            opt_level.description()
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile member_pointer_program {}: {}",
            opt_level.description(),
            stderr
        ))
    }
}

fn compile_member_pointer_program_variants(opt_levels: &[OptimizationLevel]) -> anyhow::Result<()> {
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let program_dir = fixtures_path.join("member_pointer_program");
    let outputs = opt_levels
        .iter()
        .map(|opt_level| {
            program_dir.join(match opt_level {
                OptimizationLevel::Debug => "member_pointer_program",
                OptimizationLevel::O1 => "member_pointer_program_o1",
                OptimizationLevel::O2 => "member_pointer_program_o2",
                OptimizationLevel::O3 => "member_pointer_program_o3",
                OptimizationLevel::Stripped => {
                    unreachable!("member_pointer_program does not support stripped output")
                }
            })
        })
        .collect::<Vec<_>>();
    if let Some(result) = use_precompiled_outputs("member_pointer_program variants", &outputs) {
        return result;
    }

    let requested = opt_levels
        .iter()
        .map(OptimizationLevel::description)
        .collect::<Vec<_>>()
        .join(", ");
    println!("Compiling member_pointer_program variants [{requested}] in {program_dir:?}");

    let mut command = Command::new("make");
    for opt_level in opt_levels {
        command.arg(match opt_level {
            OptimizationLevel::Debug => "member_pointer_program",
            OptimizationLevel::O1 => "member_pointer_program_o1",
            OptimizationLevel::O2 => "member_pointer_program_o2",
            OptimizationLevel::O3 => "member_pointer_program_o3",
            OptimizationLevel::Stripped => {
                anyhow::bail!(
                    "Stripped optimization level not supported for member_pointer_program"
                )
            }
        });
    }

    let output = command.current_dir(program_dir).output().map_err(|e| {
        anyhow::anyhow!("Failed to run make for member_pointer_program variants [{requested}]: {e}")
    })?;

    if output.status.success() {
        println!("✓ Successfully compiled member_pointer_program variants [{requested}]");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile member_pointer_program variants [{requested}]: {stderr}"
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
        let bin_path = program_dir.join("complex_types_program_nopie");

        if bin_path.exists() {
            println!("Using precompiled complex_types_program Non-PIE: {bin_path:?}");
            return Ok(bin_path);
        }

        COMPILE_COMPLEX_NOPIE.call_once(|| {
            let compile_result = (|| -> anyhow::Result<()> {
                println!("Compiling complex_types_program Non-PIE (ET_EXEC) in {program_dir:?}");

                let output = Command::new("make")
                    .arg("complex_types_program_nopie")
                    .current_dir(program_dir.clone())
                    .output()
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to run make for complex_types_program Non-PIE: {e}")
                    })?;

                if output.status.success() {
                    println!("✓ Successfully compiled complex_types_program Non-PIE");
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(anyhow::anyhow!(
                        "Failed to compile complex_types_program Non-PIE: {stderr}"
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
static COMPILE_GLOBALS_OPTIMIZED: Once = Once::new();
static COMPILE_LATE_GLOBALS: Once = Once::new();
static COMPILE_SHORT_LIVED_LONG_COMM: Once = Once::new();
static COMPILE_C_MULTITHREAD: Once = Once::new();
static COMPILE_BACKTRACE_HOT: Once = Once::new();
static COMPILE_BACKTRACE_CROSS_MODULE: Once = Once::new();
static COMPILE_BACKTRACE_DLOPEN: Once = Once::new();
static COMPILE_SCALAR_TYPES: Once = Once::new();
static COMPILE_SCALAR_TYPES_OPTIMIZED: Once = Once::new();
static COMPILE_CAST_TYPES: Once = Once::new();
static COMPILE_RUST_GLOBAL: Once = Once::new();
static COMPILE_INLINE_CALLSITE_DEFAULT: Once = Once::new();
static COMPILE_INLINE_CALLSITE_CLANG_DWARF5: Once = Once::new();
static COMPILE_INLINE_CALL_VALUE: Once = Once::new();
static COMPILE_PARTITIONED_RANGES_DEFAULT: Once = Once::new();
static COMPILE_PARTITIONED_RANGES_GCC_DWARF5_FUNCTION_SECTIONS: Once = Once::new();
static COMPILE_PARTITIONED_RANGES_CLANG_DWARF5_RNGLISTX: Once = Once::new();
static COMPILE_CPP_COMPLEX: Once = Once::new();
static COMPILE_STATIC_SCOPE_DEFAULT: Once = Once::new();
static COMPILE_STATIC_SCOPE_CLANG_DWARF5: Once = Once::new();
static COMPILE_ENTRY_VALUE_RECOVERY_DEFAULT: Once = Once::new();
static COMPILE_ENTRY_VALUE_RECOVERY_CLANG_DWARF5: Once = Once::new();

fn ensure_globals_program_compiled() -> anyhow::Result<()> {
    COMPILE_GLOBALS.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/globals_program");
            if let Some(result) = use_precompiled_outputs(
                "globals_program",
                &[base.join("globals_program"), base.join("libgvars.so")],
            ) {
                return result;
            }

            println!("Compiling globals_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled globals_program and libgvars.so");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile globals_program: {stderr}"
                ))
            }
        })();
        *COMPILE_GLOBALS_RESULT.lock().unwrap() = Some(compile_result);
    });
    match COMPILE_GLOBALS_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_globals_program_optimized_variants_compiled() -> anyhow::Result<()> {
    COMPILE_GLOBALS_OPTIMIZED.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/globals_program");
            let outputs = [
                base.join("globals_program_o1"),
                base.join("globals_program_o2"),
                base.join("globals_program_o3"),
                base.join("libgvars.so"),
            ];
            if let Some(result) =
                use_precompiled_outputs("globals_program optimized variants", &outputs)
            {
                return result;
            }

            println!("Compiling globals_program optimized variants in {base:?}");
            let out = Command::new("make")
                .arg("globals_program_o1")
                .arg("globals_program_o2")
                .arg("globals_program_o3")
                .current_dir(base)
                .output()?;
            if out.status.success() {
                println!("✓ Successfully compiled globals_program optimized variants");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile globals_program optimized variants: {stderr}"
                ))
            }
        })();
        *COMPILE_GLOBALS_OPTIMIZED_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_GLOBALS_OPTIMIZED_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_late_globals_program_compiled() -> anyhow::Result<()> {
    COMPILE_LATE_GLOBALS.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/late_globals_program");
            if let Some(result) = use_precompiled_outputs(
                "late_globals_program",
                &[base.join("late_globals_program")],
            ) {
                return result;
            }
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
                    "Failed to compile late_globals_program: {stderr}"
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

fn ensure_short_lived_long_comm_program_compiled() -> anyhow::Result<()> {
    COMPILE_SHORT_LIVED_LONG_COMM.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/short_lived_long_comm_program");
            if let Some(result) = use_precompiled_outputs(
                "short_lived_long_comm_program",
                &[base.join("short_lived_long_comm_program")],
            ) {
                return result;
            }
            println!("Compiling short_lived_long_comm_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled short_lived_long_comm_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile short_lived_long_comm_program: {stderr}"
                ))
            }
        })();
        *COMPILE_SHORT_LIVED_LONG_COMM_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_SHORT_LIVED_LONG_COMM_RESULT
        .lock()
        .unwrap()
        .as_ref()
    {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_c_multithread_program_compiled() -> anyhow::Result<()> {
    COMPILE_C_MULTITHREAD.call_once(|| {
        let compile_result = compile_c_make_fixture(
            "c_multithread_program",
            FixtureCompiler::Default,
            "-Wall -Wextra -g -O0 -pthread",
        );
        *COMPILE_C_MULTITHREAD_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_C_MULTITHREAD_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_backtrace_hot_program_compiled() -> anyhow::Result<()> {
    COMPILE_BACKTRACE_HOT.call_once(|| {
        let compile_result = compile_c_make_fixture(
            "backtrace_hot_program",
            FixtureCompiler::Default,
            "-Wall -Wextra -g -O0",
        );
        *COMPILE_BACKTRACE_HOT_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_BACKTRACE_HOT_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_backtrace_cross_module_program_compiled() -> anyhow::Result<()> {
    COMPILE_BACKTRACE_CROSS_MODULE.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/backtrace_cross_module_program");
            if let Some(result) = use_precompiled_outputs(
                "backtrace_cross_module_program",
                &[
                    base.join("backtrace_cross_module_program"),
                    base.join("libbacktrace_cross_module.so"),
                ],
            ) {
                return result;
            }

            println!("Compiling backtrace_cross_module_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled backtrace_cross_module_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile backtrace_cross_module_program: {stderr}"
                ))
            }
        })();
        *COMPILE_BACKTRACE_CROSS_MODULE_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_BACKTRACE_CROSS_MODULE_RESULT
        .lock()
        .unwrap()
        .as_ref()
    {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_backtrace_dlopen_program_compiled() -> anyhow::Result<()> {
    COMPILE_BACKTRACE_DLOPEN.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/backtrace_dlopen_program");
            if let Some(result) = use_precompiled_outputs(
                "backtrace_dlopen_program",
                &[
                    base.join("backtrace_dlopen_program"),
                    base.join("libbacktrace_dlopen_target.so"),
                ],
            ) {
                return result;
            }

            println!("Compiling backtrace_dlopen_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled backtrace_dlopen_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile backtrace_dlopen_program: {stderr}"
                ))
            }
        })();
        *COMPILE_BACKTRACE_DLOPEN_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_BACKTRACE_DLOPEN_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_scalar_types_program_compiled() -> anyhow::Result<()> {
    COMPILE_SCALAR_TYPES.call_once(|| {
        let compile_result = compile_scalar_types_program_target(
            "scalar_types_program",
            OptimizationLevel::Debug.description(),
        );
        *COMPILE_SCALAR_TYPES_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_SCALAR_TYPES_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn compile_scalar_types_program_target(target: &str, description: &str) -> anyhow::Result<()> {
    let base =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scalar_types_program");
    if let Some(result) = use_precompiled_outputs("scalar_types_program", &[base.join(target)]) {
        return result;
    }

    println!("Compiling scalar_types_program {description} in {base:?}");
    let out = Command::new("make")
        .arg(target)
        .current_dir(base)
        .output()?;
    if out.status.success() {
        println!("✓ Successfully compiled scalar_types_program {description}");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile scalar_types_program {description}: {stderr}"
        ))
    }
}

fn ensure_scalar_types_program_optimized_variants_compiled() -> anyhow::Result<()> {
    COMPILE_SCALAR_TYPES_OPTIMIZED.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/scalar_types_program");
            let outputs = [
                base.join("scalar_types_program_o1"),
                base.join("scalar_types_program_o2"),
                base.join("scalar_types_program_o3"),
            ];
            if let Some(result) =
                use_precompiled_outputs("scalar_types_program optimized variants", &outputs)
            {
                return result;
            }

            println!("Compiling scalar_types_program optimized variants in {base:?}");
            let out = Command::new("make")
                .arg("scalar_types_program_o1")
                .arg("scalar_types_program_o2")
                .arg("scalar_types_program_o3")
                .current_dir(base)
                .output()?;
            if out.status.success() {
                println!("✓ Successfully compiled scalar_types_program optimized variants");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile scalar_types_program optimized variants: {stderr}"
                ))
            }
        })();
        *COMPILE_SCALAR_TYPES_OPTIMIZED_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_SCALAR_TYPES_OPTIMIZED_RESULT
        .lock()
        .unwrap()
        .as_ref()
    {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_cast_types_program_compiled() -> anyhow::Result<()> {
    COMPILE_CAST_TYPES.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cast_types_program");
            if let Some(result) = use_precompiled_outputs(
                "cast_types_program",
                &[
                    base.join("cast_types_program"),
                    base.join("libcast_types.so"),
                    base.join("libcast_types_extra.so"),
                ],
            ) {
                return result;
            }

            println!("Compiling cast_types_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled cast_types_program and libcast_types.so");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile cast_types_program: {stderr}"
                ))
            }
        })();
        *COMPILE_CAST_TYPES_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_CAST_TYPES_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_rust_global_program_compiled() -> anyhow::Result<()> {
    COMPILE_RUST_GLOBAL.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/rust_global_program");
            let binary = fixture_cargo_target_dir(&base)
                .join("debug")
                .join("rust_global_program");
            if let Some(result) = use_precompiled_outputs("rust_global_program", &[binary]) {
                return result;
            }

            println!("Compiling rust_global_program (Debug) in {base:?}");
            let out = Command::new("cargo")
                .arg("build")
                .arg("--locked")
                .current_dir(base)
                .output()?;
            if out.status.success() {
                println!("✓ Successfully compiled rust_global_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile rust_global_program: {stderr}"
                ))
            }
        })();
        *COMPILE_RUST_GLOBAL_RESULT.lock().unwrap() = Some(compile_result);
    });
    match COMPILE_RUST_GLOBAL_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_inline_callsite_program_compiled(compiler: FixtureCompiler) -> anyhow::Result<()> {
    let (once, slot): (&Once, &Mutex<Option<anyhow::Result<()>>>) = match compiler {
        FixtureCompiler::Default => (
            &COMPILE_INLINE_CALLSITE_DEFAULT,
            &*COMPILE_INLINE_CALLSITE_DEFAULT_RESULT,
        ),
        FixtureCompiler::ClangDwarf5 => (
            &COMPILE_INLINE_CALLSITE_CLANG_DWARF5,
            &*COMPILE_INLINE_CALLSITE_CLANG_DWARF5_RESULT,
        ),
        _ => {
            anyhow::bail!(
                "Compiler override {} is not wired for inline_callsite_program",
                compiler.description()
            )
        }
    };

    once.call_once(|| {
        let compile_result = compile_c_make_fixture(
            "inline_callsite_program",
            compiler,
            "-Wall -Wextra -gdwarf-5 -O3",
        );
        *slot.lock().unwrap() = Some(compile_result);
    });

    match slot.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_inline_call_value_program_compiled() -> anyhow::Result<()> {
    COMPILE_INLINE_CALL_VALUE.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/inline_call_value_program");
            if let Some(result) = use_precompiled_outputs(
                "inline_call_value_program",
                &[base.join("inline_call_value_program")],
            ) {
                return result;
            }
            println!("Compiling inline_call_value_program (Optimized O3) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled inline_call_value_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile inline_call_value_program: {stderr}"
                ))
            }
        })();
        *COMPILE_INLINE_CALL_VALUE_RESULT.lock().unwrap() = Some(compile_result);
    });

    match COMPILE_INLINE_CALL_VALUE_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn ensure_partitioned_ranges_program_compiled(compiler: FixtureCompiler) -> anyhow::Result<()> {
    let (once, slot): (&Once, &Mutex<Option<anyhow::Result<()>>>) = match compiler {
        FixtureCompiler::Default => (
            &COMPILE_PARTITIONED_RANGES_DEFAULT,
            &*COMPILE_PARTITIONED_RANGES_DEFAULT_RESULT,
        ),
        FixtureCompiler::GccDwarf5FunctionSections => (
            &COMPILE_PARTITIONED_RANGES_GCC_DWARF5_FUNCTION_SECTIONS,
            &*COMPILE_PARTITIONED_RANGES_GCC_DWARF5_FUNCTION_SECTIONS_RESULT,
        ),
        FixtureCompiler::ClangDwarf5Rnglistx => (
            &COMPILE_PARTITIONED_RANGES_CLANG_DWARF5_RNGLISTX,
            &*COMPILE_PARTITIONED_RANGES_CLANG_DWARF5_RNGLISTX_RESULT,
        ),
        _ => {
            anyhow::bail!(
                "Compiler override {} is not wired for partitioned_ranges_program",
                compiler.description()
            )
        }
    };

    once.call_once(|| {
        let compile_result = compile_partitioned_ranges_program(compiler);
        *slot.lock().unwrap() = Some(compile_result);
    });

    match slot.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

fn compile_partitioned_ranges_program(compiler: FixtureCompiler) -> anyhow::Result<()> {
    match compiler {
        FixtureCompiler::Default => {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/partitioned_ranges_program");
            if let Some(result) = use_precompiled_outputs(
                "partitioned_ranges_program",
                &[base.join("partitioned_ranges_program")],
            ) {
                return result;
            }
            println!("Compiling partitioned_ranges_program (Optimized O3) in {base:?}");
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled partitioned_ranges_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile partitioned_ranges_program: {stderr}"
                ))
            }
        }
        FixtureCompiler::GccDwarf5FunctionSections => compile_c_make_fixture(
            "partitioned_ranges_program",
            compiler,
            "-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -freorder-blocks-and-partition",
        ),
        FixtureCompiler::ClangDwarf5Rnglistx => compile_c_make_fixture(
            "partitioned_ranges_program",
            compiler,
            "-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -fbasic-block-sections=all",
        ),
        _ => anyhow::bail!(
            "Compiler override {} is not wired for partitioned_ranges_program",
            compiler.description()
        ),
    }
}

fn ensure_cpp_complex_program_compiled() -> anyhow::Result<()> {
    COMPILE_CPP_COMPLEX.call_once(|| {
        let compile_result = (|| -> anyhow::Result<()> {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/cpp_complex_program");
            if let Some(result) =
                use_precompiled_outputs("cpp_complex_program", &[base.join("cpp_complex_program")])
            {
                return result;
            }

            println!("Compiling cpp_complex_program (Debug) in {base:?}");
            let _ = Command::new("make")
                .arg("clean")
                .current_dir(base.clone())
                .status()
                .is_ok();
            let out = Command::new("make").arg("all").current_dir(base).output()?;
            if out.status.success() {
                println!("✓ Successfully compiled cpp_complex_program");
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow::anyhow!(
                    "Failed to compile cpp_complex_program: {stderr}"
                ))
            }
        })();
        *COMPILE_CPP_COMPLEX_RESULT.lock().unwrap() = Some(compile_result);
    });
    match COMPILE_CPP_COMPLEX_RESULT.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}

pub(crate) fn compile_c_make_fixture(
    fixture_name: &str,
    compiler: FixtureCompiler,
    compiler_cflags: &str,
) -> anyhow::Result<()> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_name);
    let output_binary = base.join(compiler.binary_name(fixture_name));
    if let Some(result) = use_precompiled_outputs(
        &format!("{fixture_name} {}", compiler.description()),
        &[output_binary],
    ) {
        return result;
    }
    println!(
        "Compiling {fixture_name} {} in {base:?}",
        compiler.description()
    );

    let mut cmd = Command::new("make");
    compiler.apply_to_c_make(&mut cmd, fixture_name, compiler_cflags);
    let output = cmd.current_dir(base).output().map_err(|e| {
        anyhow::anyhow!(
            "Failed to run make for {fixture_name} {}: {}",
            compiler.description(),
            e
        )
    })?;

    if output.status.success() {
        println!(
            "✓ Successfully compiled {fixture_name} {}",
            compiler.description()
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile {fixture_name} {}: {}",
            compiler.description(),
            stderr
        ))
    }
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
        _ => {
            anyhow::bail!(
                "Compiler override {} is not wired for static_scope_program",
                compiler.description()
            )
        }
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
    compile_c_make_fixture(
        "static_scope_program",
        compiler,
        "-Wall -Wextra -gdwarf-5 -O0",
    )
}

fn ensure_entry_value_recovery_program_compiled(compiler: FixtureCompiler) -> anyhow::Result<()> {
    let (once, slot): (&Once, &Mutex<Option<anyhow::Result<()>>>) = match compiler {
        FixtureCompiler::Default => (
            &COMPILE_ENTRY_VALUE_RECOVERY_DEFAULT,
            &*COMPILE_ENTRY_VALUE_RECOVERY_DEFAULT_RESULT,
        ),
        FixtureCompiler::ClangDwarf5 => (
            &COMPILE_ENTRY_VALUE_RECOVERY_CLANG_DWARF5,
            &*COMPILE_ENTRY_VALUE_RECOVERY_CLANG_DWARF5_RESULT,
        ),
        _ => {
            anyhow::bail!(
                "Compiler override {} is not wired for entry_value_recovery_program",
                compiler.description()
            )
        }
    };

    once.call_once(|| {
        let compile_result = compile_c_make_fixture(
            "entry_value_recovery_program",
            compiler,
            "-Wall -Wextra -gdwarf-5 -O3",
        );
        *slot.lock().unwrap() = Some(compile_result);
    });

    match slot.lock().unwrap().as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
        None => panic!("Compilation result should be set after call_once"),
    }
}
