//! Runtime coverage for Rust 1.35's pre-hashbrown HashMap layout.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::init;

const TOOLCHAIN: &str = "1.35.0";
const REQUIRE_TOOLCHAIN_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_135_E2E";

fn rustc_for_toolchain() -> Option<PathBuf> {
    if let Ok(output) = Command::new("rustup")
        .args(["which", "--toolchain", TOOLCHAIN, "rustc"])
        .output()
    {
        if output.status.success() {
            let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
            if path.is_file() {
                return Some(path);
            }
        }
    }

    let mut rustup_homes = Vec::new();
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        rustup_homes.push(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("HOME") {
        rustup_homes.push(PathBuf::from(home).join(".rustup"));
    }
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        if let Some(home) = Path::new(&cargo_home).parent() {
            rustup_homes.push(home.join(".rustup"));
        }
    }
    if let Some(user) = std::env::var_os("SUDO_USER") {
        let user = user.to_string_lossy();
        if !user.is_empty() && !user.contains('/') {
            rustup_homes.push(PathBuf::from("/home").join(user.as_ref()).join(".rustup"));
        }
    }

    rustup_homes.into_iter().find_map(|rustup_home| {
        std::fs::read_dir(rustup_home.join("toolchains"))
            .ok()?
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let rustc = entry.path().join("bin/rustc");
                (name == TOOLCHAIN || name.starts_with(&format!("{TOOLCHAIN}-")))
                    .then_some(rustc)
                    .filter(|path| path.is_file())
            })
    })
}

fn compile_fixture(rustc: &Path, output_dir: &Path) -> anyhow::Result<PathBuf> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_legacy_hash_program/main.rs");
    let binary = output_dir.join("rust_legacy_hash_program");
    let output = Command::new(rustc)
        .args(["--edition=2018", "-g"])
        .arg("-C")
        .arg("opt-level=0")
        .arg("-C")
        .arg("link-dead-code")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "rustc {TOOLCHAIN} failed for {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(binary)
}

#[tokio::test]
async fn test_rust_135_hash_map_and_hash_set_values() -> anyhow::Result<()> {
    init();

    let Some(rustc) = rustc_for_toolchain() else {
        anyhow::ensure!(
            std::env::var_os(REQUIRE_TOOLCHAIN_ENV).is_none(),
            "required Rust toolchain {TOOLCHAIN} is not installed"
        );
        eprintln!("skipping unavailable Rust toolchain {TOOLCHAIN}");
        return Ok(());
    };

    let temp_dir = tempfile::tempdir()?;
    let binary = compile_fixture(&rustc, temp_dir.path())?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;

    let script = r#"
trace observe_legacy_hash_collections {
    print "R135_MAP:{}", map;
    print "R135_SET:{}", set;
    print "R135_EMPTY_MAP:{}", empty_map;
    print "R135_EMPTY_SET:{}", empty_set;
    print "R135_UNIT_MAP:{}", unit_map;
    print "R135_UNIT_SET:{}", unit_set;
}
"#;
    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        // Rust 1.35 starts at 32 buckets and uses a randomized hash seed. Read
        // the complete table so the asserted entries cannot fall outside a
        // truncated prefix.
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 2048
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let map_line = stdout
        .lines()
        .find(|line| line.contains("R135_MAP:"))
        .ok_or_else(|| anyhow::anyhow!("missing Rust 1.35 HashMap output: {stdout}"))?;
    assert!(map_line.contains("HashMap(size=2)"), "{map_line}");
    assert!(map_line.contains("-7: 13"), "{map_line}");
    assert!(map_line.contains("29: 17"), "{map_line}");

    let set_line = stdout
        .lines()
        .find(|line| line.contains("R135_SET:"))
        .ok_or_else(|| anyhow::anyhow!("missing Rust 1.35 HashSet output: {stdout}"))?;
    assert!(set_line.contains("HashSet(size=2)"), "{set_line}");
    assert!(
        set_line.contains("{-9, 5}") || set_line.contains("{5, -9}"),
        "{set_line}"
    );

    for expected in [
        "R135_EMPTY_MAP:HashMap(size=0) {}",
        "R135_EMPTY_SET:HashSet(size=0) {}",
        "R135_UNIT_MAP:HashMap(size=1) {(): ()}",
        "R135_UNIT_SET:HashSet(size=1) {()}",
    ] {
        assert!(stdout.contains(expected), "missing '{expected}': {stdout}");
    }
    assert!(
        !stdout.contains("ExprError"),
        "unexpected ExprError: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "invalid payload: {stdout}");
    assert!(
        !stdout.contains("<truncated>"),
        "truncated payload: {stdout}"
    );

    Ok(())
}
