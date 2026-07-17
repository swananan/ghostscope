#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ghostscope_dwarf::RustcVersion;
use tempfile::{Builder, TempDir};

const DEFAULT_TOOLCHAINS: &str = include_str!("../../rust-compat-toolchains.txt");
const TOOLCHAINS_ENV: &str = "GHOSTSCOPE_RUST_COMPAT_TOOLCHAINS";

pub fn fixture_tempdir() -> anyhow::Result<TempDir> {
    // Container-backed targets can only access host paths covered by the
    // repository bind mount, so keep runtime-compiled fixtures under it.
    Ok(Builder::new()
        .prefix(".ghostscope-rust-e2e-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?)
}

pub fn compile_standalone_fixture(
    rustc: &Path,
    toolchain: &str,
    source: &Path,
    binary: &Path,
) -> anyhow::Result<()> {
    compile_fixture(rustc, toolchain, source, binary, true)
}

pub fn compile_compact_standalone_fixture(
    rustc: &Path,
    toolchain: &str,
    source: &Path,
    binary: &Path,
) -> anyhow::Result<()> {
    compile_fixture(rustc, toolchain, source, binary, false)
}

fn compile_fixture(
    rustc: &Path,
    toolchain: &str,
    source: &Path,
    binary: &Path,
    link_dead_code: bool,
) -> anyhow::Result<()> {
    let mut command = Command::new(rustc);
    command
        .args(["--edition=2018", "-g"])
        .arg("-C")
        .arg("opt-level=0");
    if link_dead_code {
        command.arg("-C").arg("link-dead-code");
    }
    let output = command.arg(source).arg("-o").arg(binary).output()?;
    anyhow::ensure!(
        output.status.success(),
        "rustc {toolchain} failed for {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub fn rustc_for_toolchain(toolchain: &str) -> Option<PathBuf> {
    if let Ok(output) = Command::new("rustup")
        .args(["which", "--toolchain", toolchain, "rustc"])
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
                (name == toolchain || name.starts_with(&format!("{toolchain}-")))
                    .then_some(rustc)
                    .filter(|path| path.is_file())
            })
    })
}

pub fn configured_toolchains() -> Vec<String> {
    std::env::var(TOOLCHAINS_ENV)
        .ok()
        .map(|value| parse_toolchains(&value, ','))
        .filter(|toolchains| !toolchains.is_empty())
        .unwrap_or_else(|| parse_toolchains(DEFAULT_TOOLCHAINS, '\n'))
}

pub fn rustc_version(rustc: &Path, toolchain: &str) -> anyhow::Result<RustcVersion> {
    let output = Command::new(rustc).arg("--version").output()?;
    anyhow::ensure!(
        output.status.success(),
        "rustc {toolchain} --version failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .split_ascii_whitespace()
        .nth(1)
        .and_then(RustcVersion::parse)
        .ok_or_else(|| anyhow::anyhow!("unrecognized rustc version output: {stdout:?}"))
}

pub fn toolchain_id(toolchain: &str) -> String {
    toolchain
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub fn precompiled_compat_fixture(toolchain: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_compat_program/bin")
        .join(toolchain_id(toolchain))
        .join("rust_compat_program")
}

fn parse_toolchains(value: &str, separator: char) -> Vec<String> {
    value
        .split(separator)
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}
