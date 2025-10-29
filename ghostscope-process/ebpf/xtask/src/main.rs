use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "xtask",
    version,
    about = "Development tasks for GhostScope (eBPF)",
    propagate_version = true
)]
struct XtaskCli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build the sysmon eBPF object and copy it into ebpf/obj/sysmon-bpf.{bpfel,bpfeb}.o
    BuildEbpf {
        /// Rust toolchain to use (e.g. nightly-2024-07-01)
        #[arg(long, default_value = "nightly-2024-07-01")]
        toolchain: String,
        /// BPF target triple: bpfel-unknown-none, bpfeb-unknown-none, auto, or both
        #[arg(long, default_value = "auto")]
        target: String,
        /// Skip installing rust-src component
        #[arg(long, default_value_t = false)]
        skip_rust_src: bool,
    },
    /// Clean sysmon eBPF artifacts (object + target dir)
    CleanEbpf,
}

fn project_root() -> Result<PathBuf> {
    // Start from ebpf/xtask and walk up until we find root Cargo.toml
    let mut dir = std::env::current_dir()?;
    for _ in 0..8 {
        if dir.join("Cargo.toml").exists() {
            return Ok(dir);
        }
        dir = dir
            .parent()
            .ok_or_else(|| anyhow!("failed to locate project root"))?
            .to_path_buf();
    }
    Err(anyhow!("failed to locate project root (no Cargo.toml)"))
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("failed: {:?}", cmd))?;
    if !status.success() {
        return Err(anyhow!("command failed: {:?}", cmd));
    }
    Ok(())
}

fn ensure_toolchain(toolchain: &str, install_rust_src: bool) -> Result<()> {
    let mut c = Command::new("rustup");
    c.arg("toolchain").arg("install").arg(toolchain);
    if install_rust_src {
        c.arg("--component").arg("rust-src");
    }
    let _ = c.status();
    Ok(())
}

fn is_elf(path: &Path) -> Result<bool> {
    let mut f = fs::File::open(path)?;
    let mut hdr = [0u8; 4];
    let n = f.read(&mut hdr)?;
    Ok(n >= 4 && hdr == [0x7f, b'E', b'L', b'F'])
}

fn resolve_target(target: &str) -> String {
    if target == "auto" {
        if cfg!(target_endian = "little") {
            "bpfel-unknown-none".to_string()
        } else {
            "bpfeb-unknown-none".to_string()
        }
    } else {
        target.to_string()
    }
}

fn build_one(toolchain: &str, target_triple: &str, bpf_crate: &Path, out_dst: &Path) -> Result<()> {
    let mut build = Command::new("cargo");
    build
        .arg(format!("+{}", toolchain))
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target_triple)
        .arg("-Z")
        .arg("build-std=core")
        .current_dir(bpf_crate);
    run(&mut build)?;

    let dir = bpf_crate.join("target").join(target_triple).join("release");
    let cand_so = dir.join("libsysmon_bpf.so");
    let cand_bin = dir.join("sysmon-bpf");
    let cand_a = dir.join("libsysmon_bpf.a");

    if cand_so.exists() {
        if !is_elf(&cand_so)? {
            return Err(anyhow!("{} is not an ELF object", cand_so.display()));
        }
        fs::copy(&cand_so, out_dst)?;
        println!("Wrote {} (from {})", out_dst.display(), cand_so.display());
    } else if cand_bin.exists() {
        if !is_elf(&cand_bin)? {
            return Err(anyhow!("{} is not an ELF object", cand_bin.display()));
        }
        fs::copy(&cand_bin, out_dst)?;
        println!("Wrote {} (from {})", out_dst.display(), cand_bin.display());
    } else if cand_a.exists() {
        let tmp = tempfile::tempdir()?;
        let mut x = Command::new("ar");
        x.arg("x").arg(&cand_a).current_dir(tmp.path());
        run(&mut x)?;
        let mut first_o: Option<PathBuf> = None;
        for entry in fs::read_dir(tmp.path())? {
            let p = entry?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("o") {
                first_o = Some(p);
                break;
            }
        }
        let first = first_o.ok_or_else(|| anyhow!("no .o found in {}", cand_a.display()))?;
        if !is_elf(&first)? {
            return Err(anyhow!("extracted {} is not an ELF object", first.display()));
        }
        fs::copy(&first, out_dst)?;
        println!("Wrote {} (from archive {})", out_dst.display(), cand_a.display());
    } else {
        return Err(anyhow!("expected object not found under {}", dir.display()));
    }
    Ok(())
}

fn build_ebpf(toolchain: &str, target: &str, skip_rust_src: bool) -> Result<()> {
    let root = project_root()?;
    let bpf_crate = root.join("ghostscope-process/ebpf/sysmon-bpf");
    let obj_dir = root.join("ghostscope-process/ebpf/obj");
    let out_le = obj_dir.join("sysmon-bpf.bpfel.o");
    let out_be = obj_dir.join("sysmon-bpf.bpfeb.o");

    ensure_toolchain(toolchain, !skip_rust_src)?;
    fs::create_dir_all(&obj_dir)?;

    if target == "both" {
        build_one(toolchain, "bpfel-unknown-none", &bpf_crate, &out_le)?;
        build_one(toolchain, "bpfeb-unknown-none", &bpf_crate, &out_be)?;
    } else {
        let target_triple = resolve_target(target);
        println!("Using BPF target: {}", target_triple);
        let out_dst = if target_triple.starts_with("bpfel") { &out_le } else { &out_be };
        build_one(toolchain, &target_triple, &bpf_crate, out_dst)?;
    }

    Ok(())
}

fn clean_ebpf() -> Result<()> {
    let root = project_root()?;
    let out_obj = root.join("ghostscope-process/ebpf/obj/sysmon-bpf.o");
    let out_obj_compat = root.join("ghostscope-process/ebpf/obj/sysmon-bpf.bpf.o");
    let target_dir = root.join("ghostscope-process/ebpf/sysmon-bpf/target");
    let _ = fs::remove_file(&out_obj);
    let _ = fs::remove_file(&out_obj_compat);
    let _ = fs::remove_dir_all(&target_dir);
    println!("Cleaned {}", target_dir.display());
    Ok(())
}

fn main() -> Result<()> {
    let args = XtaskCli::parse();
    match args.cmd {
        Cmd::BuildEbpf {
            toolchain,
            target,
            skip_rust_src,
        } => build_ebpf(&toolchain, &target, skip_rust_src),
        Cmd::CleanEbpf => clean_ebpf(),
    }
}

