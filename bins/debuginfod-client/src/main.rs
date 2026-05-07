use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ghostscope_debuginfod::{DebuginfodClient, DebuginfodConfig, FetchedFile};
use object::Object;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const UBUNTU_DEBUGINFOD_URL: &str = "https://debuginfod.ubuntu.com";

#[derive(Debug, Parser)]
#[command(about = "Fetch debuginfod artifacts with GhostScope's async client")]
struct Cli {
    /// Debuginfod server URL. May be passed more than once.
    #[arg(long = "url", value_name = "URL", default_value = UBUNTU_DEBUGINFOD_URL)]
    urls: Vec<String>,

    /// Local cache directory for downloaded artifacts.
    #[arg(
        long,
        value_name = "DIR",
        default_value = "target/debuginfod-client-cache"
    )]
    cache_dir: PathBuf,

    /// Request timeout in seconds. Use 0 to disable reqwest's global request timeout.
    #[arg(long, default_value_t = ghostscope_debuginfod::DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,

    /// Maximum response size in bytes. Omit for no explicit client-side cap.
    #[arg(long, value_name = "BYTES")]
    max_size: Option<u64>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Fetch /buildid/<build-id>/debuginfo.
    Debuginfo(BuildIdInput),
    /// Fetch /buildid/<build-id>/executable.
    Executable(BuildIdInput),
    /// Fetch /buildid/<build-id>/source/<absolute-source-path>.
    Source(SourceInput),
}

#[derive(Debug, Args)]
struct BuildIdInput {
    /// Hex build-id to query.
    #[arg(long, conflicts_with = "file")]
    build_id: Option<String>,

    /// ELF file to read the GNU build-id from.
    #[arg(long, value_name = "ELF", conflicts_with = "build_id")]
    file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SourceInput {
    #[command(flatten)]
    build_id: BuildIdInput,

    /// Absolute source path as recorded or resolved from DWARF.
    #[arg(long, value_name = "PATH")]
    path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = DebuginfodConfig::new(cli.urls, &cli.cache_dir)?;
    if cli.timeout_secs == 0 {
        config = config.without_timeout();
    } else {
        config = config.with_timeout(Duration::from_secs(cli.timeout_secs));
    }
    config = config.with_max_size(cli.max_size);

    let client = DebuginfodClient::new(config)?;
    let fetched = match cli.command {
        Command::Debuginfo(input) => {
            let build_id = input.resolve_build_id()?;
            client.fetch_debuginfo(&build_id).await?
        }
        Command::Executable(input) => {
            let build_id = input.resolve_build_id()?;
            client.fetch_executable(&build_id).await?
        }
        Command::Source(input) => {
            let build_id = input.build_id.resolve_build_id()?;
            client.fetch_source(&build_id, &input.path).await?
        }
    };

    match fetched {
        Some(file) => print_fetched_file(&file),
        None => bail!("artifact not found on any configured debuginfod server"),
    }

    Ok(())
}

impl BuildIdInput {
    fn resolve_build_id(&self) -> Result<Vec<u8>> {
        match (&self.build_id, &self.file) {
            (Some(build_id), None) => parse_build_id_hex(build_id),
            (None, Some(file)) => read_build_id_from_elf(file),
            (None, None) => Err(anyhow!("pass either --build-id <hex> or --file <elf>")),
            (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
        }
    }
}

fn print_fetched_file(file: &FetchedFile) {
    println!("build-id: {}", file.build_id);
    println!("path: {}", file.path.display());
    println!("from-cache: {}", file.from_cache);
    if let Some(url) = &file.url {
        println!("url: {url}");
    }
}

fn read_build_id_from_elf(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read ELF file {}", path.display()))?;
    let object = object::File::parse(&bytes[..])
        .with_context(|| format!("failed to parse ELF file {}", path.display()))?;
    object
        .build_id()
        .context("failed to read GNU build-id note")?
        .map(|build_id| build_id.to_vec())
        .ok_or_else(|| anyhow!("ELF file has no GNU build-id: {}", path.display()))
}

fn parse_build_id_hex(raw: &str) -> Result<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("build-id must not be empty");
    }
    if raw.len() % 2 != 0 {
        bail!("build-id hex must contain an even number of digits");
    }

    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for idx in (0..raw.len()).step_by(2) {
        let byte = u8::from_str_radix(&raw[idx..idx + 2], 16)
            .with_context(|| format!("invalid build-id hex at byte {}", idx / 2))?;
        bytes.push(byte);
    }
    Ok(bytes)
}
