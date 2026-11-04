use anyhow::{ensure, Context, Result};
use ghostscope_compiler::{script::TracePattern, CompilationResult, UProbeConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::settings::{EbpfConfig, ValueAdapterConfig};

// Bump when the stored probe/context schema or compiled runtime ABI changes.
const FORMAT_VERSION: u32 = 1;
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    format_version: u32,
    ghostscope_version: String,
    architecture: String,
    pub target: String,
    pub target_sha256: [u8; 32],
    pub module_cookie: u64,
    pub script: String,
    pub ebpf: EbpfConfig,
    pub value_adapter: ValueAdapterConfig,
    pub probes: Vec<Probe>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Probe {
    function_name: Option<String>,
    function_address: u64,
    uprobe_offset: u64,
    ebpf_bytecode: Vec<u8>,
    ebpf_function_name: String,
    assigned_trace_id: u32,
    trace_context: ghostscope_protocol::TraceContext,
    resolved_address_index: Option<usize>,
}

impl Bundle {
    pub fn from_compilation(
        target: String,
        target_sha256: [u8; 32],
        module_cookie: u64,
        script: String,
        ebpf: EbpfConfig,
        value_adapter: ValueAdapterConfig,
        compilation: CompilationResult,
    ) -> Result<Self> {
        ensure!(
            compilation.failed_targets.is_empty(),
            "prepare refuses a partially compiled script; fix all failed targets"
        );
        ensure!(!compilation.uprobe_configs.is_empty(), "no probes compiled");
        let probes = compilation
            .uprobe_configs
            .into_iter()
            .map(|config| {
                ensure!(
                    !config.uses_backtrace,
                    "prepare does not support bt/backtrace yet"
                );
                ensure!(
                    config.binary_path == target,
                    "prepare supports one target module only"
                );
                Ok(Probe {
                    function_name: config.function_name,
                    function_address: config.function_address.context("probe has no address")?,
                    uprobe_offset: config
                        .uprobe_offset
                        .context("probe has no attachment offset")?,
                    ebpf_bytecode: config.ebpf_bytecode,
                    ebpf_function_name: config.ebpf_function_name,
                    assigned_trace_id: config.assigned_trace_id,
                    trace_context: config.trace_context,
                    resolved_address_index: config.resolved_address_index,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            format_version: FORMAT_VERSION,
            ghostscope_version: env!("CARGO_PKG_VERSION").into(),
            architecture: std::env::consts::ARCH.into(),
            target,
            target_sha256,
            module_cookie,
            script,
            ebpf,
            value_adapter,
            probes,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let file = open_regular_file(path)
            .with_context(|| format!("cannot open bundle {}", path.display()))?;
        ensure!(
            file.metadata()?.len() <= MAX_BUNDLE_BYTES,
            "bundle exceeds 64 MiB limit"
        );
        let mut bytes = Vec::new();
        file.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BUNDLE_BYTES,
            "bundle exceeds 64 MiB limit"
        );
        let bundle: Self = serde_json::from_slice(&bytes).context("invalid trace bundle")?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<()> {
        self.ebpf.validate("trace bundle")?;
        self.value_adapter.validate("trace bundle")?;
        ensure!(
            self.format_version == FORMAT_VERSION,
            "unsupported bundle format version; prepare it again"
        );
        ensure!(
            self.ghostscope_version == env!("CARGO_PKG_VERSION"),
            "bundle GhostScope version mismatch; prepare it again"
        );
        ensure!(
            self.architecture == std::env::consts::ARCH,
            "bundle architecture mismatch"
        );
        ensure!(!self.probes.is_empty(), "bundle contains no probes");
        let mut ids = std::collections::HashSet::new();
        for probe in &self.probes {
            ensure!(
                ids.insert(probe.assigned_trace_id),
                "duplicate trace ID in bundle"
            );
            ensure!(
                probe.assigned_trace_id < u32::MAX,
                "invalid trace ID in bundle"
            );
            ensure!(
                probe.ebpf_bytecode.starts_with(b"\x7fELF"),
                "probe bytecode is not ELF"
            );
        }
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(file.as_file_mut(), self)?;
        ensure!(
            file.as_file().metadata()?.len() <= MAX_BUNDLE_BYTES,
            "bundle exceeds 64 MiB limit"
        );
        file.flush()?;
        file.as_file().sync_all()?;
        // The serializer has no matching nesting limit. Do not publish a file
        // whose type context the bounded reader cannot deserialize.
        Self::read(file.path()).context("prepared context exceeds bundle decoding limits")?;
        file.persist_noclobber(path).with_context(|| {
            format!(
                "cannot create {}; existing bundles are not overwritten",
                path.display()
            )
        })?;
        Ok(())
    }

    pub fn into_compilation(self, target: &str, pid: u32) -> CompilationResult {
        let configs: Vec<_> = self
            .probes
            .into_iter()
            .map(|probe| UProbeConfig {
                trace_pattern: TracePattern::Address(probe.function_address),
                binary_path: target.into(),
                function_name: probe.function_name,
                function_address: Some(probe.function_address),
                uprobe_offset: Some(probe.uprobe_offset),
                target_pid: Some(pid),
                ebpf_bytecode: probe.ebpf_bytecode,
                ebpf_function_name: probe.ebpf_function_name,
                assigned_trace_id: probe.assigned_trace_id,
                trace_context: probe.trace_context,
                backtrace_unwind_rows: Vec::new(),
                backtrace_module_row_ranges: Vec::new(),
                backtrace_tail_call_program: None,
                uses_backtrace: false,
                resolved_address_index: probe.resolved_address_index,
            })
            .collect();
        CompilationResult {
            trace_count: configs.len(),
            target_info: target.into(),
            failed_targets: Vec::new(),
            next_available_trace_id: configs
                .iter()
                .map(|p| p.assigned_trace_id + 1)
                .max()
                .unwrap_or(0),
            uprobe_configs: configs,
        }
    }
}

pub(super) fn fingerprint(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

/// Opening a FIFO/device must not block an offline identity check.
pub(super) fn open_regular_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "expected a regular file: {}",
        path.display()
    );
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_bundle_is_rejected_before_json_decoding() -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        file.as_file().set_len(MAX_BUNDLE_BYTES + 1)?;
        assert!(Bundle::read(file.path())
            .unwrap_err()
            .to_string()
            .contains("64 MiB"));
        Ok(())
    }

    #[test]
    fn incomplete_bundle_is_rejected() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"{\"format_version\":1,")?;
        assert!(Bundle::read(file.path())
            .unwrap_err()
            .to_string()
            .contains("invalid trace bundle"));
        Ok(())
    }

    #[test]
    fn unreadable_type_context_is_not_published() -> Result<()> {
        use ghostscope_protocol::TypeInfo;
        let mut ty = TypeInfo::UnknownType {
            name: "deep".into(),
        };
        for _ in 0..128 {
            ty = TypeInfo::PointerType {
                target_type: Box::new(ty),
                size: 8,
            };
        }
        let mut context = ghostscope_protocol::TraceContext::new();
        context.add_type(ty)?;
        let bundle = Bundle {
            format_version: FORMAT_VERSION,
            ghostscope_version: env!("CARGO_PKG_VERSION").into(),
            architecture: std::env::consts::ARCH.into(),
            target: "unused".into(),
            target_sha256: [0; 32],
            module_cookie: 1,
            script: String::new(),
            ebpf: EbpfConfig::default(),
            value_adapter: ValueAdapterConfig::default(),
            probes: vec![Probe {
                function_name: None,
                function_address: 1,
                uprobe_offset: 1,
                ebpf_bytecode: b"\x7fELF".to_vec(),
                ebpf_function_name: "probe".into(),
                assigned_trace_id: 1,
                trace_context: context,
                resolved_address_index: None,
            }],
        };
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("trace.gsb");
        assert!(bundle.write(&path).is_err());
        assert!(!path.exists());
        assert_eq!(directory.path().read_dir()?.count(), 0);
        Ok(())
    }
}
