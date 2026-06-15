use super::{AddressQueryResult, DwarfAnalyzer};
use crate::core::{ModuleAddress, Result};
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleDefaultPolicy {
    MainExecutableOnly,
    MainExecutableOrSingleSharedLibrary,
}

impl DwarfAnalyzer {
    /// Return loaded module paths in deterministic order.
    pub fn module_paths(&self) -> Vec<PathBuf> {
        let mut modules: Vec<PathBuf> = self.modules.keys().cloned().collect();
        modules.sort();
        modules
    }

    /// Treat identical paths and symlink aliases that canonicalize to the same
    /// file as the same loaded module.
    pub fn module_paths_equivalent<P: AsRef<Path>, Q: AsRef<Path>>(left: P, right: Q) -> bool {
        let left = left.as_ref();
        let right = right.as_ref();
        if left == right {
            return true;
        }

        if proc_root_paths_equivalent(left, right) {
            return true;
        }

        match (left.canonicalize(), right.canonicalize()) {
            (Ok(left), Ok(right)) => left == right,
            _ => match (std::fs::metadata(left), std::fs::metadata(right)) {
                (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
                _ => false,
            },
        }
    }

    /// Match a user-provided module spec against a loaded path by exact path,
    /// symlink equivalence, or unique suffix.
    pub fn module_spec_matches_path<P: AsRef<Path>>(module_path: P, module_spec: &str) -> bool {
        let spec = module_spec.trim();
        if spec.is_empty() {
            return false;
        }

        let module_path = module_path.as_ref();
        Self::module_paths_equivalent(module_path, Path::new(spec))
            || module_path.to_string_lossy().ends_with(spec)
    }

    /// Resolve a module spec against all loaded modules.
    pub fn resolve_loaded_module_by_spec(&self, module_spec: &str) -> Result<PathBuf> {
        let module_spec = module_spec.trim();
        if module_spec.is_empty() {
            return Err(anyhow::anyhow!("Module spec is empty"));
        }

        let modules = self.module_paths();

        if let Some(found) = modules
            .iter()
            .find(|module_path| Self::module_paths_equivalent(module_path, Path::new(module_spec)))
        {
            return Ok(found.clone());
        }

        let candidates: Vec<PathBuf> = modules
            .into_iter()
            .filter(|module_path| module_path.to_string_lossy().ends_with(module_spec))
            .collect();

        match candidates.len() {
            0 => Err(anyhow::anyhow!(
                "Module '{module_spec}' not found among loaded modules. Use full path or a unique suffix."
            )),
            1 => Ok(candidates[0].clone()),
            _ => {
                let sample: Vec<String> = candidates
                    .iter()
                    .take(5)
                    .map(|path| path.to_string_lossy().to_string())
                    .collect();
                Err(anyhow::anyhow!(
                    "Ambiguous module suffix '{}'. Candidates:\n  - {}\nPlease use a more specific suffix or full path.",
                    module_spec,
                    sample.join("\n  - ")
                ))
            }
        }
    }

    /// Resolve the configured -t path to the corresponding loaded module.
    pub fn resolve_target_module_path(&self, target_path: &str) -> Result<PathBuf> {
        let target_path = target_path.trim();
        if target_path.is_empty() {
            return Err(anyhow::anyhow!("Target path from -t is empty"));
        }

        let matches: Vec<PathBuf> = self
            .module_paths()
            .into_iter()
            .filter(|module_path| {
                Self::module_paths_equivalent(module_path, Path::new(target_path))
            })
            .collect();

        match matches.len() {
            0 => Err(anyhow::anyhow!(
                "Target '{target_path}' from -t is not loaded in the analyzed modules. When -t and -p are combined, -t scopes trace target resolution and -p only supplies PID filtering."
            )),
            1 => Ok(matches[0].clone()),
            _ => Err(anyhow::anyhow!(
                "Target '{target_path}' from -t matches multiple loaded modules; use a more specific path."
            )),
        }
    }

    /// Resolve an explicit module spec, respecting -t scoping when configured.
    pub fn resolve_module_spec(
        &self,
        module_spec: &str,
        target_path: Option<&str>,
    ) -> Result<PathBuf> {
        let Some(target_path) = target_path else {
            return self.resolve_loaded_module_by_spec(module_spec);
        };

        let target_module = self.resolve_target_module_path(target_path)?;
        if Self::module_spec_matches_path(&target_module, module_spec)
            || Self::module_spec_matches_path(target_path, module_spec)
        {
            Ok(target_module)
        } else {
            Err(anyhow::anyhow!(
                "Module '{}' is outside -t target '{}'. When -t is configured, module resolution is scoped to the target.",
                module_spec.trim(),
                target_module.display()
            ))
        }
    }

    /// Resolve the module to use for a module-relative address query.
    pub fn resolve_address_module(
        &self,
        module_spec: Option<&str>,
        target_path: Option<&str>,
        fallback: ModuleDefaultPolicy,
    ) -> Result<PathBuf> {
        if let Some(module_spec) = module_spec {
            return self.resolve_module_spec(module_spec, target_path);
        }

        if let Some(target_path) = target_path {
            return self.resolve_target_module_path(target_path);
        }

        if let Some(main) = self
            .module_paths()
            .into_iter()
            .find(|module_path| self.is_main_executable_module(module_path))
        {
            return Ok(main);
        }

        if fallback == ModuleDefaultPolicy::MainExecutableOrSingleSharedLibrary {
            let libs: Vec<PathBuf> = self
                .module_paths()
                .into_iter()
                .filter(|module_path| self.is_shared_library(module_path))
                .collect();
            if libs.len() == 1 {
                return Ok(libs[0].clone());
            }
        }

        let message = match fallback {
            ModuleDefaultPolicy::MainExecutableOnly => {
                "No default module available. Start with -p <pid> or -t <binary>."
            }
            ModuleDefaultPolicy::MainExecutableOrSingleSharedLibrary => {
                "No module available to resolve address. In PID mode, default module is the main executable. In target mode (-t <binary>), the specified binary is used (including .so)."
            }
        };
        Err(anyhow::anyhow!(message))
    }

    /// Filter module-address matches to the configured -t target.
    pub fn filter_module_addresses_to_target(
        &self,
        module_addresses: Vec<ModuleAddress>,
        target_path: Option<&str>,
    ) -> Result<Vec<ModuleAddress>> {
        let Some(target_path) = target_path else {
            return Ok(module_addresses);
        };
        if module_addresses.is_empty() {
            return Ok(module_addresses);
        }

        let target_module = self.resolve_target_module_path(target_path)?;
        Ok(module_addresses
            .into_iter()
            .filter(|module_address| {
                Self::module_paths_equivalent(&module_address.module_path, &target_module)
            })
            .collect())
    }

    /// Filter address-query matches to the configured -t target.
    pub fn filter_address_results_to_target(
        &self,
        addresses: Vec<AddressQueryResult>,
        target_path: Option<&str>,
    ) -> Result<Vec<AddressQueryResult>> {
        let Some(target_path) = target_path else {
            return Ok(addresses);
        };
        if addresses.is_empty() {
            return Ok(addresses);
        }

        let target_module = self.resolve_target_module_path(target_path)?;
        Ok(addresses
            .into_iter()
            .filter(|address| Self::module_paths_equivalent(&address.module_path, &target_module))
            .collect())
    }
}

fn proc_root_paths_equivalent(left: &Path, right: &Path) -> bool {
    match (strip_proc_root_prefix(left), strip_proc_root_prefix(right)) {
        (Some(left), Some(right)) => left == right,
        (Some(left), None) => left.as_path() == right,
        (None, Some(right)) => left == right.as_path(),
        (None, None) => false,
    }
}

fn strip_proc_root_prefix(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("proc")
    ) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(pid)) if pid.as_encoded_bytes().iter().all(u8::is_ascii_digit)
    ) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("root")
    ) {
        return None;
    }

    let remaining = components.as_path();
    let mut stripped = PathBuf::from("/");
    if !remaining.as_os_str().is_empty() {
        stripped.push(remaining);
    }
    Some(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_spec_rejects_empty_strings() {
        assert!(!DwarfAnalyzer::module_spec_matches_path(
            "/tmp/libfoo.so",
            ""
        ));
        assert!(!DwarfAnalyzer::module_spec_matches_path(
            "/tmp/libfoo.so",
            "   "
        ));
    }

    #[test]
    fn module_spec_matches_unique_suffixes() {
        assert!(DwarfAnalyzer::module_spec_matches_path(
            "/opt/app/lib/libfoo.so.1",
            "lib/libfoo.so.1"
        ));
        assert!(DwarfAnalyzer::module_spec_matches_path(
            "/opt/app/lib/libfoo.so.1",
            "libfoo.so.1"
        ));
    }

    #[test]
    fn proc_root_paths_match_same_inner_path() {
        assert!(proc_root_paths_equivalent(
            Path::new("/proc/123/root/usr/lib/libfoo.so"),
            Path::new("/proc/456/root/usr/lib/libfoo.so")
        ));
        assert!(proc_root_paths_equivalent(
            Path::new("/proc/123/root/usr/lib/libfoo.so"),
            Path::new("/usr/lib/libfoo.so")
        ));
    }

    #[test]
    fn proc_root_paths_reject_non_pid_prefixes() {
        assert!(!proc_root_paths_equivalent(
            Path::new("/proc/self/root/usr/lib/libfoo.so"),
            Path::new("/usr/lib/libfoo.so")
        ));
        assert!(!proc_root_paths_equivalent(
            Path::new("/proc/123/maps"),
            Path::new("/maps")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn module_spec_matches_symlink_alias() -> anyhow::Result<()> {
        use std::os::unix::fs as unix_fs;

        let temp_dir = tempfile::tempdir()?;
        let real_path = temp_dir.path().join("libfoo.so.1");
        let alias_path = temp_dir.path().join("libfoo.so");
        std::fs::write(&real_path, b"test")?;
        unix_fs::symlink(&real_path, &alias_path)?;

        assert!(DwarfAnalyzer::module_spec_matches_path(
            &real_path,
            alias_path.to_string_lossy().as_ref()
        ));

        Ok(())
    }
}
