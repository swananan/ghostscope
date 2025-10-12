use crate::core::session::GhostSession;

/// Derive a short binary path hint for compiler options and logging.
/// Priority:
/// 1) If started with target file mode (-t), use the target binary's file stem.
/// 2) Else, use the main executable from the DWARF analyzer (file stem).
/// 3) Fallback to "unknown" if neither is available.
pub fn derive_binary_path_hint(session: &GhostSession) -> Option<String> {
    // Prefer explicit target in -t mode
    if session.is_target_mode() {
        if let Some(ref target) = session.target_binary {
            if let Some(stem) = std::path::Path::new(target)
                .file_stem()
                .and_then(|s| s.to_str())
            {
                return Some(stem.to_string());
            }
        }
    }

    // Fallback: main executable from analyzer (PID mode or resolved target)
    if let Some(main_module) = session
        .process_analyzer
        .as_ref()
        .and_then(|analyzer| analyzer.get_main_executable())
    {
        if let Some(stem) = std::path::Path::new(&main_module.path)
            .file_stem()
            .and_then(|s| s.to_str())
        {
            return Some(stem.to_string());
        }
    }

    // Final fallback to maintain previous behavior
    Some("unknown".to_string())
}
