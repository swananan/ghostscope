use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ModuleMapping {
    pub path: PathBuf,
    pub loaded_address: Option<u64>,
    pub size: u64,
}

impl ModuleMapping {
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path,
            loaded_address: None,
            size: 0,
        }
    }
}
