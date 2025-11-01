use object::Object;
use std::fs;

/// Compute a stable cookie from a module file path (no PID context):
/// 1) Build-ID if available; 2) filesystem dev:ino; 3) absolute path string hash.
pub fn from_path(module_path: &str) -> u64 {
    // 1) Build-ID
    if let Ok(bytes) = fs::read(module_path) {
        if let Ok(obj) = object::File::parse(&bytes[..]) {
            if let Ok(Some(build_id)) = obj.build_id() {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                build_id.hash(&mut hasher);
                return hasher.finish();
            }
        }
    }
    // 2) Filesystem dev:ino
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(module_path) {
            let dev = meta.dev();
            let ino = meta.ino();
            return ((dev & 0xffff_ffff) << 32) | (ino & 0xffff_ffff);
        }
    }
    // 3) Absolute path string hash
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    module_path.hash(&mut hasher);
    hasher.finish()
}
