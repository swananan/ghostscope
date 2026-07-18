use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

static mut RESULT: usize = 0;

#[no_mangle]
#[inline(never)]
pub fn observe_paths(
    borrowed: &Path,
    owned: PathBuf,
    empty: &Path,
    long: &Path,
) -> usize {
    std::hint::black_box(&owned);
    borrowed.as_os_str().as_bytes().len()
        + owned.as_os_str().as_bytes().len()
        + empty.as_os_str().as_bytes().len()
        + long.as_os_str().as_bytes().len()
}

fn main() {
    let borrowed = PathBuf::from("borrowed/path");
    let empty = PathBuf::new();
    let long = PathBuf::from("abcdefghijklmnopqrstuvwxyz");
    loop {
        let invalid = PathBuf::from(OsString::from_vec(b"bad/\xff/path".to_vec()));
        let owned_result = observe_paths(
            borrowed.as_path(),
            PathBuf::from("owned/path"),
            empty.as_path(),
            long.as_path(),
        );
        let invalid_result = observe_paths(
            borrowed.as_path(),
            invalid,
            empty.as_path(),
            long.as_path(),
        );
        unsafe {
            std::ptr::write_volatile(&mut RESULT, owned_result + invalid_result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}
