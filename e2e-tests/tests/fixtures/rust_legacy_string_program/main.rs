use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::thread;
use std::time::Duration;

static mut RESULT: usize = 0;

#[no_mangle]
#[inline(never)]
pub fn observe_legacy_strings(
    owned: String,
    valid_os: OsString,
    invalid_os: OsString,
    text: &str,
    boxed: Box<str>,
    empty_owned: String,
    empty_os: OsString,
    empty_text: &str,
    empty_boxed: Box<str>,
) -> usize {
    owned.len()
        + valid_os.len()
        + invalid_os.len()
        + text.len()
        + boxed.len()
        + empty_owned.len()
        + empty_os.len()
        + empty_text.len()
        + empty_boxed.len()
}

fn main() {
    loop {
        let result = observe_legacy_strings(
            String::from("legacy = string"),
            OsString::from("os from 1.35"),
            OsString::from_vec(vec![b'o', b's', 0xff, b'x']),
            "legacy\0str",
            String::from("boxed from 1.35").into_boxed_str(),
            String::new(),
            OsString::new(),
            "",
            String::new().into_boxed_str(),
        );
        unsafe {
            std::ptr::write_volatile(&mut RESULT, result);
        }
        thread::sleep(Duration::from_millis(25));
    }
}
