#![crate_name = "rust_backtrace_program"]

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

static RESULT: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_backtrace_probe(value: usize) -> usize {
    black_box(value.wrapping_add(1))
}

#[inline(always)]
fn rust_backtrace_inline(value: usize) -> usize {
    rust_backtrace_probe(value) // INLINE_BACKTRACE_TRACE_POINT
}

#[inline(never)]
fn rust_backtrace_middle(value: usize) -> usize {
    let result = rust_backtrace_inline(value);
    black_box(result.wrapping_mul(3))
}

#[inline(never)]
fn rust_backtrace_outer(value: usize) -> usize {
    let result = rust_backtrace_middle(value);
    black_box(result.wrapping_add(value))
}

fn main() {
    let mut value = 1usize;
    loop {
        value = rust_backtrace_outer(value);
        RESULT.store(value, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(25));
    }
}
