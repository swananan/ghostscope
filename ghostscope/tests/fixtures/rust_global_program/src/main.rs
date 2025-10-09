#![allow(non_upper_case_globals)]

use std::{thread, time::Duration};

pub static mut G_COUNTER: i32 = 0;
pub static G_MESSAGE: &str = "hello from rust";

#[repr(C)]
pub struct Config {
    pub a: i32,
    pub b: i64,
}

pub static mut CONFIG: Config = Config { a: 7, b: 11 };

pub mod math {
    #[inline(never)]
    pub fn do_stuff(x: i32) -> i32 {
        // Simple function for DWARF function indexing
        x + 1
    }
}

fn touch_globals() -> i32 {
    unsafe {
        G_COUNTER += 1;
        CONFIG.a += 1;
        CONFIG.a + (G_MESSAGE.len() as i32)
    }
}

fn main() {
    let mut acc = 0;
    for _ in 0..50000 {
        acc += math::do_stuff(3);
        acc += touch_globals();
        thread::sleep(Duration::from_millis(1000));
    }
    // Prevent optimization from dropping acc
    if acc == 0x7fff_ffff { println!("dead"); }
}

