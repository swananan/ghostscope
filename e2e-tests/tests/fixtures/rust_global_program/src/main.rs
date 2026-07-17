#![allow(non_upper_case_globals)]
#![allow(static_mut_refs)]

use std::{
    ffi::OsString,
    marker::{PhantomData, PhantomPinned},
    num::NonZeroU32,
    thread,
    time::Duration,
};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

pub static mut G_COUNTER: i32 = 0;
pub static G_MESSAGE: &str = "hello from rust";
pub static G_EMPTY_MESSAGE: &str = "";
pub static G_NUL_MESSAGE: &str = "left\0right";
pub static mut G_OWNED_MESSAGE: String = String::new();
pub static mut G_EMPTY_OWNED: String = String::new();
pub static mut G_NUL_OWNED: String = String::new();
pub static mut G_SEPARATOR_OWNED: String = String::new();
pub static mut G_VEC_U8: Vec<u8> = Vec::new();
pub static mut G_VEC_I32: Vec<i32> = Vec::new();
pub static mut G_EMPTY_VEC: Vec<i32> = Vec::new();
pub static mut G_VEC_UNIT: Vec<()> = Vec::new();
pub static mut G_SLICE_I32: &[i32] = &[];
pub static mut G_MUT_SLICE_U16: &mut [u16] = &mut [];
pub static mut G_EMPTY_SLICE: &[i32] = &[];

pub mod user_types {
    pub struct String {
        pub vec: std::vec::Vec<u8>,
        pub marker: u32,
    }

    #[repr(C)]
    pub struct Vec<T> {
        pub buf: Buffer<T>,
        pub len: usize,
    }

    #[repr(C)]
    pub struct Buffer<T> {
        pub inner: BufferInner<T>,
    }

    #[repr(C)]
    pub struct BufferInner<T> {
        pub padding: usize,
        pub ptr: Unique<T>,
    }

    #[repr(C)]
    pub struct Unique<T> {
        pub pointer: NonNull<T>,
    }

    #[repr(C)]
    pub struct NonNull<T> {
        pub pointer: *mut T,
    }
}

pub static mut G_USER_STRING: user_types::String = user_types::String {
    vec: Vec::new(),
    marker: 41,
};

pub static mut G_USER_VEC: user_types::Vec<i32> = user_types::Vec {
    buf: user_types::Buffer {
        inner: user_types::BufferInner {
            padding: 0,
            ptr: user_types::Unique {
                pointer: user_types::NonNull {
                    pointer: std::ptr::null_mut(),
                },
            },
        },
    },
    len: 0,
};

#[repr(C)]
pub struct Config {
    pub a: i32,
    pub b: i64,
}

pub static mut CONFIG: Config = Config { a: 7, b: 11 };

pub struct Pair(pub i32, pub i32);

pub struct PhantomWrapper<T> {
    pub value: i32,
    _marker: PhantomData<T>,
}

pub union NumberUnion {
    pub int_value: i32,
    pub float_value: f32,
}

#[derive(Clone, Copy)]
pub enum GlobalState {
    Idle,
    Counter(i32),
    Slice(&'static [u8]),
    TupleState { left: i32, right: bool },
}

pub trait Greeter {
    fn greet(&self) -> &'static str;
}

pub struct StaticGreeter;

impl Greeter for StaticGreeter {
    fn greet(&self) -> &'static str {
        "static-greeter"
    }
}

pub struct DynHolder<'a> {
    pub greet: Option<&'a dyn Greeter>,
}

impl<'a> DynHolder<'a> {
    fn toggle(&mut self) {
        if self.greet.is_some() {
            self.greet = None;
        } else {
            self.greet = Some(&STATIC_GREETER);
        }
    }
}

pub struct PinnedCounter {
    pub value: i32,
    _pin: PhantomPinned,
}

impl PinnedCounter {
    const fn new(value: i32) -> Self {
        Self {
            value,
            _pin: PhantomPinned,
        }
    }

    fn bump(&mut self) -> i32 {
        self.value += 1;
        self.value
    }
}

static STATIC_GREETER: StaticGreeter = StaticGreeter;
static DATA_ALPHA: &[u8] = b"alpha";
static DATA_OMEGA: &[u8] = b"omega";
static DATA_STRINGS: [&[u8]; 2] = [DATA_ALPHA, DATA_OMEGA];

pub static mut GLOBAL_TUPLE: (i32, bool) = (1, true);
pub static mut GLOBAL_PAIR: Pair = Pair(2, 3);
pub static GLOBAL_PAIRS: [Pair; 2] = [Pair(5, 8), Pair(13, 21)];
pub static mut GLOBAL_UNION: NumberUnion = NumberUnion { int_value: 10 };
pub static mut GLOBAL_SLICE: &'static [u8] = DATA_ALPHA;
pub static mut GLOBAL_NICHE: Option<NonZeroU32> = NonZeroU32::new(7);
pub static mut GLOBAL_PHANTOM: PhantomWrapper<&'static str> = PhantomWrapper {
    value: 0,
    _marker: PhantomData,
};
pub static mut GLOBAL_DYN: DynHolder<'static> = DynHolder { greet: None };
pub static mut GLOBAL_PINNED: PinnedCounter = PinnedCounter::new(0);
pub static mut GLOBAL_ENUM: GlobalState = GlobalState::Idle;
/// Mirror of GLOBAL_ENUM, kept as plain i32 so tests can assert DWARF global resolution
/// without relying on enum pretty printing.
pub static mut GLOBAL_ENUM_BITS: i32 = 0;

pub mod math {
    #[inline(never)]
    pub fn do_stuff(x: i32) -> i32 {
        // Simple function for DWARF function indexing
        x + 1
    }

    #[inline(never)]
    pub fn observe_boxed_str(value: Box<str>, empty: Box<str>) -> usize {
        value.len() + empty.len()
    }

    #[inline(never)]
    pub fn observe_os_string(
        value: std::ffi::OsString,
        invalid: std::ffi::OsString,
        empty: std::ffi::OsString,
    ) -> usize {
        value.len() + invalid.len() + empty.len()
    }
}

fn touch_globals() -> i32 {
    // SAFETY: This single-threaded fixture mutates its own static test globals to
    // keep DWARF global-variable scenarios observable.
    unsafe {
        G_COUNTER = G_COUNTER.wrapping_add(1);
        CONFIG.a = CONFIG.a.wrapping_add(1);

        GLOBAL_TUPLE.0 = GLOBAL_TUPLE.0.wrapping_add(1);
        GLOBAL_TUPLE.1 = !GLOBAL_TUPLE.1;

        GLOBAL_PAIR.0 = GLOBAL_PAIR.0.wrapping_add(GLOBAL_PAIR.1);
        GLOBAL_PAIR.1 = GLOBAL_PAIR.0.wrapping_sub(GLOBAL_PAIR.1);

        let mut union_value = GLOBAL_UNION.int_value.wrapping_add(1);
        GLOBAL_UNION.int_value = union_value;
        if union_value % 5 == 0 {
            // Flip to float representation occasionally to keep DWARF union data interesting.
            union_value = union_value.wrapping_add(1);
            GLOBAL_UNION.float_value = union_value as f32 * 1.5;
        }

        let current_slice = GLOBAL_SLICE;
        GLOBAL_SLICE = if current_slice.as_ptr() == DATA_STRINGS[0].as_ptr() {
            DATA_STRINGS[1]
        } else {
            DATA_STRINGS[0]
        };

        let nonzero_seed = GLOBAL_PAIR.0.unsigned_abs().max(1);
        GLOBAL_NICHE = NonZeroU32::new(nonzero_seed);
        GLOBAL_PHANTOM.value = GLOBAL_PHANTOM.value.wrapping_add(1);
        GLOBAL_DYN.toggle();
        let pinned_value = GLOBAL_PINNED.bump();

        let enum_snapshot = GLOBAL_ENUM;
        let next_state = match enum_snapshot {
            GlobalState::Idle => GlobalState::Counter(G_COUNTER),
            GlobalState::Counter(val) if val % 2 == 0 => GlobalState::Slice(GLOBAL_SLICE),
            GlobalState::Counter(_) => GlobalState::TupleState {
                left: GLOBAL_TUPLE.0,
                right: GLOBAL_TUPLE.1,
            },
            GlobalState::Slice(_) => GlobalState::Idle,
            GlobalState::TupleState { .. } => GlobalState::Counter(GLOBAL_PAIR.0),
        };
        GLOBAL_ENUM = next_state;
        let enum_contrib = match enum_snapshot {
            GlobalState::Idle => 0,
            GlobalState::Counter(val) => val,
            GlobalState::Slice(slice) => slice.len() as i32,
            GlobalState::TupleState { left, right } => left + if right { 1 } else { 0 },
        };
        GLOBAL_ENUM_BITS = enum_contrib;

        let total = CONFIG.a as i64
            + G_MESSAGE.len() as i64
            + G_EMPTY_MESSAGE.len() as i64
            + G_NUL_MESSAGE.len() as i64
            + G_OWNED_MESSAGE.len() as i64
            + G_EMPTY_OWNED.len() as i64
            + G_NUL_OWNED.len() as i64
            + G_SEPARATOR_OWNED.len() as i64
            + G_USER_STRING.vec.len() as i64
            + G_USER_STRING.marker as i64
            + G_VEC_U8.len() as i64
            + G_VEC_I32.len() as i64
            + G_EMPTY_VEC.len() as i64
            + G_VEC_UNIT.len() as i64
            + G_SLICE_I32.len() as i64
            + G_MUT_SLICE_U16.len() as i64
            + G_EMPTY_SLICE.len() as i64
            + G_USER_VEC.len as i64
            + GLOBAL_PAIRS[0].0 as i64
            + union_value as i64
            + pinned_value as i64
            + GLOBAL_PHANTOM.value as i64
            + enum_contrib as i64;

        total as i32
    }
}

fn main() {
    // SAFETY: The fixture initializes these globals before its tracing loop and
    // does not mutate them afterward.
    unsafe {
        G_OWNED_MESSAGE = String::from("owned from rust");
        G_NUL_OWNED = String::from("owned\0value");
        G_SEPARATOR_OWNED = String::from("left = right");
        G_USER_STRING.vec = b"user bytes".to_vec();
        G_VEC_U8 = vec![1, 2, 3, 255];
        G_VEC_I32 = vec![10, -20, 30, 40];
        G_VEC_UNIT = vec![(); 3];
        G_SLICE_I32 = Box::leak(vec![7, -8, 9].into_boxed_slice());
        G_MUT_SLICE_U16 = Box::leak(vec![1000, 2000, 65535].into_boxed_slice());
    }

    let mut acc: i64 = 0;
    for _ in 0..50000 {
        acc += math::do_stuff(3) as i64;
        acc += math::observe_boxed_str("boxed from rust".into(), "".into()) as i64;
        acc += math::observe_os_string(
            OsString::from("os from rust"),
            OsString::from_vec(vec![b'o', b's', 0xff, b'x']),
            OsString::new(),
        ) as i64;
        acc += touch_globals() as i64;
        thread::sleep(Duration::from_millis(1000));
    }
    // Prevent optimization from dropping acc
    if acc == 0x7fff_ffff { println!("dead"); }
}
