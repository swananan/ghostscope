#![allow(non_upper_case_globals)]
#![allow(static_mut_refs)]

use std::{
    marker::{PhantomData, PhantomPinned},
    num::NonZeroU32,
    thread,
    time::Duration,
};

pub static mut G_COUNTER: i32 = 0;
pub static G_MESSAGE: &str = "hello from rust";

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
}

fn touch_globals() -> i32 {
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
            + union_value as i64
            + pinned_value as i64
            + GLOBAL_PHANTOM.value as i64
            + enum_contrib as i64;

        total as i32
    }
}

fn main() {
    let mut acc: i64 = 0;
    for _ in 0..50000 {
        acc += math::do_stuff(3) as i64;
        acc += touch_globals() as i64;
        thread::sleep(Duration::from_millis(1000));
    }
    // Prevent optimization from dropping acc
    if acc == 0x7fff_ffff { println!("dead"); }
}
