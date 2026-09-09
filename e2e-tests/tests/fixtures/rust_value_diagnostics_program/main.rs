#![allow(static_mut_refs)]

use std::cell::Cell;

pub struct Node {
    pub label: String,
    pub children: Vec<Node>,
}

pub enum Branch {
    Empty,
    Limited(Cell<String>),
}

pub struct Outer {
    pub middle: Middle,
}
pub struct Middle {
    pub leaf: Leaf,
}
pub struct Leaf {
    pub value: Cell<u64>,
}
#[used]
#[no_mangle]
pub static mut G_WRAPPED: Outer = Outer {
    middle: Middle {
        leaf: Leaf {
            value: Cell::new(91),
        },
    },
};
#[used]
#[no_mangle]
pub static mut G_NULL_WRAPPED: *const Outer = std::ptr::null();
#[used]
#[no_mangle]
pub static mut G_BAD_WRAPPED: *const Outer = 1 as *const Outer;
#[used]
#[no_mangle]
pub static mut G_GOOD_WRAPPED: *const Outer = std::ptr::addr_of!(G_WRAPPED);

#[used]
#[no_mangle]
pub static G_TEXT: &str = "alphabet";
#[used]
#[no_mangle]
pub static G_EMPTY: &str = "";
#[used]
#[no_mangle]
pub static mut G_ITEMS: Vec<String> = Vec::new();
#[used]
#[no_mangle]
pub static mut G_NESTED: Vec<Vec<String>> = Vec::new();
#[used]
#[no_mangle]
pub static mut G_CELL: Cell<String> = Cell::new(String::new());
#[used]
#[no_mangle]
pub static mut G_INACTIVE: Branch = Branch::Empty;
#[used]
#[no_mangle]
pub static mut G_TREE: Node = Node {
    label: String::new(),
    children: Vec::new(),
};

#[inline(never)]
#[no_mangle]
pub extern "C" fn observe_diagnostics() {
    // The target initializes its values before the first probe hit and never
    // mutates them afterward. Recursive types form a finite, acyclic tree.
    std::hint::black_box(std::ptr::addr_of!(G_TREE));
}

fn main() {
    unsafe {
        G_ITEMS = vec!["alpha".into(), "beta".into(), "omega".into()];
        G_NESTED = vec![vec!["deep alpha".into()], vec!["deep beta".into()]];
        G_CELL = Cell::new("cell value".into());
        G_TREE = Node {
            label: "root".into(),
            children: vec![Node {
                label: "leaf".into(),
                children: Vec::new(),
            }],
        };
    }
    loop {
        unsafe {
            std::hint::black_box(G_WRAPPED.middle.leaf.value.get());
            // Fault in the pointer objects without dereferencing their values.
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_NULL_WRAPPED)));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_BAD_WRAPPED)));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_GOOD_WRAPPED)));
        }
        // Initialize mappings for the static string metadata and contents;
        // non-sleepable probes cannot fault in untouched read-only pages.
        for text in unsafe {
            [
                std::ptr::read_volatile(&G_TEXT),
                std::ptr::read_volatile(&G_EMPTY),
            ]
        } {
            for byte in text.as_bytes() {
                std::hint::black_box(unsafe { std::ptr::read_volatile(byte) });
            }
        }
        observe_diagnostics();
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
