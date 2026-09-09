pub mod string {
    pub struct String {
        pub raw: u64,
    }
}
#[used]
#[no_mangle]
pub static G_REJECTED_STRING: string::String = string::String { raw: 42 };
#[inline(never)]
#[no_mangle]
pub extern "C" fn observe_adapter_rejection() -> usize {
    std::hint::black_box(&G_REJECTED_STRING as *const _ as usize)
}
fn main() {
    loop {
        // Fault in the root objects before the probe. Merely taking their
        // addresses leaves untouched read-only pages unavailable to a normal
        // uprobe. These structs own no allocations; the raw pointers are
        // copied here, never dereferenced by the target.
        unsafe {
            std::hint::black_box(std::ptr::read_volatile(&G_REJECTED_STRING));
            std::hint::black_box(std::ptr::read_volatile(&G_PLAIN));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_UNREADABLE)));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_MIXED)));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(G_NULL)));
            std::hint::black_box(std::ptr::read_volatile(std::ptr::addr_of!(
                G_NO_ELEMENT_TYPE
            )));
        }
        std::hint::black_box(observe_adapter_rejection());
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[repr(C)]
pub struct Leaf {
    pub number: u64,
}
#[repr(C)]
pub struct Middle {
    pub leaf: Leaf,
}
#[repr(C)]
pub struct Plain {
    pub middle: Middle,
}
#[used]
#[no_mangle]
pub static G_PLAIN: Plain = Plain {
    middle: Middle {
        leaf: Leaf { number: 99 },
    },
};

// These are ordinary fixture structs, not invalid instances of std types.
// Their qualified identities and fields deliberately exercise adapter paths.
pub mod ffi {
    pub mod c_str {
        #[repr(C)]
        pub struct Bytes {
            pub data_ptr: *const u8,
            pub length: usize,
        }
        #[repr(C)]
        pub struct CString {
            pub inner: Bytes,
        }
    }
}
#[used]
#[no_mangle]
pub static mut G_UNREADABLE: ffi::c_str::CString = ffi::c_str::CString {
    inner: ffi::c_str::Bytes {
        data_ptr: 1 as *const u8,
        length: 9,
    },
};
#[used]
#[no_mangle]
pub static mut G_NULL: *const u64 = std::ptr::null();
#[repr(C)]
pub struct Mixed {
    pub good: u64,
    pub bad: ffi::c_str::CString,
}
#[used]
#[no_mangle]
pub static mut G_MIXED: Mixed = Mixed {
    good: 73,
    bad: ffi::c_str::CString {
        inner: ffi::c_str::Bytes {
            data_ptr: 1 as *const u8,
            length: 9,
        },
    },
};

pub mod vec {
    #[repr(C)]
    pub struct Pointer {
        pub pointer: *const u8,
    }
    #[repr(C)]
    pub struct Buffer {
        pub ptr: Pointer,
    }
    // Layout validation succeeds, but a const parameter cannot supply Vec's
    // required DW_TAG_template_type_parameter. No real Vec is corrupted.
    #[repr(C)]
    pub struct Vec<const N: usize> {
        pub buf: Buffer,
        pub len: usize,
    }
}
#[used]
#[no_mangle]
pub static mut G_NO_ELEMENT_TYPE: vec::Vec<3> = vec::Vec {
    buf: vec::Buffer {
        ptr: vec::Pointer {
            pointer: std::ptr::null(),
        },
    },
    len: 7,
};
