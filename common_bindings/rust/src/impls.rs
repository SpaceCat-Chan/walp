use std::{cell::RefCell, collections::HashMap};

type SSI = u32;
#[no_mangle]
pub extern "C" fn print(ptr: *const u8, len: usize) {
    print!(
        "{}",
        unsafe {
            std::mem::ManuallyDrop::new(String::from_raw_parts(ptr as _, len as _, len as _))
        }
        .to_string()
    );
}
static mut RANDOM_STATE: u64 = 196260306832;
#[no_mangle]
pub extern "C" fn math_random() -> f64 {
    let mut x = unsafe { RANDOM_STATE };
    x ^= x >> 12; // a
    x ^= x << 25; // b
    x ^= x >> 27; // c
    unsafe { RANDOM_STATE = x };
    x.wrapping_mul(0x2545F4914F6CDD1D) as f64 / u64::MAX as f64
}
#[no_mangle]
pub extern "C" fn tonumber(ptr: *const u8, len: u32) -> f64 {
    let s = unsafe {
        std::mem::ManuallyDrop::new(String::from_raw_parts(ptr as _, len as _, len as _))
    }
    .to_string();
    s.parse().unwrap()
}
thread_local! {
    static STRING_STORE: RefCell<HashMap<u32, String>> = RefCell::new(HashMap::new());
    static NEXT_SSI: RefCell<u32>  = RefCell::new(1);
}
#[no_mangle]
pub extern "C" fn tostring(num: f64) -> SSI {
    STRING_STORE.with(|ssi| {
        NEXT_SSI.with(|ns| {
            let s = format!("{}", num);
            let mut ns = ns.borrow_mut();
            ssi.borrow_mut().insert(*ns, s);
            *ns += 1;
            *ns - 1
        })
    })
}
#[no_mangle]
pub extern "C" fn get_string_len(string: SSI) -> usize {
    STRING_STORE.with(|ssi| {
        ssi.borrow()
            .get(&string)
            .map(|s| s.len())
            .unwrap_or(0xFFFFFFFF)
    })
}
#[no_mangle]
pub extern "C" fn write_string_to_ptr(string: SSI, ptr: *mut u8, len: usize) -> bool {
    STRING_STORE.with(|ssi| {
        if let Some(s) = ssi.borrow().get(&string) {
            unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), ptr, len) };
            true
        } else {
            false
        }
    })
}
#[no_mangle]
pub extern "C" fn delete_string(string: SSI) {
    STRING_STORE.with(|ssi| ssi.borrow_mut().remove(&string));
}
#[no_mangle]
pub extern "C" fn store_string(ptr: *const u8, len: usize) -> SSI {
    STRING_STORE.with(|ssi| {
        NEXT_SSI.with(|ni| {
            let mut ni = ni.borrow_mut();
            ssi.borrow_mut().insert(*ni, unsafe {
                std::mem::ManuallyDrop::new(String::from_raw_parts(ptr as _, len, len)).to_string()
            });
            *ni += 1;
            *ni - 1
        })
    })
}
#[no_mangle]
pub extern "C" fn print_ssi(string: SSI) {
    STRING_STORE.with(|ssi| {
        ssi.borrow()
            .get(&string)
            .iter()
            .for_each(|s| print!("{}", s))
    })
}
#[no_mangle]
pub extern "C" fn i_take_a_break() {}
