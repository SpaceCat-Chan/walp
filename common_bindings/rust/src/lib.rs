pub mod raw {
    extern "C" {
        pub fn print(ptr: *const u8, len: usize);
        pub fn math_random() -> f64;
        pub fn tonumber(ptr: *const u8, len: u32) -> f64;
        pub fn tostring(num: f64) -> u32;
        pub fn get_string_len(string: u32) -> usize;
        pub fn write_string_to_ptr(string: u32, ptr: *mut u8, len: usize) -> bool;
        pub fn delete_string(string: u32);
    }
}

pub fn print(string: &str) {
    unsafe {
        raw::print(string.as_ptr(), string.len());
    }
}

pub fn math_random() -> f64 {
    unsafe { raw::math_random() }
}

pub fn tonumber(ptr: *const u8, len: u32) -> f64 {
    unsafe { raw::tonumber(ptr, len) }
}

pub fn tostring(num: f64) -> Result<String, std::string::FromUtf8Error> {
    let s = unsafe { raw::tostring(num) };
    let len = unsafe { raw::get_string_len(s) };

    let mut vec = Vec::with_capacity(len);
    unsafe { raw::write_string_to_ptr(s, vec.as_mut_ptr(), len) };

    String::from_utf8(vec)
}

pub fn print_fmt(args: std::fmt::Arguments) {
    print(&std::fmt::format(args))
}

#[macro_export]
macro_rules! walp_print {
    ($($arg:tt)*) => ($crate::print_fmt(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! walp_println {
    () => ($crate::walp_print!("\n"));
    ($($arg:tt)*) => ($crate::walp_print!("{}\n", format_args!($($arg)*)));
}
