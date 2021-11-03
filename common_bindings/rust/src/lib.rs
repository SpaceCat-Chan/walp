pub mod raw {
    type SSI = u32;
    extern "C" {
        pub fn print(ptr: *const u8, len: usize);
        pub fn math_random() -> f64;
        pub fn tonumber(ptr: *const u8, len: u32) -> f64;
        pub fn tostring(num: f64) -> SSI;
        pub fn get_string_len(string: SSI) -> usize;
        pub fn write_string_to_ptr(string: SSI, ptr: *mut u8, len: usize) -> bool;
        pub fn delete_string(string: SSI);
        pub fn store_string(ptr: *const u8, len: usize) -> SSI;
        pub fn print_ssi(string: SSI);
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
    tostring_ssi(num).as_string()
}

pub fn tostring_ssi(num: f64) -> SSI {
    unsafe { SSI::from_index(raw::tostring(num)) }
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

pub struct SSI {
    index: u32,
}

impl SSI {
    pub unsafe fn from_index(index: u32) -> SSI {
        SSI { index }
    }

    pub fn from_string(s: &str) -> SSI {
        Self {
            index: unsafe { raw::store_string(s.as_ptr(), s.len()) },
        }
    }

    pub fn len(&self) -> usize {
        unsafe { raw::get_string_len(self.index) }
    }

    pub fn as_vec(&self) -> Vec<u8> {
        let len = unsafe { raw::get_string_len(self.index) };

        let mut vec = Vec::with_capacity(len);
        unsafe { raw::write_string_to_ptr(self.index, vec.as_mut_ptr(), len) };
        vec
    }

    pub fn as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.as_vec())
    }

    pub fn delete(self) {
        unsafe { raw::delete_string(self.index) }
    }

    pub fn print(&self) {
        unsafe { raw::print_ssi(self.index) }
    }
}

impl Drop for SSI {
    fn drop(&mut self) {
        unsafe { raw::delete_string(self.index) }
    }
}
