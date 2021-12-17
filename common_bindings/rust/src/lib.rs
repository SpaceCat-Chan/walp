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
        pub fn read_line() -> SSI;
    }
}

#[cfg(not(target_family = "wasm"))]
mod impls;

/// prints a string to the console, does not append a newline
pub fn print(string: &str) {
    unsafe {
        raw::print(string.as_ptr(), string.len());
    }
}

/// returns a random number in the range 0..1
pub fn math_random() -> f64 {
    unsafe { raw::math_random() }
}

/// converts a string to a f64, returns 0 on error
pub fn tonumber(ptr: *const u8, len: u32) -> f64 {
    unsafe { raw::tonumber(ptr, len) }
}

/// converts a f64 to a string
pub fn tostring(num: f64) -> Result<String, std::string::FromUtf8Error> {
    tostring_ssi(num).as_string()
}

/// converts a f64 to a string and returns the raw SSI
pub fn tostring_ssi(num: f64) -> SSI {
    unsafe { SSI::from_index(raw::tostring(num)) }
}

/// prints a formatarg using the print function
pub fn print_fmt(args: std::fmt::Arguments) {
    print(&std::fmt::format(args))
}

/// reads a line from console
pub fn read_line() -> Result<String, std::string::FromUtf8Error> {
    read_line_ssi().as_string()
}

/// reads a line to an SSI
pub fn read_line_ssi() -> SSI {
    return unsafe { SSI::from_index(raw::read_line()) };
}

/// print! macro using the print function
#[macro_export]
macro_rules! walp_print {
    ($($arg:tt)*) => ($crate::print_fmt(format_args!($($arg)*)));
}

/// println! macro using the print function
#[macro_export]
macro_rules! walp_println {
    () => ($crate::walp_print!("\n"));
    ($($arg:tt)*) => ($crate::walp_print!("{}\n", format_args!($($arg)*)));
}

/// a container that holds a raw SSI string and ensures it's validity
pub struct SSI {
    index: u32,
}

impl SSI {
    /// creates an SSI object from a raw SSI
    /// # Safety
    /// passing an invalid SSI can cause all available memory to be consumed
    pub unsafe fn from_index(index: u32) -> SSI {
        SSI { index }
    }

    pub fn get_index(&self) -> u32 {
        self.index
    }

    /// creates an SSI object from a string
    pub fn from_string(s: &str) -> SSI {
        Self {
            index: unsafe { raw::store_string(s.as_ptr(), s.len()) },
        }
    }

    /// gets the length of the SSI object
    pub fn len(&self) -> usize {
        unsafe { raw::get_string_len(self.index) }
    }

    /// converts the SSI into a Vec of bytes
    pub fn as_vec(&self) -> Vec<u8> {
        let len = unsafe { raw::get_string_len(self.index) };

        let mut vec = Vec::with_capacity(len);
        unsafe { raw::write_string_to_ptr(self.index, vec.as_mut_ptr(), len) };
        unsafe { vec.set_len(len) };
        vec
    }

    /// converts the SSI into a string
    pub fn as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.as_vec())
    }

    /// deletes the SSI
    pub fn delete(self) {
        unsafe { raw::delete_string(self.index) }
    }

    /// prints the SSI to the console
    pub fn print(&self) {
        unsafe { raw::print_ssi(self.index) }
    }
}

impl Drop for SSI {
    fn drop(&mut self) {
        unsafe { raw::delete_string(self.index) }
    }
}
