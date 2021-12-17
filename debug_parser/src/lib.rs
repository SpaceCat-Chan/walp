use std::{cell::RefCell, collections::HashMap};

use nom::{
    bytes::complete::{tag, take},
    combinator::{complete, opt},
    multi::{length_count, length_data, many_m_n},
    sequence::tuple,
};

use walp_rs::*;

extern "C" {
    fn get_module_section(module_id: u32, section_name: u32) -> u32;
    fn passthrough(_: u8) -> u8;
}

fn get_module_section_safe(module_id: u32, section_name: &str) -> Option<SSI> {
    let name = SSI::from_string(section_name);
    let result = unsafe { get_module_section(module_id, name.get_index()) };
    if result != 0xFFFFFFFF {
        Some(unsafe { SSI::from_index(result) })
    } else {
        None
    }
}

fn my_custom_panic_hook(info: &std::panic::PanicInfo) {
    let msg = info.to_string();

    walp_println!("{}", &msg);
}

fn leb128(mut r: &[u8]) -> nom::IResult<&[u8], u32> {
    const CONTINUATION_BIT: u8 = 0b10000000;

    let mut result = 0;
    let mut shift = 0;

    loop {
        let (new_r, mut buf) = take(1usize)(r)?;
        r = new_r;

        if shift == 63 && buf[0] != 0x00 && buf[0] != 0x01 {
            while buf[0] & CONTINUATION_BIT != 0 {
                let (new_r, new_buf) = take(1usize)(r)?;
                r = new_r;
                buf = new_buf
            }
            return Err(nom::Err::Error(nom::error::Error::new(
                r,
                nom::error::ErrorKind::Digit,
            )));
        }

        let low_bits = (buf[0] & !CONTINUATION_BIT) as u32;
        result |= low_bits << shift;

        // `passthrough` does nothing, but it makes the compiler think the value is used elsewhere
        // for some reason removing it breaks things
        let res = unsafe { passthrough(buf[0] & CONTINUATION_BIT) };
        if res == 0 {
            return Ok((r, result as u32));
        }

        shift += 7;
    }
}

struct Names {
    module_name: Option<String>,
    function_names: Option<HashMap<u32, String>>,
    local_names: Option<HashMap<u32, HashMap<u32, String>>>,
}

fn name(r: &[u8]) -> nom::IResult<&[u8], String> {
    let (r, bytes) = leb128(r)?;
    let (r, bytes) = take(bytes)(r)?;
    Ok((r, String::from_utf8_lossy(bytes).into_owned()))
}

fn module_name(r: &[u8]) -> nom::IResult<&[u8], String> {
    let (r, _) = tag([0u8])(r)?;
    let (r, o_r) = length_data(leb128)(r)?;
    Ok((r, name(o_r)?.1))
}
fn function_names(r: &[u8]) -> nom::IResult<&[u8], Vec<(u32, String)>> {
    let (r, (_, _)) = tuple((tag([1u8]), leb128))(r)?;
    let (mut r, count) = leb128(r)?;
    //walp_println!("r: {:?}", r);
    let result = (0..count)
        .map(|n| {
            if n == 128 {}
            match tuple((leb128, name))(r) {
                Err(e) => Err(e),
                Ok((new_r, res)) => {
                    r = new_r;
                    Ok(res)
                }
            }
        })
        .collect::<Result<Vec<(_, _)>, _>>();
    Ok((r, result?))
}
fn local_names(r: &[u8]) -> nom::IResult<&[u8], Vec<(u32, Vec<(u32, String)>)>> {
    let (r, _) = tag([2u8])(r)?;
    let (r, o_r) = length_data(leb128)(r)?;
    Ok((
        r,
        length_count(
            leb128,
            tuple((leb128, length_count(leb128, tuple((leb128, name))))),
        )(o_r)?
        .1,
    ))
}

impl Names {
    fn parse(r: &[u8]) -> nom::IResult<&[u8], Self> {
        let (r, (module_name, function_name, local_names)) = tuple((
            opt(complete(module_name)),
            opt(complete(function_names)),
            opt(complete(local_names)),
        ))(r)?;
        Ok((
            r,
            Self {
                module_name,
                function_names: function_name.map(|v| v.into_iter().collect()),
                local_names: local_names.map(|v| {
                    v.into_iter()
                        .map(|l| (l.0, l.1.into_iter().collect()))
                        .collect()
                }),
            },
        ))
    }
}

struct Module {
    name_section: Vec<u8>,
    parsed_form: Option<Names>,
    looked_up_names: HashMap<u32, SSI>,
}

impl Module {
    fn look_up_function(&mut self, address: u32) -> Option<&SSI> {
        if self.looked_up_names.contains_key(&(address)) {
            return self.looked_up_names.get(&(address));
        }
        if self.parsed_form.is_none() {
            let parsed = Names::parse(&self.name_section[..]);
            if let Err(e) = &parsed {
                walp_println!("unable to parse name section: {:?}", e);
            }
            self.parsed_form = parsed.ok().map(|(_, a)| a)
        }
        match &self.parsed_form {
            None => None,
            Some(parsed) => {
                let name = parsed
                    .function_names
                    .as_ref()
                    .and_then(|o| o.get(&(address)))?;

                let ssi = SSI::from_string(name);
                Some(self.looked_up_names.entry(address).or_insert(ssi))
            }
        }
    }
}

static mut NEXT_ID: u32 = 0;
thread_local! {
    static MODULES: RefCell<HashMap<u32, Module>> = RefCell::new(HashMap::new());
}

#[no_mangle]
extern "C" fn ready_new_module() -> u32 {
    std::panic::set_hook(Box::new(my_custom_panic_hook));
    unsafe {
        let next = NEXT_ID;
        NEXT_ID += 1;
        next
    }
}

#[no_mangle]
extern "C" fn parse_module(module_id: u32) -> u32 {
    let name_section = get_module_section_safe(module_id, "name").map(|s| s.as_vec());
    match name_section {
        None => 0,
        Some(vec) => {
            MODULES.with(|m: _| {
                m.borrow_mut().insert(
                    module_id,
                    Module {
                        name_section: vec,
                        looked_up_names: HashMap::new(),
                        parsed_form: None,
                    },
                )
            });
            1
        }
    }
}

#[no_mangle]
extern "C" fn get_function_name(module_id: u32, address: u32) -> u32 {
    MODULES.with(|m: _| {
        let mut modules = m.borrow_mut();
        let module = modules.get_mut(&module_id);
        match module {
            None => 0xFFFFFFFF,
            Some(module) => module
                .look_up_function(address)
                .map(|s| s.get_index())
                .unwrap_or(0xFFFFFFFF),
        }
    })
}
