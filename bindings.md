# Bindings
the `common_bindings` folder contains some files that have some common functions which are usefull in most programs

## languages

current languages:
 - lua (making the versions of the functions for loading the WASM)
 - rust
 - c++

languages todo:
 - currently none

## importing on the lua side
all you have to do is require or somehow load the `lua_impl.lua` file,  
and then use the returned function before instantiation, which has the below decleration  
```
(module, namespace, memory) => lua_interface
```
the functions takes the module, a namespace, and a memory module  
the namespace and memory module are optional  
the namespace defaults to `env` and the memory module defaults to one exported by the module named `memory`  
it also returns an interface that can be used to upload SSI strings that can then be loaded into wasm using the interface provided below, full docs are further below

## types

all types used below are in WASM/Rust syntax, so the only ones that exist are  
 - i32
 - i64
 - f32
 - f64
 - bool

note: in wasm there is no difference between signed and unsigned integer types, it is up to the individual language binding to select which is used

other than that, there are also some extra special types which mean special things  
### SSI
underlying type: `i32`  
SSI means Special String Index, each index refers to a string stored in lua memory  
this is needed because any functions that produce strings needs to know where to put the string, so instead an SSI is returned and the application can request that the string be stored at a specific address, this may in the future also allow for higher speed string manipulation

## functions
`print(ptr: i32, len: i32)`  
takes a pointer and a length, and prints the string pointed to.

&nbsp;  
`math_random() -> f32/f64`  
return a random number in the range \[0,1)

&nbsp;  
`tostring(num: i32/f32/f64) -> SSI`  
tostring converts a number to a string

&nbsp;  
`tonumber(ptr: i32, len: i32) -> f32/f64`  
tonumber takes a ptr to the start of the string and the length of the string.  
if the string can not be converted to a number, it returns 0.

&nbsp;  
`get_string_len(string: SSI) -> i32`  
returns the length of the string, or 0xFFFFFFFF if it doesn't exist (-1 in signed 32bit)

&nbsp;  
`write_string_to_ptr(string: SSI, ptr: i32, len: 32) -> bool`  
writes the string to the pointer without null termination.  
if the string doesn't exist, nothing is written and false is returned, else true is returned.

&nbsp;  
`delete_string(string: SSI)`   
possibly deletes a special string index, thus freeing memory.  
the string may not be deleted, as this is an optimization hint.

&nbsp;  
`store_string(ptr: i32, len: i32) -> SSI`  
stores a string into an SSI

&nbsp;  
`print_ssi(string: SSI)`  
prints a string stored in an SSI

&nbsp;  
`read_line() -> SSI`  
reads a line from stdin and returns it, includes the newline character

&nbsp;
## lua interface
`create_ssi_string(s: string) -> SSI`  
uploads an SSI from lua

&nbsp;  
`create_ssi_vec(s: array<u8>) -> SSI`  
uploads an SSI from lua using a raw byte vector

&nbsp;  
`load_ssi_string(s: SSI) -> string/nil`  
returns the string for the SSI if it exists

&nbsp;  
`load_ssi_vec(s: SSI) -> attay<u8>/nil`  
returns the raw byte vector for the SSI if it exists