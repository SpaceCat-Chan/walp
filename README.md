# WALP
walp is a lua program that parses and inteprets WASM  
currently, if you load multiple WASM files, they will have no way to interact other than the ones you provide through imports and exports

currently, not all instructions are implemented, but it is gauranteed that all examples will run successfully


# Examples

## Game of Life (game_of_life)
this program simulates 100 iterations of the game of life on a random 16x16 looping board


# Bindings
the `common_bindings` folder contains some files that have some common functions which are usefull in most programs

current languages:
 - lua (making the versions of the functions for loading the WASM)

languages todo:
 - rust
 - c++

## functions

all types used below are in WASM/Rust syntax, so the only ones that exist are  
 - i32
 - i64
 - f32
 - f64
 - bool



`print(ptr: i32, len: i32)`  
takes a pointer and a length, and prints the string pointed to.

&nbsp;  
`random() -> f32/f64`  
return a random number in the range \[0,1)

&nbsp;  
`tostring(num: i32/f32/f64) -> i32`  
tostring takes a number and returns a special index, which can be used to retrive the string result.

&nbsp;  
`tonumber(ptr: i32, len: i32) -> f32/f64`  
tonumber takes a ptr to the start of the string and the length of the string.  
if the string can not be converted to a number, it returns 0.

&nbsp;  
`get_string_len(string: i32) -> i32`  
takes a special string index, and returns how long the string is in bytes, excluding null termination.  
if the string does not exist 0xFFFFFFFF is returned (if you are using signed numbers, that would be -1).

&nbsp;  
`write_string_to_ptr(string: i32, ptr: i32, len: 32) -> bool`  
takes a special string index, a pointer, and a length. then attempts to write the string to the pointer.  
this function will not write more than the string length or the given length.  
no null termination is written.  
if the string doesn't exist, nothing is written and false is returned.  
true is returned on success.

&nbsp;  
`delete_string(string: i32)`   
possibly deletes a special string index, thus freeing memory.  
the string may not be deleted, as this is an optimization hint.
