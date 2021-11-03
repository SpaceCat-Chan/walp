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
 - c++

languages todo:
 - rust
 - lua (making the versions of the functions for loading the WASM)

## functions

all types used below are in WASM syntax, so the only ones that exist are  
 - i32
 - i64
 - f32
 - f64

### print
`print(ptr: i32, len: i32)`
takes a pointer and a length, prints the string pointed to and prints it to the console

### random
`random() -> f32/f64`
return a random number in the range \[0,1)

### tostring
TO BE CHANGED

### tonumber
TO BE CHANGED
