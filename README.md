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
