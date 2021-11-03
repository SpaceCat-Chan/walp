-- simulate that we are outside the walp folder
-- i certainly hope the walp folder is named "walp"
package.path = "../../../?.lua;"..package.path

--[[
    this program runs 100 iterations of The Game of Life on a 16x16 looping grid
]]

local walp = require("walp.main")

local module = walp.parse("test.wasm")

-- .debug_info section is big, remove it before instantiation
module.custom_sections = {}

local memory = module.EXPORTS.memory

math.randomseed(os.time())

module.IMPORTS = {
    env = {
        i_print = function(str_ptr, str_len)
            for x=str_ptr, str_ptr+str_len-1 do
                io.write(string.char(memory.read8(x)))
            end
        end,
        i_random = math.random,
        print_u64 = function(n)
            print(n.l, n.h, n.l + n.h * 0x100000000)
        end,
        passthrough = function(x) return x end,
        i_take_a_break = function()
            -- do nothing on 5.2, coroutine.yield on CC
            if _G._HOST then
                coroutine.yield()
            end
        end
    }
}

walp.instantiate(module)

module.EXPORTS.main.call()
