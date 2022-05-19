local require_path = (...):match("(.-)[^%.]+$")

local parsers = require(require_path .. "parser")
local preprocessor = require(require_path .. "preprocessor")

local function preprocess(parsed_result)
    preprocessor.module(parsed_result)
end

local debug_info_module

local parse

local bindings = require("walp.common_bindings.lua_impl")

local instantiate = require(require_path .. "instantiate")

local eval = require(require_path .. "eval")

local function load_debug_parser()
    local module = parse(WALP_DEBUG_PARSE_MODULE_FILEPATH or "debug_parser/target/wasm32-unknown-unknown/release/debug_parser.wasm")
    module.IMPORTS = {}
    local interface = bindings(module)
    local parsed_modules = {}
    module.IMPORTS.env.get_module_section = function(module_id, section_name)
        local name = interface.load_ssi_string(section_name)
        print("walp debug parser: loading section \"" .. name .. "\" for module " .. tostring(module_id))
        local found
        for _, section in pairs(parsed_modules[module_id].custom_sections) do
            if section[1] == name then
                found = section[2]
            end
        end
        if found == nil then
            return 0xFFFFFFFF
        end
        return interface.create_ssi_vec(found)
    end
    module.IMPORTS.env.passthrough = function(x) return x end
    module.add_module = function(module_id, module)
        parsed_modules[module_id] = module
    end
    module.get_function_name = function(module_id, address)
        local ssi = module.EXPORTS.get_function_name.call(module_id, address)
        if ssi == 0xFFFFFFFF then return nil end
        return interface.load_ssi_string(ssi)
    end
    instantiate(module)
    eval.set_debug_module(module)
    return module
end

parse = function(filename, parse_debug_info)
    local file, err = io.open(filename, "rb")
    if file == nil then
        return nil, err
    end
    local string = file:read("*a")
    local parsed = parsers.module(function(i) return string.byte(string, i) end, 1)
    if parsed == nil then return nil end
    preprocess(parsed[3])
    if parse_debug_info then
        debug_info_module = debug_info_module or load_debug_parser()
        if debug_info_module then
            parsed[3].debug_info = debug_info_module.EXPORTS.ready_new_module.call()
            debug_info_module.add_module(parsed[3].debug_info, parsed[3])
            print("b")
            local parse_result = debug_info_module.EXPORTS.parse_module.call(parsed[3].debug_info)
            print("a")
            if parse_result == 0 then
                print("walp error: failed to load debug info for module")
            end
        else
            print("walp error: failed to load debug parser")
        end
    end
    return parsed[3]
end

return {
    parse = parse,
    instantiate = instantiate,
}
