local require_path = (...):match("(.-)[^%.]+$")

local parsers = require(require_path.."parser")
local preprocessor = require(require_path.."preprocessor")

local function preprocess(parsed_result)
    preprocessor.module(parsed_result)
end

local function parse(filename)
    local file, err = io.open(filename, "rb")
    if file == nil then
        return nil, err
    end
    local string = file:read("*a")
    local parsed = parsers.module(function(i) return string.byte(string, i) end, 1)
    if parsed == nil then return nil end
    preprocess(parsed[3])
    return parsed[3]
end

local instantiate = require(require_path.."instantiate")

return {
    parse = parse,
    instantiate = instantiate,
}