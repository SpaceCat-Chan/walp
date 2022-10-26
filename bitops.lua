local require_path = (...):match("(.-)[^%.]+$")

local bit_attempt = require("bit")

if bit32 then
    return require(require_path .. 'bitops_bit32')
elseif bit_attempt then
    return require(require_path .. 'bitops_luajit')
else
    return require(require_path .. 'bitops_rawops')
end
