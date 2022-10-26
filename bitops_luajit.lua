local bit = require("bit")


local function inv_signed(N, i)
    if i < 0 then
        return i + math.pow(2, N)
    end
    return i
end

return {
    band = function(a, b) return inv_signed(32, bit.band(a, b)) end,
    bor = function(a, b) return inv_signed(32, bit.bor(a, b)) end,
    bnot = function(a) return inv_signed(32, bit.bnot(a)) end,
    bxor = function(a, b) return inv_signed(32, bit.bxor(a, b)) end,
    lshift = function(a, b) return inv_signed(32, bit.lshift(a, b)) end,
    rshift = function(a, b) return inv_signed(32, bit.rshift(a, b)) end,
    arshift = function(a, b) return inv_signed(32, bit.arshift(a, b)) end,
    lrotate = function(a, b) return inv_signed(32, bit.rol(a, b)) end,
}
