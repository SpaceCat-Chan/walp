local require_path = (...):match("(.-)[^%.]+$")

local bit_attempt = pcall(require, "bit")

local bit

if bit32 then
    bit = require(require_path .. 'bitops_bit32')
elseif bit_attempt then
    bit = require(require_path .. 'bitops_luajit')

    local ffi = require("ffi")
    function bit.to_u64(l, h)
        return ffi.cast("uint64_t", l) + bit.lshift(ffi.cast("uint64_t", h), 32)
    end

    function bit.u64_to_i64(n)
        return ffi.cast("int64_t", n)
    end

    function bit.i64_to_u64(n)
        return ffi.cast("uint64_t", n)
    end

    function bit.u32_to_u64(n)
        return ffi.cast("uint64_t", n)
    end

    function bit.i32_to_u64(n)
        return ffi.cast("uint64_t", ffi.cast("int64_t", bit.signed(32, n)))
    end

    function bit.i16_to_u64(n)
        return ffi.cast("uint64_t", ffi.cast("int64_t", bit.signed(16, n)))
    end

    function bit.i8_to_u64(n)
        return ffi.cast("uint64_t", ffi.cast("int64_t", bit.signed(8, n)))
    end
else
    bit = require(require_path .. 'bitops_rawops')
end


function bit.signed(N, i)
    if i > math.pow(2, N - 1) then
        return i - math.pow(2, N)
    end
    return i
end

function bit.signed_32(i)
    return bit.signed(32, i)
end

function bit.inv_signed(N, i)
    if i < 0 then
        return i + math.pow(2, N)
    end
    return i
end

function bit.extend(M, N, i)
    return bit.inv_signed(N, bit.signed(M, i))
end

function bit.extend_8_to_32(i)
    return bit.extend(8, 32, i)
end

function bit.extend_16_to_32(i)
    return bit.extend(16, 32, i)
end

function bit.extend_8_to_64(i)
    local res = bit.extend(8, 32, i)
    return { [0] = res, [1] = bit.arshift(bit.band(res, 0x80000000), 31) }
end

function bit.extend_16_to_64(i)
    local res = bit.extend(16, 32, i)
    return { [0] = res, [1] = bit.arshift(bit.band(res, 0x80000000), 31) }
end

function bit.extend_32_to_64(i)
    return { [0] = i, [1] = bit.arshift(bit.band(i, 0x80000000), 31) }
end

function bit.make_u64(i)
    return { [0] = i, [1] = 0 }
end

function bit.trunc(i)
    if i >= 0 then
        return math.floor(i)
    else
        return math.ceil(i)
    end
end

local __clz_tab = { 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 }
__clz_tab[0] = 4

function bit.clz(x)
    local n = 0
    if bit.band(x, -65536) == 0 then n = 16;
        x = bit.lshift(x, 16)
    end
    if bit.band(x, -16777216) == 0 then n = n + 8;
        x = bit.lshift(x, 8)
    end
    if bit.band(x, -268435456) == 0 then n = n + 4;
        x = bit.lshift(x, 4)
    end
    n = n + __clz_tab[bit.rshift(x, 28)]
    return n
end

local __ctz_tab = {}

for i = 0, 31 do
    __ctz_tab[bit.rshift(125613361 * bit.lshift(1, i), 27)] = i
end

function bit.ctz(x)
    if x == 0 then return 32 end
    return __ctz_tab[bit.rshift(bit.band(x, -x) * 125613361, 27)]
end

local bit_band   = bit.band
local bit_lshift = bit.lshift
local bit_rshift = bit.rshift
local math_floor = math.floor
local math_frexp = math.frexp
local math_ldexp = math.ldexp
local math_huge  = math.huge

-- Integers
function bit.UInt8ToUInt8s(n)
    return n
end

function bit.UInt16ToUInt8s(n)
    return n % 256,
        math_floor(n / 256) % 256
end

function bit.UInt32ToUInt8s(n)
    return n % 256,
        math_floor(n / 256) % 256,
        math_floor(n / 65536) % 256,
        math_floor(n / 16777216) % 256
end

function bit.UInt64ToUInt8s(n)
    return n % 256,
        math_floor(n / 256) % 256,
        math_floor(n / 65536) % 256,
        math_floor(n / 16777216) % 256,
        math_floor(n / 4294967296) % 256,
        math_floor(n / 1099511627776) % 256,
        math_floor(n / 281474976710656) % 256,
        math_floor(n / 72057594037927936) % 256
end

function bit.UInt8sToUInt8(uint80)
    return uint80
end

function bit.UInt8sToUInt16(uint80, uint81)
    return uint80 +
        uint81 * 256
end

function bit.UInt8sToUInt32(uint80, uint81, uint82, uint83)
    return uint80 +
        uint81 * 256 +
        uint82 * 65536 +
        uint83 * 16777216
end

function bit.UInt8sToUInt64(uint80, uint81, uint82, uint83, uint84, uint85, uint86, uint87)
    return uint80 +
        uint81 * 256 +
        uint82 * 65536 +
        uint83 * 16777216 +
        uint84 * 4294967296 +
        uint85 * 1099511627776 +
        uint86 * 281474976710656 +
        uint87 * 72057594037927936
end

function bit.Int8ToUInt8s(n)
    if n < 0 then n = n + 256 end
    return bit.UInt8ToUInt8s(n)
end

function bit.Int16ToUInt8s(n)
    if n < 0 then n = n + 65536 end
    return bit.UInt16ToUInt8s(n)
end

function bit.Int32ToUInt8s(n)
    if n < 0 then n = n + 4294967296 end
    return bit.UInt32ToUInt8s(n)
end

function bit.Int64ToUInt8s(n)
    local uint80, uint81, uint82, uint83 = bit.UInt32ToUInt8s(n % 4294967296)
    local uint84, uint85, uint86, uint87 = bit.Int32ToUInt8s(math_floor(n / 4294967296))
    return uint80, uint81, uint82, uint83, uint84, uint85, uint86, uint87
end

function bit.UInt8sToInt8(uint80)
    local n = bit.UInt8sToUInt8(uint80)
    if n >= 128 then n = n - 256 end
    return n
end

function bit.UInt8sToInt16(uint80, uint81)
    local n = bit.UInt8sToUInt16(uint80, uint81)
    if n >= 32768 then n = n - 65536 end
    return n
end

function bit.UInt8sToInt32(uint80, uint81, uint82, uint83)
    local n = bit.UInt8sToUInt32(uint80, uint81, uint82, uint83)
    if n >= 2147483648 then n = n - 4294967296 end
    return n
end

function bit.UInt8sToInt64(uint80, uint81, uint82, uint83, uint84, uint85, uint86, uint87)
    local low  = bit.UInt8sToUInt32(uint80, uint81, uint82, uint83)
    local high = bit.UInt8sToInt32(uint84, uint85, uint86, uint87)
    return low + high * 4294967296
end

-- IEEE floating point numbers
function bit.FloatToUInt32(f)
    -- 1 / f is needed to check for -0
    local n = 0
    if f < 0 or 1 / f < 0 then
        n = n + 0x80000000
        f = -f
    end

    local mantissa = 0
    local biasedExponent = 0

    if f == math_huge then
        biasedExponent = 0xFF
    elseif f ~= f then
        biasedExponent = 0xFF
        mantissa = 1
    elseif f == 0 then
        biasedExponent = 0x00
    else
        mantissa, biasedExponent = math_frexp(f)
        biasedExponent = biasedExponent + 126

        if biasedExponent <= 0 then
            -- Denormal
            mantissa = math_floor(mantissa * 2 ^ (23 + biasedExponent) + 0.5)
            biasedExponent = 0
        else
            mantissa = math_floor((mantissa * 2 - 1) * 2 ^ 23 + 0.5)
        end
    end

    n = n + bit_lshift(bit_band(biasedExponent, 0xFF), 23)
    n = n + bit_band(mantissa, 0x007FFFFF)

    return n
end

function bit.DoubleToUInt32s(f)
    -- 1 / f is needed to check for -0
    local high = 0
    local low  = 0
    if f < 0 or 1 / f < 0 then
        high = high + 0x80000000
        f = -f
    end

    local mantissa = 0
    local biasedExponent = 0

    if f == math_huge then
        biasedExponent = 0x07FF
    elseif f ~= f then
        biasedExponent = 0x07FF
        mantissa = 1
    elseif f == 0 then
        biasedExponent = 0x00
    else
        mantissa, biasedExponent = math_frexp(f)
        biasedExponent = biasedExponent + 1022

        if biasedExponent <= 0 then
            -- Denormal
            mantissa = math_floor(mantissa * 2 ^ (52 + biasedExponent) + 0.5)
            biasedExponent = 0
        else
            mantissa = math_floor((mantissa * 2 - 1) * 2 ^ 52 + 0.5)
        end
    end

    low = mantissa % 4294967296
    high = high + bit_lshift(bit_band(biasedExponent, 0x07FF), 20)
    high = high + bit_band(math_floor(mantissa / 4294967296), 0x000FFFFF)

    return low, high
end

function bit.UInt32ToFloat(n)
    -- 1 sign bit
    -- 8 biased exponent bits (bias of 127, biased value of 0 if 0 or denormal)
    -- 23 mantissa bits (implicit 1, unless biased exponent is 0)

    local negative = false

    if n >= 0x80000000 then
        negative = true
        n = n - 0x80000000
    end

    local biasedExponent = bit_rshift(bit_band(n, 0x7F800000), 23)
    local mantissa = bit_band(n, 0x007FFFFF) / (2 ^ 23)

    local f
    if biasedExponent == 0x00 then
        f = mantissa == 0 and 0 or math_ldexp(mantissa, -126)
    elseif biasedExponent == 0xFF then
        f = mantissa == 0 and math_huge or (math_huge - math_huge)
    else
        f = math_ldexp(1 + mantissa, biasedExponent - 127)
    end

    return negative and -f or f
end

function bit.UInt32sToDouble(low, high)
    -- 1 sign bit
    -- 11 biased exponent bits (bias of 127, biased value of 0 if 0 or denormal)
    -- 52 mantissa bits (implicit 1, unless biased exponent is 0)

    local negative = false

    if high >= 0x80000000 then
        negative = true
        high = high - 0x80000000
    end

    local biasedExponent = bit_rshift(bit_band(high, 0x7FF00000), 20)
    local mantissa = (bit_band(high, 0x000FFFFF) * 4294967296 + low) / 2 ^ 52

    local f
    if biasedExponent == 0x0000 then
        f = mantissa == 0 and 0 or math_ldexp(mantissa, -1022)
    elseif biasedExponent == 0x07FF then
        f = mantissa == 0 and math_huge or (math_huge - math_huge)
    else
        f = math_ldexp(1 + mantissa, biasedExponent - 1023)
    end

    return negative and -f or f
end

return bit
