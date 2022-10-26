return {
    band = function(a, b) return a & b end,
    bor = function(a, b) return a | b end,
    bnot = function(a) return ~a end,
    lshift = function(a, b) return a << b end,
    rshift = function(a, b) return a >> b end,
    arshift = function(a, b)
        local upper_bits = (~(((a & 0x80000000) >> b) - 1)) & 0xffffffff
        return (a >> b) | upper_bits
    end,
    lrotate = function(a, b)
        return (a << b) | (a >> (32 - b))
    end
}
