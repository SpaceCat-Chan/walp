local bit = bit32

local require_path = (...):match("(.-)[^%.]+$")
local bit_conv = require(require_path.."bitconverter")


local function signed(N, i)
    if i > math.pow(2,N-1) then
        return i - math.pow(2,N)
    end
    return i
end

local function inv_signed(N, i)
    if i < 0 then
        return i + math.pow(2,N)
    end
    return i
end

local function extend(M,N, i)
    return inv_signed(N, signed(M,i))
end

local function take(byte, return_instead)
    return function(inseq, ptr)
        if inseq(ptr) == byte then
            return return_instead or byte, ptr+1
        else
            return nil
        end
    end
end

local function tuple(...)
    local args = {...}
    return function(inseq, ptr)
        local results = {}
        for _,parser in ipairs(args) do
            local result, next = parser(inseq, ptr)
            if result ~= nil then
                table.insert(results, result)
                ptr = next
            else
                return nil
            end
        end
        return results, ptr
    end
end

local function alt(...)
    local args = {...}
    return function(inseq, ptr)
        for _,parser in ipairs(args) do
            local result, next = parser(inseq, ptr)
            if result ~= nil then
                return result, next
            end
        end
        return nil
    end
end

local function repeat_n(amount, parser)
    return function(inseq, ptr)
        local results = {}
        for x=1,amount do
            local result, next = parser(inseq, ptr)
            if result == nil then
                return nil
            end
            ptr = next
            results[x] = result
        end
        return results, ptr
    end
end

local function map(parser, mapper)
    return function(inseq, ptr)
        local result, ptr = parser(inseq, ptr)
        if result ~= nil then
            return mapper(result), ptr
        else
            return nil
        end
    end
end

local function many0(parser)
    return function(inseq, ptr)
        local results = {}
        while true do
            local result, next = parser(inseq, ptr)
            if result == nil then
                return results, ptr
            else
                table.insert(results, result)
                ptr = next
            end
        end
    end
end

local function many1(parser)
    return function(inseq, ptr)
        local results, next = many0(parser)(inseq, ptr)
        if next(results) == nil then
            return nil
        end
        return results, next
    end
end

local function condition(parser, cond)
    return function(inseq, ptr)
        local result, next = parser(inseq, ptr)
        if result == nil then
            return nil
        elseif cond(result) then
            return result, next
        else
            return nil
        end
    end
end

local function eq(parser, val)
    return condition(parser, function(x) return x == val end)
end

local function le(parser, val)
    return condition(parser, function(x) return x <= val end)
end
local function ge(parser, val)
    return condition(parser, function(x) return x >= val end)
end
local function within(parser, min, max)
    return le(ge(parser, min), max)
end


local function byte(insep, ptr)
    return insep(ptr), ptr + 1
end

local function LEBlist(insep, ptr)
    local results = {}
    while true do
        local this_byte = byte(insep, ptr)
        if this_byte == nil then return nil end
        ptr = ptr + 1
        results[#results + 1] = this_byte
        if bit.band(this_byte, 0x80) == 0 then
            return results, ptr
        end
    end
end

local function interpuLEB(bytes)
    local result = 0
    for index, byte in ipairs(bytes) do
        result = bit.bor(result, bit.lshift(bit.band(byte, 0x7F), (index-1)*7))
    end
    return result
end

local function uLEB(inseq, ptr)
    local bytes, ptr = LEBlist(inseq, ptr)
    if bytes == nil then return nil end
    return interpuLEB(bytes), ptr
end

local function sLEB(inseq, ptr)
    local bytes, ptr = LEBlist(inseq, ptr)
    if bytes == nil then return nil end
    local result = extend(7 * #bytes, 32, interpuLEB(bytes))

    return result, ptr
end

local function iLEB(inseq, ptr)
    return sLEB(inseq, ptr)
end

local function interpuLEB64(bytes)
    local low, high = 0, 0
    local byte_count = #bytes
    for idx=1,4 do
        if idx > byte_count then return high,low end
        local byte = bytes[idx]
        low = bit.bor(low, bit.lshift(bit.band(byte, 0x7F), (idx-1)*7))
    end
    if 5 > byte_count then return high,low end
    low = bit.bor(low, bit.lshift(bit.band(bytes[5], 0x0F), 28))
    high = bit.rshift(bit.band(bytes[5], 0x70), 4)
    for idx=6,10 do
        if idx > byte_count then return high,low end
        local byte = bytes[idx]
        high = bit.bor(high, bit.lshift(bit.band(byte, 0x7F), (idx-1)*7+3))
    end
    return high, low
end

local function uLEB64(inseq, ptr)
    local bytes, ptr = LEBlist(inseq, ptr)
    if bytes == nil then return nil end
    local high, low = interpuLEB64(bytes)
    return {h = high, l = low}, ptr
end

local function sLEB64(inseq, ptr)
    local bytes, ptr = LEBlist(inseq, ptr)
    if bytes == nil then return nil end
    if #bytes == 0 then
        return nil
    end
    local high, low = interpuLEB64(bytes)
    if #bytes < 5 then
        low = extend(7 * #bytes, 32, low)
        high = bit.arshift(bit.band(low,0x80000000),32)
    else
        high = extend((7 * #bytes + 3)-32, 32, high)
    end
    return {h = high, l = low}, ptr
end

local function iLEB64(inseq, ptr)
    return sLEB64(inseq, ptr)
end

--[[
    the fuck, this looks like autogenerated code
    self._m_value = 
                 (((((((self.groups[0 + 1].value + utils.box_unwrap((self.len >= 2) 
    and utils.box_wrap((self.groups[1 + 1].value << 7)) or (0))) + utils.box_unwrap((self.len >= 3) 
    and utils.box_wrap((self.groups[2 + 1].value << 14)) or (0))) + utils.box_unwrap((self.len >= 4) 
    and utils.box_wrap((self.groups[3 + 1].value << 21)) or (0))) + utils.box_unwrap((self.len >= 5) 
    and utils.box_wrap((self.groups[4 + 1].value << 28)) or (0))) + utils.box_unwrap((self.len >= 6) 
    and utils.box_wrap((self.groups[5 + 1].value << 35)) or (0))) + utils.box_unwrap((self.len >= 7) 
    and utils.box_wrap((self.groups[6 + 1].value << 42)) or (0))) + utils.box_unwrap((self.len >= 8) 
    and utils.box_wrap((self.groups[7 + 1].value << 49)) or (0)))

    a. what is box_wrap and box_unwrap?
    b. the fuck is this hyper-nested ternary statement?

    found a much nicer version
  len:
    value: groups.size
  value:
    value: >-
      for idx, group in groups do
        value = value + bit.lshift(group, 7*idx)
      end
    doc: Resulting unsigned value as normal integer
  sign_bit:
    value: '1 << (7 * len - 1)'
  value_signed:
    value: 'bit.bnot(value, sign_bit) - sign_bit'
]]

--local function uLEB(inseq, )
-- i hope no one will try to load ints larger than 2^52-1


local function vec(parser)
    return function(inseq, ptr)
        local amount, ptr = uLEB(inseq, ptr)
        if amount == nil then return nil end
        local results = {}
        for i=1,amount do
            local result, next = parser(inseq, ptr)
            if result == nil then return nil end
            results[i] = result
            ptr = next
        end
        return results, ptr
    end
end

local function name(inseq, ptr)
    local length = inseq(ptr)
    local result = ""
    for x=ptr+1, ptr+length do
        result = result..string.char(inseq(x))
    end
    return result, ptr+length+1
end

local value_type =
alt(
    take(0x7F, "i32"),
    take(0x7E, "i64"),
    take(0x7D, "f32"),
    take(0x7C, "f64")
)

local ref_type = 
alt(
    take(0x70, "funcref"),
    take(0x6F, "externref")
)

local ptype = alt(value_type, ref_type)

local result_type = vec(ptype)

local function_type =
map(tuple(take(0x60), result_type, result_type), function(f) return {from=f[2], to=f[3]} end)

local limit = 
map(alt(
    tuple(take(0), uLEB),
    tuple(take(1), uLEB, uLEB)
), function(f) return {min=f[2], max=f[3]} end)

local memtype = limit

local tabletype = tuple(ref_type, limit)

local globaltype = tuple(value_type, alt(take(0, false), take(1, true)))


local block_type =
alt(
    take(0x40, -1),
    value_type,
    sLEB
)

local index = uLEB

local memarg = tuple(uLEB, uLEB)

local function u8sToFloat(u8s)
    local u32 = bit_conv.UInt8sToUInt32(u8s[1],u8s[2],u8s[3],u8s[4])
    return bit_conv.UInt32ToFloat(u32)
end

local function u8sToDouble(u8s)
    local u32_low = bit_conv.UInt8sToUInt32(u8s[1],u8s[2],u8s[3],u8s[4])
    local u32_high = bit_conv.UInt8sToUInt32(u8s[5],u8s[6],u8s[7],u8s[8])
    return bit_conv.UInt32sToDouble(u32_low, u32_high)
end

local function instr(inseq, ptr)
    return alt(
        tuple(take(0x00)), -- unreachable
        tuple(take(0x01)), -- noop
        tuple(take(0x02), block_type, many0(instr), take(0x0B)), -- block
        tuple(take(0x03), block_type, many0(instr), take(0x0B)), -- loop
        tuple(take(0x04), block_type, many0(instr), take(0x0B)), -- if, no else
        tuple(take(0x04), block_type, many0(instr), take(0x05), many0(instr), take(0x0B)), -- if else
        tuple(take(0x0C), index), -- branch
        tuple(take(0x0D), index), -- branch if
        tuple(take(0x0E), vec(index), index), -- branch table
        tuple(take(0x0F)), --return
        tuple(take(0x10), index), -- call
        tuple(take(0x11), index, index), -- call indirect
        tuple(take(0xD0), ref_type), --ref.null
        tuple(take(0xD1)), -- ref.is_null
        tuple(take(0xD2), index), -- ref.func
        tuple(take(0x1A)), -- drop
        tuple(take(0x1B)), -- select
        tuple(take(0x1C), value_type), -- select
        tuple(within(byte, 0x20, 0x26), index), -- local.get, local.set, local.tee, global.get, global.set, table.get, table.set
        tuple(take(0xFC), eq(uLEB, 12), index, index), -- table.init
        tuple(take(0xFC), eq(uLEB, 13), index), -- elem.drop
        tuple(take(0xFC), eq(uLEB, 14), index, index), -- table.copy
        tuple(take(0xFC), within(uLEB, 15, 17), index), -- table.grow size and fill
        tuple(within(byte, 0x28, 0x3E), memarg), -- memory load and store instructions (23)
        tuple(within(byte, 0x3F,0x40), take(0x00)), -- memory size and grow
        tuple(take(0xFC), eq(uLEB, 8), index, take(0x00)), -- memory.init
        tuple(take(0xFC), eq(uLEB, 9), index), -- data.drop
        tuple(take(0xFC), eq(uLEB, 10), take(0x00), take(0x00)), -- memory.copy
        tuple(take(0xFC), eq(uLEB, 11), take(0x00)), -- memory.fill
        tuple(take(0x41), iLEB), -- i32.const
        tuple(take(0x42), iLEB64), -- i64.const
        tuple(take(0x43), map(repeat_n(4, byte), u8sToFloat)), -- f32.const
        tuple(take(0x44), map(repeat_n(8, byte), u8sToDouble)), -- f32 const
        tuple(within(byte, 0x45, 0xC4)), -- numeric instructions (128)
        tuple(take(0xFC), within(uLEB, 0,7)) -- saturating truncate instructions (8)
    )(inseq, ptr)
end

local expr = tuple(many0(instr), take(0x0B))

local function custom_section(size)
    return function(inseq, ptr)
        local name, ptr = name(inseq, ptr)
        if name == nil then
            return nil
        end
        local bytes, ptr = repeat_n(size-name:len(), byte)(inseq, ptr)
        if bytes == nil then
            return nil
        else
            return {name, bytes}, ptr
        end
    end
end

local type_section = vec(function_type)

local importdesc = alt(
    tuple(take(0x00), index),
    tuple(take(0x01), tabletype),
    tuple(take(0x02), memtype),
    tuple(take(0x03), globaltype)
)

local import = tuple(name, name, importdesc)

local import_section = vec(import)

local function_section = vec(index)

local table_section = vec(tabletype)

local memory_section = vec(memtype)

local global = tuple(globaltype, expr)
local global_section = vec(global)

local exportdesc = tuple(within(byte, 0, 3), index)
local export = tuple(name, exportdesc)
local export_section = vec(export)

local start_section = index

local function elem(inseq, ptr)
    local type, ptr = within(byte, 0, 7)(inseq, ptr)
    if type == nil then return nil end
    local is_active = bit.band(type, 1) ~= 0
    local is_declerative_explicit_table_index = bit.band(type, 2) ~= 0
    local use_element_type = bit.band(type, 4) ~= 0
    local result = {}
    if not is_active then
        result.mode = "active"
        if is_declerative_explicit_table_index then
            local table_index, next = index(inseq, ptr)
            if table_index == nil then return nil end
            ptr = next
            result.active_info = {table = table_index}
        else
            result.active_info = {table = 0}
        end
        result.type = "funcref"
        local offset, next = expr(inseq, ptr)
        if offset == nil then return nil end
        ptr = next
        result.active_info.offset = offset

        if use_element_type then
            if is_declerative_explicit_table_index then
                local ref, next = ref_type(inseq, ptr)
                if ref == nil then return nil end
                ptr = next
                result.type = ref
            end
            local expressions, next = vec(expr)(inseq, ptr)
            if expressions == nil then return nil end
            ptr = next
            result.init = expressions
        else
            if is_declerative_explicit_table_index then
                local kind, next = take(0x00)(inseq, ptr)
                if kind == nil then return nil end
                ptr = next
            end
            local function_ids, next = vec(map(index, function(index) return {{{0xD2, index}}, 0x0B} end))(inseq, ptr)
            if function_ids == nil then return nil end
            ptr = next
            result.init = function_ids
        end
    else
        if use_element_type then
            local ref, next = ref_type(inseq, ptr)
            if ref == nil then return nil end
            ptr = next
            local expressions, next = vec(expr)(inseq, ptr)
            if expressions == nil then return nil end
            ptr = next
            result.init = expressions
            result.type = ref
        else
            local kind, next = take(0x00)(inseq, ptr)
            if kind == nil then return nil end
            ptr = next
            local function_ids, next = vec(map(index, function(index) return {{{0xD2, index}}, 0x0B} end))
            if function_ids == nil then return nil end
            ptr = next
            result.init = function_ids
            result.type = "funcref"
        end
        if is_declerative_explicit_table_index then
            result.mode = "declerative"
        else
            result.mode = "passive"
        end
    end
    return result, ptr
end

local elem_section = vec(elem)

local local_ = tuple(uLEB, value_type)
local func = tuple(vec(local_), expr)
local code = tuple(uLEB, func)
local code_section = vec(code)

local data = alt(
    tuple(take(0x00), expr, vec(byte)),
    tuple(take(0x01), vec(byte)),
    tuple(take(0x02), index, expr, vec(byte))
)
local data_section = vec(data)

local data_count_section = uLEB

local section_table = {
    [0] = custom_section,
    [1] = type_section,
    [2] = import_section,
    [3] = function_section,
    [4] = table_section,
    [5] = memory_section,
    [6] = global_section,
    [7] = export_section,
    [8] = start_section,
    [9] = elem_section,
    [10] = code_section,
    [11] = data_section,
    [12] = data_count_section,
}

local function section(inseq, ptr)
    local id, ptr = within(byte, 0, 12)(inseq, ptr)
    if id == nil then
        return nil
    end
    local size, ptr = uLEB(inseq, ptr)
    if size == nil then
        return nil
    end
    local section, new_ptr
    if id == 0 then
        section, new_ptr = custom_section(size)(inseq, ptr)
    else
        section, new_ptr = section_table[id](inseq, ptr)
    end
    return {id, size, section}, new_ptr
end

local magic = tuple(take(0x00), take(0x61), take(0x73), take(0x6D))
local version = tuple(take(0x01), take(0x00), take(0x00), take(0x00))
local module = tuple(magic, version, many0(section))

return {
    byte = byte,
    uLEB = uLEB,
    sLEB = sLEB,
    iLEB = iLEB,
    name = name,
    value_type = value_type,
    ref_type = ref_type,
    ptype = ptype,
    result_type = result_type,
    function_type = function_type,
    limit = limit,
    memtype = memtype,
    tabletype = tabletype,
    globaltype = globaltype,
    block_type = block_type,
    instr = instr,
    expr = expr,
    custom_section = custom_section,
    type_section = type_section,
    import_section = import_section,
    function_section = function_section,
    table_section = table_section,
    memory_section = memory_section,
    global_section = global_section,
    export_section = export_section,
    start_section = start_section,
    code_section = code_section,
    data_section = data_section,
    data_count_section = data_count_section,
    section = section,
    magic = magic,
    version = version,
    module = module
}
