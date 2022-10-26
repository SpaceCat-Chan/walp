local require_path = (...):match("(.-)[^%.]+$")
local bit_conv = require(require_path .. "bitconverter")
local bit = require(require_path .. "bitops")

local function cut_dot_0(s)
    local _, _, new = string.find(s, "(%d+)%.?0?")
    return new
end

local function push(stack, value)
    stack[#stack + 1] = value
end

local function pop(stack)
    local value = stack[#stack]
    stack[#stack] = nil
    return value
end

local function top(stack)
    return stack[#stack]
end

local function signed(N, i)
    if i > math.pow(2, N - 1) then
        return i - math.pow(2, N)
    end
    return i
end

local function inv_signed(N, i)
    if i < 0 then
        return i + math.pow(2, N)
    end
    return i
end

local function extend(M, N, i)
    return inv_signed(N, signed(M, i))
end

local function trunc(i)
    if i >= 0 then
        return math.floor(i)
    else
        return math.ceil(i)
    end
end

local function expand_type(t, module)
    if t == -1 then
        return { from = {}, to = {} }
    elseif type(t) == "string" then
        return { from = {}, to = { t } }
    else
        return module.types[t]
    end
end

local function find_mem_address(ins, stack, frame, N, module)
    local m = ins[2]
    local mem = module.store.mems[1]
    local i = pop(stack)
    local ea = i + m[2]
    if ea + N / 8 > #mem.data then
        return nil, nil, "attempted to access memory address outside of allocated memory"
    end
    return mem, ea
end

local function load_from(ins, stack, frame, N, module)
    local mem, ea, error = find_mem_address(ins, stack, frame, N, module)
    if error then return nil, error end
    local bytes = {}
    for x = 1, N / 8 do
        bytes[x] = mem.data[ea + x]
    end
    return bytes
end

local function store_to(ins, stack, frame, bytes, module)
    local mem, ea, error = find_mem_address(ins, stack, frame, #bytes * 8, module)
    if error then return error end
    for x = 1, #bytes do
        mem.data[ea + x] = bytes[x]
    end
end

local eval_single_with, eval_instructions_with

local extra_instructions

local function invoke(addr, stack, frame, labels, module, frame_cache)
    local new_f = module.store.funcs[addr + 1]

    local arg_count = #new_f.type.from
    local args = {}
    for x = arg_count, 1, -1 do
        args[x] = pop(stack) -- or args[arg_count-x+1] dont know which one
    end

    if new_f.hostcode then
        local results = { new_f.hostcode((table.unpack or unpack)(args)) }
        for x = 1, #results do
            push(stack, results[x])
        end
        return
    end

    for x = 1, #new_f.code.locals do
        if new_f.code.locals[x] == "i64" then
            args[x + arg_count] = { l = 0, h = 0 }
        else
            args[x + arg_count] = 0
        end
    end

    local new_frame = { func = new_f.code, func_addr = addr, locals = args, type = new_f.type, ins_ptr = 0,
        stack_height = #stack, label_height = #labels }
    push(frame, new_frame)
    push(labels, { type = new_f.type, is_function = true, stack_height = #stack })
    return true
    --[[ from before de-recursion
	local r, p = eval_instructions_with(new_f.code.body, stack, new_frame, labels)
	pop(labels)
    if r then
	    for x=1,#new_f.type.to do
		    push(stack, p[x])
	    end
    end
    ]]
end

local function i64_ge_u(n1, n2)
    if n1.h > n2.h then
        return 1
    elseif n1.h == n2.h then
        if n1.l >= n2.l then
            return 1
        else
            return 0
        end
    else
        return 0
    end
end

local function i64_gt_u(n1, n2)
    if n1.h > n2.h then
        return 1
    elseif n1.h == n2.h then
        if n1.l > n2.l then
            return 1
        else
            return 0
        end
    else
        return 0
    end
end

local function i64_le_u(n1, n2)
    if n1.h < n2.h then
        return 1
    elseif n1.h == n2.h then
        if n1.l <= n2.l then
            return 1
        else
            return 0
        end
    else
        return 0
    end
end

local function i64_add(n1, n2)
    local low = n1.l + n2.l
    local high = n1.h + n2.h + (low >= 4294967296 and 1 or 0)
    return {
        l = bit.band(low, 0xFFFFFFFF),
        h = bit.band(high, 0xFFFFFFFF)
    }
end

local function i64_sub(n1, n2)
    local low = n1.l - n2.l
    local high = n1.h - n2.h - (low < 0 and 1 or 0)
    return {
        l = inv_signed(32, low),
        h = inv_signed(32, high)
    }
end

local function i64_mul(a, b)
    local a48 = bit.rshift(a.h, 16)
    local a32 = bit.band(a.h, 65535)
    local a16 = bit.rshift(a.l, 16)
    local a00 = bit.band(a.l, 65535)

    local b48 = bit.rshift(b.h, 16)
    local b32 = bit.band(b.h, 65535)
    local b16 = bit.rshift(b.l, 16)
    local b00 = bit.band(b.l, 65535)

    local c00 = a00 * b00
    local c16 = bit.rshift(c00, 16)
    c00 = bit.band(c00, 65535)

    c16 = c16 + a16 * b00
    local c32 = bit.rshift(c16, 16)
    c16 = bit.band(c16, 65535)

    c16 = c16 + a00 * b16
    c32 = c32 + bit.rshift(c16, 16)
    c16 = bit.band(c16, 65535)

    c32 = c32 + a32 * b00
    local c48 = bit.rshift(c32, 16)
    c32 = bit.band(c32, 65535)

    c32 = c32 + a16 * b16
    c48 = c48 + bit.rshift(c32, 16)
    c32 = bit.band(c32, 65535)

    c32 = c32 + a00 * b32
    c48 = c48 + bit.rshift(c32, 16)
    c32 = bit.band(c32, 65535)

    c48 = c48 + a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48
    c48 = bit.band(c48, 65535)

    return {
        l = bit.bor(c00, bit.lshift(c16, 16)),
        h = bit.bor(c32, bit.lshift(c48, 16))
    }
end

local function i64_div_core(rem, divisor)
    assert(divisor.l ~= 0 or divisor.h ~= 0, "divide by zero")

    local res = {
        l = 0,
        h = 0,
    }

    local d_approx = divisor.l + divisor.h * 4294967296

    while i64_ge_u(rem, divisor) == 1 do
        local n_approx = rem.l + rem.h * 4294967296

        -- Don't allow our approximation to be larger than an i64
        n_approx = math.min(n_approx, 18446744073709549568)

        local q_approx = math.max(1, math.floor(n_approx / d_approx))

        -- dark magic from long.js / closure lib
        local log2 = math.ceil(math.log(q_approx, 2))
        local delta = math.pow(2, math.max(0, log2 - 48))

        local res_approx_low, res_approx_high = bit.band(math.floor(q_approx), 0xFFFFFFFF),
            bit.band(math.floor(q_approx / math.pow(2, 32)), 0xFFFFFFFF)
        local res_approx = { l = res_approx_low, h = res_approx_high }
        local rem_approx = i64_mul(res_approx, divisor)

        -- decrease approximation until smaller than remainder and the multiply hopefully
        while i64_gt_u(rem_approx, rem) == 1 do
            q_approx = q_approx - delta
            res_approx_low, res_approx_high = bit.band(math.floor(q_approx), 0xFFFFFFFF),
                bit.band(math.floor(q_approx / math.pow(2, 32)), 0xFFFFFFFF)
            res_approx = { l = res_approx_low, h = res_approx_high }
            rem_approx = i64_mul(res_approx, divisor)
        end

        -- res must be at least one, lib I copied the algo from had this check
        -- but I'm not sure is necessary or makes sense
        if res_approx.l == 0 and res_approx.h == 0 then
            error("res_approx = 0")
            res_approx.l = 1
        end

        res = i64_add(res, res_approx)
        rem = i64_sub(rem, rem_approx)
    end

    return res, rem
end

local __clz_tab = { 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 }
__clz_tab[0] = 4

local function __CLZ__(x)
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

local function __CTZ__(x)
    if x == 0 then return 32 end
    return __ctz_tab[bit.rshift(bit.band(x, -x) * 125613361, 27)]
end

local __popcnt_tab = {
    1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4,
    5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4,
    5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5,
    6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
}
__popcnt_tab[0] = 0

local function __POPCNT__(x)
    -- the really cool algorithm uses a multiply that can overflow, so we're stuck with a LUT
    return __popcnt_tab[bit.band(x, 255)]
        + __popcnt_tab[bit.band(bit.rshift(x, 8), 255)]
        + __popcnt_tab[bit.band(bit.rshift(x, 16), 255)]
        + __popcnt_tab[bit.rshift(x, 24)]
end

local instructions
instructions = {
    -- CONTROL INSTRUCTIONS ---------------------
    [0x00] = function(ins, stack, frame) -- unreachable
        return "unreachable"
    end,
    [0x01] = function(ins, stack, frame) -- noop
    end,
    [0x02] = function(ins, stack, frame, labels, module) -- block,  br skips
        local new_label = expand_type(ins[2], module)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + ins[3], stack_height = #stack })
        --[[ old stuff from before de-recursion was done
        local r, p = eval_instructions_with(ins[3], stack, frame, labels)
        pop(labels)
        if r == -1 then
            return -1, p
        end
        if r ~= nil then
            if r > 0 then
                return r - 1, p
            end
            while #stack ~= stack_height do
                pop(stack)
            end
            for x=1,#new_label.to do
                push(stack, p[x])
            end
        end]]
    end,
    [0x03] = function(ins, stack, frame, labels, module) -- loop
        -- br loops again
        local new_label = expand_type(ins[2], module)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + 1, stack_height = #stack })
        --[[ old stuff from before de-recursion was done
        local r, p = eval_instructions_with(ins[3], stack, frame, labels)
        pop(labels)
        if r == -1 then
            return -1, p
        end
        if r ~= nil then
            if r > 0 then
                return r - 1, p
            end
            while #stack ~= stack_height do
                pop(stack)
            end
            for x=1,#new_label.to do
                push(stack, p[x])
            end
        else
            break
        end]]
    end,
    [0x04] = function(ins, stack, frame, labels, module) -- if else
        local new_label = expand_type(ins, module)
        local c = pop(stack)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + ins[3], stack_height = #stack })
        if c == 0 then
            top(frame).ins_ptr = top(frame).ins_ptr + ins[4]
        end
        --[[ old stuff from before de-recursion was done
        if c ~= 0 then
            r, p = eval_instructions_with(ins[2], stack, frame, labels)
        else
            r, p = eval_instructions_with(ins[4] or {}, stack, frame, labels)
        end
        pop(labels)
        if r == -1 then
            return -1, p
        end
        if r ~= nil then
            if r > 0 then
                return r - 1, p
            end
            while #stack ~= stack_height do
                pop(stack)
            end
            for x=1,#new_label.to do
                push(stack, p[x])
            end
        end
        ]]
    end,
    [0x05] = function(ins, stack, frame, labels) -- else
        top(frame).ins_ptr = top(labels).break_pos - 2
    end,
    [0x0B] = function(ins, stack, frame, labels) -- end
        local label = pop(labels)
        if label.is_function then
            pop(frame)
            return true
        end
    end,
    [0x0C] = function(ins, stack, frame, labels, module, frame_cache) -- br
        local label = labels[#labels - ins[2]]
        if label.is_function then
            return instructions[0x0F](ins, stack, frame, label, frame_cache)
        end
        local pop_count = #label.type.to
        local p = {}
        for x = pop_count, 1, -1 do
            p[x] = pop(stack)
        end
        while #stack ~= label.stack_height do
            pop(stack)
        end
        for x = 1, pop_count do
            push(stack, p[x])
        end
        for _ = 1, (ins[2] + 1) do
            pop(labels)
        end
        push(labels, label)
        frame_cache.ins_ptr = label.break_pos - 1
    end,
    [0x0D] = function(ins, stack, frame, labels, module, frame_cache) -- br_if
        local c = pop(stack)
        if c ~= 0 then
            return instructions[0x0C]({ 0x0C, ins[2] }, stack, frame, labels, module, frame_cache)
        end
    end,
    [0x0E] = function(ins, stack, frame, labels, module, frame_cache) -- br_table
        local i = pop(stack)
        if i + 1 <= #ins[2] then
            return instructions[0x0C]({ 0x0C, ins[2][i + 1] }, stack, frame, labels, module, frame_cache)
        else
            return instructions[0x0C]({ 0x0C, ins[3] }, stack, frame, labels, module, frame_cache)
        end
    end,
    [0x0F] = function(ins, stack, frame, labels, module, frame_cache) -- return
        local pop_count = #frame_cache.type.to
        local p = {}
        for x = pop_count, 1, -1 do
            p[x] = pop(stack)
        end
        while #stack ~= frame_cache.stack_height do
            pop(stack)
        end
        while #labels ~= frame_cache.label_height do
            pop(labels)
        end
        pop(frame)
        for x = 1, pop_count do
            push(stack, p[x])
        end
        return true
    end,
    [0x10] = function(ins, stack, frame, labels, module, frame_cache) -- call
        return invoke(ins[2], stack, frame, labels, module, frame_cache)
    end,
    [0x11] = function(ins, stack, frame, labels, module, frame_cache) -- call_indirect
        local tab = module.store.tables[ins[3] + 1]
        local ft_expect = module.types[ins[2] + 1]
        local i = pop(stack)
        if i >= #tab.elem then
            error("trap")
        end
        local r = tab.elem[i + 1]
        if r == 0 then
            error("trap")
        end
        local ft_actual = module.store.funcs[r + 1].type
        if #ft_expect.from ~= #ft_actual.from then
            error("trap")
        end
        if #ft_expect.to ~= #ft_actual.to then
            error("trap")
        end
        for k, v in pairs(ft_actual.from) do
            if v ~= ft_expect.from[k] then
                error("trap")
            end
        end
        for k, v in pairs(ft_actual.to) do
            if v ~= ft_expect.to[k] then
                error("trap")
            end
        end
        return invoke(r, stack, frame, labels, module, frame_cache)
    end,
    -- REFERENCE INSTRUCTIONS -----------------------
    [0xD0] = function(ins, stack, frame) -- ref.null
        push(stack, 0)
    end,
    [0xD1] = function(ins, stack, frame) -- ref.is_null
        local val = pop(stack)
        if val == 0 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0xD2] = function(ins, stack, frame) -- ref.func
        --[[
            from my current understanding:
            currently only one module can be loaded, so no lookup is required
        ]]
        push(stack, ins[2])
    end,
    -- PARAMETRIC INSTRUCTIONS -----------------------
    [0x1A] = function(ins, stack, frame) -- drop
        pop(stack)
    end,
    [0x1B] = function(ins, stack, frame) -- select
        local selector = pop(stack)
        local val2 = pop(stack)
        local val1 = pop(stack)
        if selector ~= 0 then
            push(stack, val1)
        else
            push(stack, val2)
        end
    end,
    -- VARIABLE INSTRUCTIONS -------------------------
    [0x20] = function(ins, stack, frame, labels, module, frame_cache) -- local.get
        push(stack, frame_cache.locals[ins[2] + 1])
    end,
    [0x21] = function(ins, stack, frame, labels, module, frame_cache) -- local.set
        frame_cache.locals[ins[2] + 1] = pop(stack)
    end,
    [0x22] = function(ins, stack, frame, labels, module, frame_cache) -- local.tee
        frame_cache.locals[ins[2] + 1] = stack[#stack]
    end,
    [0x23] = function(ins, stack, frame, labels, module) -- global.get
        push(stack, module.store.globals[ins[2] + 1].val)
    end,
    [0x24] = function(ins, stack, frame, labels, module) -- global.set
        module.store.globals[ins[2] + 1].val = pop(stack)
    end,
    -- TABLE INSTRUCTIONS ----------------------------
    [0x25] = function(ins, stack, frame, labels, module) -- table.get
        local tab = module.store.tables[ins[2] + 1]
        local i = pop(stack)
        if i >= #tab.elem then
            error("trap")
        end
        push(stack, tab.elem[i + 1])
    end,
    [0x26] = function(ins, stack, frame, labels, module) -- table.set
        local x = ins[2]
        local tab = module.store.tables[x + 1]
        local val = pop(stack)
        local i = pop(stack)
        if i >= #tab.elem then
            error("trap")
        end
        tab.elem[i + 1] = val
    end,
    -- MEMORY INSTRUCTIONS ---------------------------
    [0x28] = function(ins, stack, frame, labels, module) -- i32.load
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes)))
    end,
    [0x29] = function(ins, stack, frame, labels, module) -- i64.load
        local bytes, error = load_from(ins, stack, frame, 64, module)
        if error then return error end
        push(stack, {
            l = bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes, 1, 4)),
            h = bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes, 5, 8))
        })
    end,
    [0x2A] = function(ins, stack, frame, labels, module) -- f32.load
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, bit_conv.UInt32ToFloat(bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes))))
    end,
    [0x2B] = function(ins, stack, frame, labels, module) -- f64.load
        local bytes, error = load_from(ins, stack, frame, 64, module)
        if error then return error end
        push(stack, bit_conv.UInt32sToDouble(
            bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes, 1, 4)),
            bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes, 5, 8))
        ))
    end,
    [0x2C] = function(ins, stack, frame, labels, module) -- i32.load8_s
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, extend(8, 32, bytes[1]))
    end,
    [0x2D] = function(ins, stack, frame, labels, module) -- i32.load8_u
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, bytes[1])
    end,
    [0x2E] = function(ins, stack, frame, labels, module) -- i32.load16_s
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, extend(16, 32, bit_conv.UInt8sToUInt16((table.unpack or unpack)(bytes))))
    end,
    [0x2F] = function(ins, stack, frame, labels, module) -- i32.load16_u
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, bit_conv.UInt8sToUInt16((table.unpack or unpack)(bytes)))
    end,
    [0x30] = function(ins, stack, frame, labels, module) -- i64.load8_s
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        if bit.band(bytes[1], 0x80) ~= 0 then
            push(stack, { l = extend(8, 32, bytes[1]), h = 0xFFFFFFFF })
        else
            push(stack, { l = bytes[1], h = 0 })
        end
    end,
    [0x31] = function(ins, stack, frame, labels, module) -- i64.load8_u
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, { l = bytes[1], h = 0 })
    end,
    [0x32] = function(ins, stack, frame, labels, module) -- i64.load16_s
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        local raw_num = bit_conv.UInt8sToUInt16((table.unpack or unpack)(bytes))
        if bit.band(raw_num, 0x8000) ~= 0 then
            push(stack, { l = extend(16, 32, raw_num), h = 0xFFFFFFFF })
        else
            push(stack, { l = raw_num, h = 0 })
        end
    end,
    [0x33] = function(ins, stack, frame, labels, module) -- i64.load16_u
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, { l = bit_conv.UInt8sToUInt16((table.unpack or unpack)(bytes)), h = 0 })
    end,
    [0x34] = function(ins, stack, frame, labels, module) -- i64.load32_s
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        local raw_num = bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes))
        if bit.band(raw_num, 0x80000000) ~= 0 then
            push(stack, { l = raw_num, h = 0xFFFFFFFF })
        else
            push(stack, { l = raw_num, h = 0 })
        end
    end,
    [0x35] = function(ins, stack, frame, labels, module) -- i64.load32_u
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, { l = bit_conv.UInt8sToUInt32((table.unpack or unpack)(bytes)), h = 0 })
    end,
    [0x36] = function(ins, stack, frame, labels, module) -- i32.store
        local c = pop(stack)
        local bytes = { bit_conv.UInt32ToUInt8s(c) }
        return store_to(ins, stack, frame, bytes, module)
    end,
    [0x37] = function(ins, stack, frame, labels, module) -- i64.store
        local c = pop(stack)
        local u80, u81, u82, u83 = bit_conv.UInt32ToUInt8s(c.l)
        local u84, u85, u86, u87 = bit_conv.UInt32ToUInt8s(c.h)
        return store_to(ins, stack, frame, { u80, u81, u82, u83, u84, u85, u86, u87 }, module)
    end,
    [0x38] = function(ins, stack, frame, labels, module) -- f32.store
        local c = pop(stack)
        return store_to(ins, stack, frame, { bit_conv.UInt32ToUInt8s(bit_conv.FloatToUInt32(c)) }, module)
    end,
    [0x39] = function(ins, stack, frame, labels, module) -- f64.store
        local c = pop(stack)
        local l, h = bit_conv.DoubleToUInt32s(c)
        local u80, u81, u82, u83 = bit_conv.UInt32ToUInt8s(l)
        local u84, u85, u86, u87 = bit_conv.UInt32ToUInt8s(h)
        return store_to(ins, stack, frame, { u80, u81, u82, u83, u84, u85, u86, u87 }, module)
    end,
    [0x3A] = function(ins, stack, frame, labels, module) -- i32.store8
        local c = pop(stack)
        local u80, _, _, _ = bit_conv.UInt32ToUInt8s(c)
        return store_to(ins, stack, frame, { u80 }, module)
    end,
    [0x3B] = function(ins, stack, frame, labels, module) -- i32.store16
        local c = pop(stack)
        local u80, u81, _, _ = bit_conv.UInt32ToUInt8s(c)
        return store_to(ins, stack, frame, { u80, u81 }, module)
    end,
    [0x3C] = function(ins, stack, frame, labels, module) -- i64.store8
        local c = pop(stack)
        local u80, _, _, _ = bit_conv.UInt32ToUInt8s(c.l)
        return store_to(ins, stack, frame, { u80 }, module)
    end,
    [0x3D] = function(ins, stack, frame, labels, module) -- i64.store16
        local c = pop(stack)
        local u80, u81, _, _ = bit_conv.UInt32ToUInt8s(c.l)
        return store_to(ins, stack, frame, { u80, u81 }, module)
    end,
    [0x3E] = function(ins, stack, frame, labels, module) -- i64.store32
        local c = pop(stack)
        local bytes = { bit_conv.UInt32ToUInt8s(c.l) }
        return store_to(ins, stack, frame, bytes, module)
    end,
    [0x3F] = function(ins, stack, frame, labels, module) -- memory.size
        local m = ins[2]
        local mem = module.store.mems[m + 1]
        push(stack, #mem.data / 65536)
    end,
    [0x40] = function(ins, stack, frame, labels, module) -- memory.grow
        local mem = module.store.mems[ins[2] + 1]
        local sz = #mem.data / 65536
        local n = pop(stack)
        if mem.type.max and mem.type.max < sz + n then
            push(stack, inv_signed(32, -1))
            return
        end
        local curr_index = sz * 65536
        for x = curr_index, curr_index + n * 65536 do
            mem.data[x] = 0
        end
        push(stack, sz)
    end,
    -- NUMERICS -----------------------------
    [0x41] = function(ins, stack, frame) -- i32.const, i64.const, f32.const, f64.const
        push(stack, ins[2])
    end,
    [0x45] = function(ins, stack, frame) -- i32.eqz
        local n = pop(stack)
        if n == 0 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x46] = function(ins, stack, frame) -- i32.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 == n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x47] = function(ins, stack, frame) -- i32.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 ~= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x48] = function(ins, stack, frame) -- i32.lt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        if signed(32, n1) < signed(32, n2) then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x49] = function(ins, stack, frame) -- i32.lt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 < n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4A] = function(ins, stack, frame) -- i32.gt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        if signed(32, n1) > signed(32, n2) then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4B] = function(ins, stack, frame) -- i32.gt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 > n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4C] = function(ins, stack, frame) -- i32.le_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        if signed(32, n1) <= signed(32, n2) then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4D] = function(ins, stack, frame) -- i32.le_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 <= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4E] = function(ins, stack, frame) -- i32.ge_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        if signed(32, n1) >= signed(32, n2) then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x4F] = function(ins, stack, frame) -- i32.ge_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 >= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x50] = function(ins, stack, frame) -- i64.eqz
        local n = pop(stack)
        if n.l == 0 and n.h == 0 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x51] = function(ins, stack, frame) -- i64.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1.l == n2.l and n1.h == n2.h then
            push(stack, 1)
        else
            push(stack, 0)
        end

    end,
    [0x52] = function(ins, stack, frame) -- i64.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1.l ~= n2.l or n1.h ~= n2.h then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x53] = function(ins, stack, frame) -- i64.lt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        local n1_is_neg = bit.rshift(n1.h, 31) == 1
        local n2_is_neg = bit.rshift(n2.h, 31) == 1
        if n1_is_neg and not n2_is_neg then
            push(stack, 1)
        elseif not n1_is_neg and n2_is_neg then
            push(stack, 0)
        else
            local t, n = 1, 0
            if n1_is_neg then
                t, n = n, t
            end
            if n1.h < n2.h then
                push(stack, t)
            elseif n1.h == n2.h then
                if n1.l < n2.l then
                    push(stack, t)
                elseif n1.l == n2.l then
                    push(stack, 0)
                else
                    push(stack, n)
                end
            else
                push(stack, n)
            end
        end
    end,
    [0x54] = function(ins, stack, frame) -- i64.lt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1.h < n2.h then
            push(stack, 1)
        elseif n1.h == n2.h then
            if n1.l < n2.l then
                push(stack, 1)
            else
                push(stack, 0)
            end
        else
            push(stack, 0)
        end
    end,
    [0x55] = function(ins, stack, frame) -- i64.gt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        local n1_is_neg = bit.rshift(n1.h, 31) == 1
        local n2_is_neg = bit.rshift(n2.h, 31) == 1
        if n1_is_neg and not n2_is_neg then
            push(stack, 0)
        elseif not n1_is_neg and n2_is_neg then
            push(stack, 1)
        else
            local t, n = 0, 1
            if n1_is_neg then
                t, n = n, t
            end
            if n1.h < n2.h then
                push(stack, t)
            elseif n1.h == n2.h then
                if n1.l < n2.l then
                    push(stack, t)
                elseif n1.l == n2.l then
                    push(stack, 0)
                else
                    push(stack, n)
                end
            else
                push(stack, n)
            end
        end
    end,
    [0x56] = function(ins, stack, frame) -- i64.gt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_gt_u(n1, n2))
    end,
    [0x57] = function(ins, stack, frame) -- i64.le_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        local n1_is_neg = bit.rshift(n1.h, 31) == 1
        local n2_is_neg = bit.rshift(n2.h, 31) == 1
        if n1_is_neg and not n2_is_neg then
            push(stack, 1)
        elseif not n1_is_neg and n2_is_neg then
            push(stack, 0)
        else
            local t, f = 1, 0
            if n1_is_neg then
                t, f = f, t
            end
            if n1.h > n2.h then
                push(stack, f)
            elseif n1.h == n2.h then
                if n1.l > n2.l then
                    push(stack, f)
                elseif n1.l == n2.l then
                    push(stack, 1)
                else
                    push(stack, t)
                end
            else
                push(stack, t)
            end
        end
    end,
    [0x58] = function(ins, stack, frame) -- i64.le_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_le_u(n1, n2))
    end,
    [0x59] = function(ins, stack, frame) -- i64.ge_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        local n1_is_neg = bit.rshift(n1.h, 31) == 1
        local n2_is_neg = bit.rshift(n2.h, 31) == 1
        if n1_is_neg and not n2_is_neg then
            push(stack, 0)
        elseif not n1_is_neg and n2_is_neg then
            push(stack, 1)
        else
            local t, f = 1, 0
            if n1_is_neg then
                t, f = f, t
            end
            if n1.h < n2.h then
                push(stack, f)
            elseif n1.h == n2.h then
                if n1.l < n2.l then
                    push(stack, f)
                elseif n1.l == n2.l then
                    push(stack, 1)
                else
                    push(stack, t)
                end
            else
                push(stack, t)
            end
        end
    end,
    [0x5A] = function(ins, stack, frame) -- i64.ge_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_ge_u(n1, n2))
    end,
    [0x5B] = function(ins, stack, frame) -- f32.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 == n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x5C] = function(ins, stack, frame) -- f32.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 ~= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x5D] = function(ins, stack, frame) -- f32.lt
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 < n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x5E] = function(ins, stack, frame) -- f32.gt
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 > n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x5F] = function(ins, stack, frame) -- f32.le
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 <= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x60] = function(ins, stack, frame) -- f32.ge
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1 >= n2 then
            push(stack, 1)
        else
            push(stack, 0)
        end
    end,
    [0x67] = function(ins, stack, frame) -- i32.clz
        local n = pop(stack)
        push(stack, __CLZ__(n))
    end,
    [0x68] = function(ins, stack, frame) -- i32.ctz
        local n = pop(stack)
        push(stack, __CTZ__(n))
    end,
    [0x69] = function(ins, stack, frame) -- i32.popcnt
        local n = pop(stack)
        push(stack, __POPCNT__(n))
    end,
    [0x6A] = function(ins, stack, frame) -- i32.add
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1 + n2, 0xFFFFFFFF))
    end,
    [0x6B] = function(ins, stack, frame) -- i32.sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, inv_signed(32, n1 - n2))
    end,
    [0x6C] = function(ins, stack, frame) -- i32.mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1 * n2, 0xFFFFFFFF))
    end,
    [0x6D] = function(ins, stack, frame) -- i32.div_s
        local n2 = signed(32, pop(stack))
        local n1 = signed(32, pop(stack))
        if n2 == 0 then
            error("trap, i32.div_s div by 0")
        end
        local res = trunc(n1 / n2)
        if res == math.pow(2, 31) then
            error("trap, division resulted in 2^31")
        end
        push(stack, inv_signed(32, res))
    end,
    [0x6E] = function(ins, stack, frame) -- i32.div_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n2 == 0 then
            error("trap, i32.div_s div by 0")
        end
        push(stack, math.floor(n1 / n2))
    end,
    [0x6F] = function(ins, stack, frame) -- i32.rem_s
        local n2 = signed(32, pop(stack))
        local n1 = signed(32, pop(stack))
        if n2 == 0 then
            error("trap, i32.rem_u div by zero")
        end
        push(stack, inv_signed(32, n1 - n2 * trunc(n1 / n2)))
    end,
    [0x70] = function(ins, stack, frame) -- i32.rem_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n2 == 0 then
            error("trap, i32.rem_u div by zero")
        end
        push(stack, n1 - n2 * trunc(n1 / n2))
    end,
    [0x71] = function(ins, stack, frame) -- i32.and
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1, n2))
    end,
    [0x72] = function(ins, stack, frame) -- i32.or
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.bor(n1, n2))
    end,
    [0x73] = function(ins, stack, frame) -- i32.xor
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.bxor(n1, n2))
    end,
    [0x74] = function(ins, stack, frame) -- i32.shl
        local n2 = pop(stack) % 32
        local n1 = pop(stack)
        push(stack, bit.band(bit.lshift(n1, n2), 0xFFFFFFFF))
    end,
    [0x75] = function(ins, stack, frame) -- i32.shr_s
        local n2 = pop(stack) % 32
        local n1 = pop(stack)
        push(stack, bit.arshift(n1, n2))
    end,
    [0x76] = function(ins, stack, frame) -- i32.shr_u
        local n2 = pop(stack) % 32
        local n1 = pop(stack)
        push(stack, bit.rshift(n1, n2))
    end,
    [0x77] = function(ins, stack, frame) -- i32.rotl
        local n2 = pop(stack) % 32
        local n1 = pop(stack)
        push(stack, bit.lrotate(n1, n2))
    end,
    [0x79] = function(ins, stack, frame) -- i64.clz
        local n = pop(stack)
        local result = (n.h ~= 0) and __CLZ__(n.h) or 32 + __CLZ__(n.l)
        push(stack, { l = result, h = 0 })
    end,
    [0x7C] = function(ins, stack, frame) -- i64.add
        local b = pop(stack)
        local a = pop(stack)
        push(stack, i64_add(a, b))
    end,
    [0x7D] = function(ins, stack, frame) -- i64.sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_sub(n1, n2))
    end,
    [0x7E] = function(ins, stack, frame) -- i64.mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_mul(n1, n2))
    end,
    [0x80] = function(ins, stack, frame) -- i64.div_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        local res, rem = i64_div_core(n1, n2)
        push(stack, res)
    end,
    [0x83] = function(ins, stack, frame) -- i64.and
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.band(n1.l, n2.l),
            h = bit.band(n1.h, n2.h)
        })
    end,
    [0x84] = function(ins, stack, frame) -- i64.or
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.bor(n1.l, n2.l),
            h = bit.bor(n1.h, n2.h)
        })
    end,
    [0x85] = function(ins, stack, frame) -- i64.xor
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.bxor(n1.l, n2.l),
            h = bit.bxor(n1.h, n2.h)
        })
    end,
    [0x86] = function(ins, stack, frame) -- i64.shl
        local n2 = pop(stack).l % 64
        local n1 = pop(stack)
        if n2 < 32 then
            local h = bit.bor(bit.lshift(n1.h, n2), n2 == 0 and 0 or bit.rshift(n1.l, 32 - n2))
            push(stack, {
                l = bit.lshift(n1.l, n2),
                h = h,
            })
        else
            push(stack, {
                l = 0,
                h = bit.lshift(n1.l, n2 - 32),
            })
        end
    end,
    [0x87] = function(ins, stack, frame) -- i64.shr_s
        local n2 = pop(stack).l % 64
        local n1 = pop(stack)
        if n2 == 0 then
            push(stack, {
                l = n1.l,
                h = n1.h,
            })
        elseif n2 < 32 then
            local l = bit.bor(bit.lshift(n1.h, 32 - n2), bit.rshift(n1.l, n2))
            push(stack, {
                l = l,
                h = bit.arshift(n1.h, n2)
            })
        elseif n2 == 32 then
            push(stack, {
                l = n1.h,
                h = bit.arshift(n1.h, 31)
            })
        else
            push(stack, {
                l = bit.arshift(n1.h, n2 - 32),
                h = bit.arshift(n1.h, 31)
            })
        end
    end,
    [0x88] = function(ins, stack, frame) -- i64.shr_u
        local n2 = pop(stack).l % 64
        local n1 = pop(stack)
        if n2 == 0 then
            push(stack, {
                l = n1.l,
                h = n1.h,
            })
        elseif n2 < 32 then
            local l = bit.bor(bit.lshift(n1.h, 32 - n2), bit.rshift(n1.l, n2))
            push(stack, {
                l = l,
                h = bit.rshift(n1.h, n2)
            })
        elseif n2 == 32 then
            push(stack, {
                l = n1.h,
                h = 0
            })
        else
            push(stack, {
                l = bit.rshift(n1.h, n2 - 32),
                h = 0
            })
        end
    end,
    [0x89] = function(ins, stack, frame) -- i64.rotl
        local n2 = pop(stack).l % 64
        local n1 = pop(stack)
        if n2 == 0 then
            push(stack, n1)
        elseif n2 < 32 then
            local l = bit.bor(bit.lshift(n1.h, 32 - n2), bit.rshift(n1.l, n2))
            local h = bit.bor(bit.lshift(n1.l, 32 - n2), bit.rshift(n1.h, n2))
            push(stack, {
                l = l,
                h = h,
            })
        elseif n2 == 32 then
            push(stack, {
                l = n1.h,
                h = n1.l,
            })
        else
            n2 = n2 - 32
            local l = bit.bor(bit.lshift(n1.h, 32 - n2), bit.rshift(n1.l, n2))
            local h = bit.bor(bit.lshift(n1.l, 32 - n2), bit.rshift(n1.h, n2))
            push(stack, {
                l = h,
                h = l,
            })
        end
    end,
    [0x8B] = function(ins, stack, frame) -- (f32/f64).abs
        local n = pop(stack)
        push(stack, math.abs(n))
    end,
    [0x8C] = function(ins, stack, frame) -- (f32/f64).neg
        local n = pop(stack)
        push(stack, -n)
    end,
    [0x92] = function(ins, stack, frame) -- (f32/f64).add
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 + n2)
    end,
    [0x93] = function(ins, stack, frame) -- (f32/f64).sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 - n2)
    end,
    [0x94] = function(ins, stack, frame) -- (f32/f64).mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 * n2)
    end,
    [0x95] = function(ins, stack, frame) -- (f32/f64).div
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 / n2)
    end,
    [0xA7] = function(ins, stack, frame) -- i32.wrap_i64
        push(stack, pop(stack).l)
    end,
    [0xAC] = function(ins, stack, frame) -- i64.extend_i32_s
        local n = pop(stack)
        push(stack, { l = n, h = bit.arshift(n, 31) })
    end,
    [0xAD] = function(ins, stack, frame) -- i64.extend_i32_u
        local n = pop(stack)
        push(stack, { l = n, h = 0 })
    end,
    [0xB5] = function(ins, stack, frame) -- (f32/f64).convert_i64_u
        local n = pop(stack)
        local res = n.h * 4294967296 + n.l
        push(stack, res)
    end,
    [0xBC] = function(ins, stack, frame) -- i32.reinterpret_f32
        local n = pop(stack)
        push(stack, bit_conv.FloatToUInt32(n))
    end,
    [0xBD] = function(ins, stack, frame) -- i64.reinterpret_f64
        local n = pop(stack)
        local low, high = bit_conv.DoubleToUInt32s(n)
        push(stack, {
            l = low,
            h = high
        })
    end,
    [0xBE] = function(ins, stack, frame) -- f32.reinterpret_i32
        local n = pop(stack)
        push(stack, bit_conv.UInt32ToFloat(n))
    end,
    [0xBF] = function(ins, stack, frame) -- f64.reinterpret_i64
        local n = pop(stack)
        push(stack, bit_conv.UInt32sToDouble(n.l, n.h))
    end,
    -- EXTRA INSTRUCTIONS ----------------------------
    [0xFC] = function(ins, stack, frame, labels, module, frame_cache)
        local ei = extra_instructions[ins[2]]
        if ei == nil then
            error("missing instruction for 0xFC " .. tostring(ins[2]))
        end
        ei(ins, stack, frame, labels, module, frame_cache)
    end
}
instructions[0x1C] = instructions[0x1B]
instructions[0x42] = instructions[0x41]
instructions[0x43] = instructions[0x41]
instructions[0x44] = instructions[0x41]


for x = 0x5B, 0x60 do
    instructions[x + 6] = instructions[x]
end
for x = 0x8B, 0x98 do
    instructions[x + 14] = instructions[x]
end
for x = 0xB2, 0xB6 do
    instructions[x + 5] = instructions[x]
end

extra_instructions = {
    [8] = function(ins, stack, frame, labels, module) -- memory.init
        local y = ins[3]
        local x = ins[4]
        local mem = module.store.mems[x + 1]
        local da = module.store.datas[y + 1]
        local n = pop(stack)
        local s = pop(stack)
        local d = pop(stack)
        while true do
            if s + n > #da.data or d + n > #mem.data then
                error("trap")
            end
            if n == 0 then
                return
            end
            local b = da.data[s + 1]
            push(stack, d)
            push(stack, b)
            instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame, labels, module) -- i32.store8
            d = d + 1
            s = s + 1
            n = n - 1
        end
    end,
    [9] = function(ins, stack, frame, labels, module) -- data.drop
        local x = ins[3]
        module.store.datas[x + 1] = { data = {} }
    end,
    [10] = function(ins, stack, frame, labels) -- memory.copy
        local mem = module.store.mems[1] -- cant tell which arg is to and which is from
        local n = pop(stack)
        local s = pop(stack)
        local d = pop(stack)
        if s + n > #mem.data or d + n > #mem.data then
            error("trap")
        end
        while n ~= 0 do
            if d <= s then
                push(stack, d)
                push(stack, s)
                instructions[0x3A]({ 0x2D, { 0, 0 } }, stack, frame) -- i32.load8_u
                instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame) -- i32.store8
                d = d + 1
                s = s + 1
            else
                push(stack, d + n - 1)
                push(stack, s + n - 1)
                instructions[0x3A]({ 0x2D, { 0, 0 } }, stack, frame) -- i32.load8_u
                instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame) -- i32.store8
            end
            n = n - 1
        end
    end,
    [11] = function(ins, stack, frame, labels, module) -- memory.fill
        local mem = module.store.mems[ins[3] + 1]
        local n = pop(stack)
        local val = pop(stack)
        local d = pop(stack)
        if d + n > #mem.data then
            error("trap")
        end
        while n ~= 0 do
            push(stack, d)
            push(stack, val)
            eval_single_with({ 0x38, { 0, 0 } }, stack, frame, labels) -- i32.store8
            n = n - 1
            d = d + 1
        end
    end,
    [12] = function(ins, stack, frame, labels, module) -- table.init
        local y = ins[3]
        local x = ins[4]
        local tab = module.store.tables[x + 1]
        local elem = module.store.elems[y + 1]
        local n = pop(stack)
        local s = pop(stack)
        local d = pop(stack)
        while true do
            if s + n > #elem.elem or d + n > #tab.elem then
                error("trap")
            end
            if n == 0 then
                return
            end
            local val = elem.elem[s + 1]
            push(stack, d)
            push(stack, val)
            eval_single_with({ 0x26, x }, stack, frame, labels, module) -- table.set
            d = d + 1
            s = s + 1
            n = n - 1
        end
    end,
    [13] = function(ins, stack, frame, labels, module) -- elem.drop
        local x = ins[3]
        module.store.elems[x + 1] = { elem = {}, type = module.store.elems[x + 1].type }
    end,
    [14] = function(ins, stack, frame, labels) -- table.copy
        local tab_x = module.store.tables[ins[3] + 1]
        local tab_y = module.store.tables[ins[4] + 1]
        local n = pop(stack)
        local s = pop(stack)
        local d = pop(stack)
        if s + n > #tab_y.elem or d + n > #tab_x.elem then
            error("trap")
        end
        while n ~= 0 do
            if d <= s then
                push(stack, d)
                push(stack, s)
                eval_single_with({ 0x25, ins[4] }, stack, frame, labels)
                eval_single_with({ 0x26, ins[3] }, stack, frame, labels)
                d = d + 1
                s = s + 1
            else
                push(stack, d + n - 1)
                push(stack, s + n - 1)
                eval_single_with({ 0x25, ins[4] }, stack, frame, labels)
                eval_single_with({ 0x26, ins[3] }, stack, frame, labels)
            end
            n = n + 1
        end
    end,
    [15] = function(ins, stack, frame, labels, module) -- table.grow
        local tab = module.store.tables[ins[3] + 1]
        local n = pop(stack)
        local val = pop(stack)
        if tab.type.max and #tab.elem + n > tab.type.max then
            push(stack, -1)
        else
            local start_size = #tab.elem
            for x = 1, n do
                tab.elem[start_size + x] = val
            end
            push(stack, start_size)
        end
    end,
    [16] = function(ins, stack, frame, labels, module) -- table.size
        push(stack, module.store.tables[ins[3] + 1].elem)
    end,
    [17] = function(ins, stack, frame, labels, module) -- table.fill
        local tab = module.store.tables[ins[3] + 1]
        local n = pop(stack)
        local val = pop(stack)
        local i = pop(stack)
        if n + i > #tab.elem then
            error("trap")
        end
        while n ~= 0 do
            push(stack, i)
            push(stack, val)
            eval_single_with({ 0x26, ins[3] }, stack, frame, labels)
            i = i + 1
            n = n - 1
        end
    end,
}

-- assumes that the expression is a constant expression that does not rely on having an available frame
local function simple_eval(expr)
    local stack = {}
    for _, ins in ipairs(expr[1]) do
        local i = instructions[ins[1]]
        if i == nil then
            error(string.format("missing instruction %X", ins[1]))
        end
        i(ins, stack, nil, nil)
    end
    return pop(stack)
end

local function simple_list_eval(exprs)
    local results = {}
    for i, expr in pairs(exprs) do
        results[i] = simple_eval(expr)
    end
    return results
end

eval_instructions_with = function(ins, stack, frame, labels, module)
    for _, sins in ipairs(ins) do
        local i = instructions[sins[1]]
        if i == nil then
            error(string.format("missing instruction 0x%X", sins[1]))
        end
        local r, p = i(sins, stack, frame, labels, module)
        if r then return r, p end
    end
end

eval_single_with = function(ins, stack, frame, labels, module)
    local i = instructions[ins[1]]
    if i == nil then
        error(string.format("missing instruction %x", ins[1]))
    end
    return i(ins, stack, frame, labels, module)
end

local function find_func_name(func_addr, module)
    if func_addr == "root" then
        return "\"some lua thing\""
    end
    return "???"
end

local debug_module

local function set_debug_module(module)
    debug_module = module
end

local function raise_error(err, stack, frames, labels, module)
    io.write("trap: ", err, "\nStacktrace:\n")
    for x = #frames, 1, -1 do
        local name = "???"
        if frames[x].func_addr == "root" then
            name = "(lua code)"
        elseif debug_module and module.debug_info then
            name = debug_module.get_function_name(module.debug_info, frames[x].func_addr) or "???"
        end
        io.write("$", x, " = func_addr ", frames[x].func_addr, " named ", name, "\n")
    end
end

local function full_eval(module, funcaddr, opt_start_stack)
    local stack = opt_start_stack or {}
    local frames = { { module = module, func_addr = "root" } }
    local labels = {}
    local current_frame_cache = top(frames)
    invoke(funcaddr, stack, frames, labels, module, current_frame_cache)
    current_frame_cache = top(frames)
    current_frame_cache.ins_ptr = current_frame_cache.ins_ptr + 1
    while true do
        local ins = current_frame_cache.func.body[current_frame_cache.ins_ptr]
        local ins_func = ins[0]
        local error = ins_func(ins, stack, frames, labels, module, current_frame_cache)
        if error == true then
            current_frame_cache = top(frames)
            error = nil
        end
        if frames[2] == nil then
            return stack
        end
        current_frame_cache.ins_ptr = current_frame_cache.ins_ptr + 1
        if error then
            raise_error(error, stack, frames, labels, module)
            return nil, -2, error
        end
    end
end

local function pre_lookup_instructions(module)
    for _, func in pairs(module.funcs) do
        for _, ins in pairs(func.body) do
            local li = instructions[ins[1]]
            if li == nil then
                error(string.format("missing instruction 0x%x", ins[1]))
            end
            ins[0] = li
        end
    end
end

local function fill_elems(module)
    local frame = { { module = module, locals = {} } }
    local stack = {}
    for idx, elem in pairs(module.elems) do
        if elem.mode == "active" then
            local n = #elem.init
            eval_instructions_with(elem.active_info.offset[1], stack, frame, {}, module)
            push(stack, 0)
            push(stack, n)
            eval_single_with({ 0xFC, 12, idx - 1, elem.active_info.table }, stack, frame, {}, module)
            eval_single_with({ 0xFC, 13, idx - 1 }, stack, frame, {}, module)
        end
    end
end

local function fill_datas(module)
    local frame = { { module = module, locals = {} } }
    local stack = {}
    for idx, data in pairs(module.datas) do
        if data.mode == "active" then
            local n = #data.init
            eval_instructions_with(data.active_info.offset[1], stack, frame, {}, module)
            push(stack, 0)
            push(stack, n)
            eval_single_with({ 0xFC, 8, idx - 1, data.active_info.memory }, stack, frame, {}, module)
            eval_single_with({ 0xFC, 9, idx - 1 }, stack, frame, {}, module)
        end
    end
end

local function call_start(module)
    if module.start and module.start.func then
        full_eval(module, module.start.func)
    end
end

local function call_function(module, funcidx, args)
    full_eval(module, funcidx, args)
    return (table.unpack or unpack)(args)
end

local function make_memory_interface(module, memidx, interface_export)
    function interface_export.read8(address)
        local stack = { address }
        eval_single_with({ 0x2D, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.read16(address)
        local stack = { address }
        eval_single_with({ 0x2F, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.read32(address)
        local stack = { address }
        eval_single_with({ 0x28, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.read64(address)
        local stack = { address }
        eval_single_with({ 0x29, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.write8(address, value)
        local stack = { address, value }
        eval_single_with({ 0x3A, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end

    function interface_export.write16(address, value)
        local stack = { address, value }
        eval_single_with({ 0x3B, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end

    function interface_export.write32(address, value)
        local stack = { address, value }
        eval_single_with({ 0x36, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end

    function interface_export.write64(address, value)
        local stack = { address, value }
        eval_single_with({ 0x37, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end

    function interface_export.readf32(address)
        local stack = { address }
        eval_single_with({ 0x2A, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.readf64(address)
        local stack = { address }
        eval_single_with({ 0x2B, { 0, 0 } }, stack, { { module = module } }, {}, module)
        return stack[1]
    end

    function interface_export.writef32(address, value)
        local stack = { address, value }
        eval_single_with({ 0x38, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end

    function interface_export.writef64(address, value)
        local stack = { address, value }
        eval_single_with({ 0x39, { 0, 0 } }, stack, { { module = module } }, {}, module)
    end
end

return {
    simple = simple_eval,
    simple_list = simple_list_eval,
    fill_elems = fill_elems,
    fill_datas = fill_datas,
    call_start = call_start,
    call_function = call_function,
    make_memory_interface = make_memory_interface,
    full_eval = full_eval,
    pre_lookup_instructions = pre_lookup_instructions,
    set_debug_module = set_debug_module,
}
