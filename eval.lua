local require_path = (...):match("(.-)[^%.]+$")
local bit = require(require_path .. "bitops")
local serpent = require(require_path .. "serpent")
local bc = require(require_path .. "bytecode")

local function simple_nop() end

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

local bool_to_num = {
    [true] = 1,
    [false] = 0
}

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

local function store_to(ins, stack, frame, bytes, module, labels, frame_cache, next_ins, next_ins_data, ...)
    local mem, ea, error = find_mem_address(ins, stack, frame, #bytes * 8, module)
    if error then return error end
    for x = 1, #bytes do
        mem.data[ea + x] = bytes[x]
    end
    return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
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
        stack_height = #stack, label_height = #labels, decoded_instructions = new_f.decoded_instruction_cache }
    push(frame, new_frame)
    push(labels, { type = new_f.type, is_function = true, stack_height = #stack })
    return true
end

local function i64_ge_u(n1, n2)
    if n1.h > n2.h then
        return 1
    elseif n1.h == n2.h then
        return bool_to_num[n1.l >= n2.l]
    else
        return 0
    end
end

local function i64_gt_u(n1, n2)
    if n1.h > n2.h then
        return 1
    elseif n1.h == n2.h then
        return bool_to_num[n1.l > n2.l]
    else
        return 0
    end
end

local function i64_le_u(n1, n2)
    if n1.h < n2.h then
        return 1
    elseif n1.h == n2.h then
        return bool_to_num[n1.l <= n2.l]
    else
        return 0
    end
end

local function i64_add(n1, n2)
    local low = n1.l + n2.l
    local high = n1.h + n2.h + bool_to_num[low >= 4294967296]
    return {
        l = bit.band(low, 0xFFFFFFFF),
        h = bit.band(high, 0xFFFFFFFF)
    }
end

local function i64_sub(n1, n2)
    local low = n1.l - n2.l
    local high = n1.h - n2.h - bool_to_num[low < 0]
    return {
        l = bit.inv_signed(32, low),
        h = bit.inv_signed(32, high)
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
    [0x01] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- noop
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x02] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- block,  br skips
        local new_label = expand_type(ins[2], module)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + ins[3], stack_height = #stack })
    end,
    [0x03] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- loop
        -- br loops again
        local new_label = expand_type(ins[2], module)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + 1, stack_height = #stack })
    end,
    [0x04] = function(ins, stack, frame, labels, module) -- if else
        local new_label = expand_type(ins, module)
        local c = pop(stack)
        push(labels, { type = new_label, break_pos = top(frame).ins_ptr + ins[3], stack_height = #stack })
        if c == 0 then
            top(frame).ins_ptr = top(frame).ins_ptr + ins[4]
        end
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
    [0xD0] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- ref.null
        push(stack, 0)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xD1] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- ref.is_null
        local val = pop(stack)
        push(stack, bool_to_num[val == 0])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xD2] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- ref.func
        --[[
            from my current understanding:
            currently only one module can be loaded, so no lookup is required
            NOTE: turns out i misunderstood the spec, yeah, multiple modules can be loaded, we just don't support it
        ]]
        push(stack, ins[2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- PARAMETRIC INSTRUCTIONS -----------------------
    [0x1A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- drop
        pop(stack)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x1B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- select
        local selector = pop(stack)
        local val2 = pop(stack)
        local val1 = pop(stack)
        push(stack, ({
            [true] = val1,
            [false] = val2,
        })[selector ~= 0])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- VARIABLE INSTRUCTIONS -------------------------
    [0x20] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- local.get
        push(stack, frame_cache.locals[ins[2] + 1])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x21] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- local.set
        frame_cache.locals[ins[2] + 1] = pop(stack)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x22] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- local.tee
        frame_cache.locals[ins[2] + 1] = stack[#stack]
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x23] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- global.get
        push(stack, module.store.globals[ins[2] + 1].val)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x24] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- global.set
        module.store.globals[ins[2] + 1].val = pop(stack)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- TABLE INSTRUCTIONS ----------------------------
    [0x25] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.get
        local tab = module.store.tables[ins[2] + 1]
        local i = pop(stack)
        if i >= #tab.elem then
            error("trap")
        end
        push(stack, tab.elem[i + 1])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x26] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.set
        local x = ins[2]
        local tab = module.store.tables[x + 1]
        local val = pop(stack)
        local i = pop(stack)
        if i >= #tab.elem then
            error("trap")
        end
        tab.elem[i + 1] = val
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- MEMORY INSTRUCTIONS ---------------------------
    [0x28] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.load
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, bit.UInt8sToUInt32((table.unpack or unpack)(bytes)))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x29] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load
        local bytes, error = load_from(ins, stack, frame, 64, module)
        if error then return error end
        push(stack, {
            l = bit.UInt8sToUInt32((table.unpack or unpack)(bytes, 1, 4)),
            h = bit.UInt8sToUInt32((table.unpack or unpack)(bytes, 5, 8))
        })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.load
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, bit.UInt32ToFloat(bit.UInt8sToUInt32((table.unpack or unpack)(bytes))))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f64.load
        local bytes, error = load_from(ins, stack, frame, 64, module)
        if error then return error end
        push(stack, bit.UInt32sToDouble(
            bit.UInt8sToUInt32((table.unpack or unpack)(bytes, 1, 4)),
            bit.UInt8sToUInt32((table.unpack or unpack)(bytes, 5, 8))
        ))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.load8_s
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, bit.extend(8, 32, bytes[1]))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.load8_u
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, bytes[1])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.load16_s
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, bit.extend(16, 32, bit.UInt8sToUInt16((table.unpack or unpack)(bytes))))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x2F] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.load16_u
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, bit.UInt8sToUInt16((table.unpack or unpack)(bytes)))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x30] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load8_s
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        if bit.band(bytes[1], 0x80) ~= 0 then
            push(stack, { l = bit.extend(8, 32, bytes[1]), h = 0xFFFFFFFF })
        else
            push(stack, { l = bytes[1], h = 0 })
        end
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x31] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load8_u
        local bytes, error = load_from(ins, stack, frame, 8, module)
        if error then return error end
        push(stack, { l = bytes[1], h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x32] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load16_s
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        local raw_num = bit.UInt8sToUInt16((table.unpack or unpack)(bytes))
        if bit.band(raw_num, 0x8000) ~= 0 then
            push(stack, { l = bit.extend(16, 32, raw_num), h = 0xFFFFFFFF })
        else
            push(stack, { l = raw_num, h = 0 })
        end
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x33] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load16_u
        local bytes, error = load_from(ins, stack, frame, 16, module)
        if error then return error end
        push(stack, { l = bit.UInt8sToUInt16((table.unpack or unpack)(bytes)), h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x34] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load32_s
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        local raw_num = bit.UInt8sToUInt32((table.unpack or unpack)(bytes))
        if bit.band(raw_num, 0x80000000) ~= 0 then
            push(stack, { l = raw_num, h = 0xFFFFFFFF })
        else
            push(stack, { l = raw_num, h = 0 })
        end
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x35] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.load32_u
        local bytes, error = load_from(ins, stack, frame, 32, module)
        if error then return error end
        push(stack, { l = bit.UInt8sToUInt32((table.unpack or unpack)(bytes)), h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x36] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.store
        local c = pop(stack)
        local bytes = { bit.UInt32ToUInt8s(c) }
        return store_to(ins, stack, frame, bytes, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x37] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.store
        local c = pop(stack)
        local u80, u81, u82, u83 = bit.UInt32ToUInt8s(c.l)
        local u84, u85, u86, u87 = bit.UInt32ToUInt8s(c.h)
        return store_to(ins, stack, frame, { u80, u81, u82, u83, u84, u85, u86, u87 }, module, labels, frame_cache,
            next_ins, next_ins_data, ...)
    end,
    [0x38] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.store
        local c = pop(stack)
        return store_to(ins, stack, frame, { bit.UInt32ToUInt8s(bit.FloatToUInt32(c)) }, module, labels,
            frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x39] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f64.store
        local c = pop(stack)
        local l, h = bit.DoubleToUInt32s(c)
        local u80, u81, u82, u83 = bit.UInt32ToUInt8s(l)
        local u84, u85, u86, u87 = bit.UInt32ToUInt8s(h)
        return store_to(ins, stack, frame, { u80, u81, u82, u83, u84, u85, u86, u87 }, module, labels, frame_cache,
            next_ins, next_ins_data, ...)
    end,
    [0x3A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.store8
        local c = pop(stack)
        local u80, _, _, _ = bit.UInt32ToUInt8s(c)
        return store_to(ins, stack, frame, { u80 }, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x3B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.store16
        local c = pop(stack)
        local u80, u81, _, _ = bit.UInt32ToUInt8s(c)
        return store_to(ins, stack, frame, { u80, u81 }, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x3C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.store8
        local c = pop(stack)
        local u80, _, _, _ = bit.UInt32ToUInt8s(c.l)
        return store_to(ins, stack, frame, { u80 }, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x3D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.store16
        local c = pop(stack)
        local u80, u81, _, _ = bit.UInt32ToUInt8s(c.l)
        return store_to(ins, stack, frame, { u80, u81 }, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x3E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.store32
        local c = pop(stack)
        local bytes = { bit.UInt32ToUInt8s(c.l) }
        return store_to(ins, stack, frame, bytes, module, labels, frame_cache, next_ins, next_ins_data, ...)
    end,
    [0x3F] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- memory.size
        local m = ins[2]
        local mem = module.store.mems[m + 1]
        push(stack, #mem.data / 65536)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x40] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- memory.grow
        local mem = module.store.mems[ins[2] + 1]
        local sz = #mem.data / 65536
        local n = pop(stack)
        if mem.type.max and mem.type.max < sz + n then
            push(stack, bit.inv_signed(32, -1))
            return
        end
        local curr_index = sz * 65536
        for x = curr_index, curr_index + n * 65536 do
            mem.data[x] = 0
        end
        push(stack, sz)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- NUMERICS -----------------------------
    [0x41] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.const, i64.const, f32.const, f64.const
        push(stack, ins[2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x45] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.eqz
        local n = pop(stack)
        push(stack, bool_to_num[n == 0])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x46] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 == n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x47] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 ~= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x48] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.lt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[bit.signed(32, n1) < bit.signed(32, n2)])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x49] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.lt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 < n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.gt_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[bit.signed(32, n1) > bit.signed(32, n2)])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.gt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 > n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.le_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[bit.signed(32, n1) <= bit.signed(32, n2)])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.le_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 <= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.ge_s
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[bit.signed(32, n1) >= bit.signed(32, n2)])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x4F] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.ge_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 >= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x50] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.eqz
        local n = pop(stack)
        push(stack, bool_to_num[n.l == 0 and n.h == 0])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x51] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1.l == n2.l and n1.h == n2.h])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x52] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1.l ~= n2.l or n1.h ~= n2.h])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x53] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.lt_s
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x54] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.lt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n1.h < n2.h then
            push(stack, 1)
        elseif n1.h == n2.h then
            push(stack, bool_to_num[n1.l < n2.l])
        else
            push(stack, 0)
        end
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x55] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.gt_s
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x56] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.gt_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_gt_u(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x57] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.le_s
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x58] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.le_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_le_u(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x59] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.ge_s
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.ge_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_ge_u(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.eq
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 == n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.ne
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 ~= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.lt
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 < n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.gt
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 > n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x5F] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.le
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 <= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x60] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.ge
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bool_to_num[n1 >= n2])
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x67] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.clz
        local n = pop(stack)
        push(stack, bit.clz(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x68] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.ctz
        local n = pop(stack)
        push(stack, bit.ctz(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x69] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.popcnt
        local n = pop(stack)
        push(stack, __POPCNT__(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6A] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.add
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1 + n2, 0xFFFFFFFF))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.inv_signed(32, n1 - n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1 * n2, 0xFFFFFFFF))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.div_s
        local n2 = bit.signed(32, pop(stack))
        local n1 = bit.signed(32, pop(stack))
        if n2 == 0 then
            error("trap, i32.div_s div by 0")
        end
        local res = bit.trunc(n1 / n2)
        if res == math.pow(2, 31) then
            error("trap, division resulted in 2^31")
        end
        push(stack, bit.inv_signed(32, res))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.div_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n2 == 0 then
            error("trap, i32.div_s div by 0")
        end
        push(stack, math.floor(n1 / n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x6F] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.rem_s
        local n2 = bit.signed(32, pop(stack))
        local n1 = bit.signed(32, pop(stack))
        if n2 == 0 then
            error("trap, i32.rem_u div by zero")
        end
        push(stack, bit.inv_signed(32, n1 - n2 * bit.trunc(n1 / n2)))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x70] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.rem_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        if n2 == 0 then
            error("trap, i32.rem_u div by zero")
        end
        push(stack, n1 - n2 * bit.trunc(n1 / n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x71] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.and
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.band(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x72] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.or
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.bor(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x73] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.xor
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, bit.bxor(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x74] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.shl
        local n2 = bit.band(pop(stack), 31)
        local n1 = pop(stack)
        push(stack, bit.band(bit.lshift(n1, n2), 0xFFFFFFFF))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x75] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.shr_s
        local n2 = bit.band(pop(stack), 31)
        local n1 = pop(stack)
        push(stack, bit.arshift(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x76] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.shr_u
        local n2 = bit.band(pop(stack), 31)
        local n1 = pop(stack)
        push(stack, bit.rshift(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x77] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.rotl
        local n2 = bit.band(pop(stack), 31)
        local n1 = pop(stack)
        push(stack, bit.lrotate(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x79] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.clz
        local n = pop(stack)
        local result = (n.h ~= 0) and bit.clz(n.h) or 32 + bit.clz(n.l)
        push(stack, { l = result, h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x7a] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.ctz
        local n = pop(stack)
        local result = (n.l ~= 0) and bit.ctz(n.l) or 32 + bit.ctz(n.h)
        push(stack, { l = result, h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x7C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.add
        local b = pop(stack)
        local a = pop(stack)
        push(stack, i64_add(a, b))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x7D] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_sub(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x7E] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, i64_mul(n1, n2))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x80] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.div_u
        local n2 = pop(stack)
        local n1 = pop(stack)
        local res, rem = i64_div_core(n1, n2)
        push(stack, res)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x83] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.and
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.band(n1.l, n2.l),
            h = bit.band(n1.h, n2.h)
        })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x84] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.or
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.bor(n1.l, n2.l),
            h = bit.bor(n1.h, n2.h)
        })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x85] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.xor
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, {
            l = bit.bxor(n1.l, n2.l),
            h = bit.bxor(n1.h, n2.h)
        })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x86] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.shl
        local n2 = bit.band(pop(stack).l, 63)
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x87] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.shr_s
        local n2 = bit.band(pop(stack).l, 63)
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x88] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.shr_u
        local n2 = bit.band(pop(stack).l, 63)
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x89] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.rotl
        local n2 = bit.band(pop(stack).l, 63)
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x8B] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).abs
        local n = pop(stack)
        push(stack, math.abs(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x8C] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).neg
        local n = pop(stack)
        push(stack, -n)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x92] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).add
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 + n2)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x93] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).sub
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 - n2)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x94] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).mul
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 * n2)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0x95] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).div
        local n2 = pop(stack)
        local n1 = pop(stack)
        push(stack, n1 / n2)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xA7] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.wrap_i64
        push(stack, pop(stack).l)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xAC] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.extend_i32_s
        local n = pop(stack)
        push(stack, { l = n, h = bit.arshift(n, 31) })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xAD] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.extend_i32_u
        local n = pop(stack)
        push(stack, { l = n, h = 0 })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xB5] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- (f32/f64).convert_i64_u
        local n = pop(stack)
        local res = n.h * 4294967296 + n.l
        push(stack, res)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xBC] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i32.reinterpret_f32
        local n = pop(stack)
        push(stack, bit.FloatToUInt32(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xBD] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- i64.reinterpret_f64
        local n = pop(stack)
        local low, high = bit.DoubleToUInt32s(n)
        push(stack, {
            l = low,
            h = high
        })
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xBE] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f32.reinterpret_i32
        local n = pop(stack)
        push(stack, bit.UInt32ToFloat(n))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [0xBF] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- f64.reinterpret_i64
        local n = pop(stack)
        push(stack, bit.UInt32sToDouble(n.l, n.h))
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    -- EXTRA INSTRUCTIONS ----------------------------
    [0xFC] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...)
        local ei = extra_instructions[ins[2]]
        if ei == nil then
            error("missing instruction for 0xFC " .. tostring(ins[2]))
        end
        return ei(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...)
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
    [8] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- memory.init
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
                return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
            end
            local b = da.data[s + 1]
            push(stack, d)
            push(stack, b)
            instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame, labels, module, nil, simple_nop) -- i32.store8
            d = d + 1
            s = s + 1
            n = n - 1
        end
    end,
    [9] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- data.drop
        local x = ins[3]
        module.store.datas[x + 1] = { data = {} }
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [10] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- memory.copy
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
                instructions[0x3A]({ 0x2D, { 0, 0 } }, stack, frame, nil, nil, nil, simple_nop) -- i32.load8_u
                instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame, nil, nil, nil, simple_nop) -- i32.store8
                d = d + 1
                s = s + 1
            else
                push(stack, d + n - 1)
                push(stack, s + n - 1)
                instructions[0x3A]({ 0x2D, { 0, 0 } }, stack, frame, nil, nil, nil, simple_nop) -- i32.load8_u
                instructions[0x3A]({ 0x3A, { 0, 0 } }, stack, frame, nil, nil, nil, simple_nop) -- i32.store8
            end
            n = n - 1
        end
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [11] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- memory.fill
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [12] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.init
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
                return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
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
    [13] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- elem.drop
        local x = ins[3]
        module.store.elems[x + 1] = { elem = {}, type = module.store.elems[x + 1].type }
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [14] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.copy
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [15] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.grow
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [16] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.size
        push(stack, module.store.tables[ins[3] + 1].elem)
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
    end,
    [17] = function(ins, stack, frame, labels, module, frame_cache, next_ins, next_ins_data, ...) -- table.fill
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
        return next_ins(next_ins_data, stack, frame, labels, module, frame_cache, ...)
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
        i(ins, stack, nil, nil, nil, nil, simple_nop)
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
        local r, p = i(sins, stack, frame, labels, module, nil, simple_nop)
        if r then return r, p end
    end
end

eval_single_with = function(ins, stack, frame, labels, module)
    local i = instructions[ins[1]]
    if i == nil then
        error(string.format("missing instruction %x", ins[1]))
    end
    return i(ins, stack, frame, labels, module, nil, simple_nop)
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

local function create_bool_to_num(bytecode)
    local bool_to_num_idx, bool_to_num = bytecode:new_table_template()
    bool_to_num.narray = 0
    bool_to_num.nhash = 2
    bool_to_num.hash_keys = { true, false }
    bool_to_num.hash_values = { 1, 0 }
    return bool_to_num_idx
end

local function create_i64(bytecode, i64)
    local i64_idx, i64_table = bytecode:new_table_template()
    i64_table.narray = 2
    i64_table.nhash = 0
    i64_table.array = { i64.l, i64.h }
    return i64_idx
end

local function load_memory_array(bytecode, target_location)
    bytecode:op_tget(target_location, 0, "S", bytecode:const("store"))
    bytecode:op_tget(target_location, target_location, "S", bytecode:const("mems"))
    bytecode:emit(bc.BC.TGETB, target_location, target_location, 1)
    bytecode:op_tget(target_location, target_location, "S", bytecode:const("data"))
end

local function load_bytes_from_mem(bytecode, address, memory_location, target_location, scratch, offset, byte_count)
    bytecode:op_load(scratch, offset)
    bytecode:op_add(scratch, scratch, address)
    bytecode:op_load(target_location, 0)
    for x = 1, byte_count do
        bytecode:emit(bc.BC.ADDVN, scratch + 3, scratch, bytecode:const(x))
        bytecode:emit(bc.BC.TGETV, scratch + 3, memory_location, scratch + 3)
        bytecode:op_tget(scratch + 1, 1, "S", bytecode:const("lshift"))
        bytecode:op_load(scratch + 4, (x - 1) * 8)
        bytecode:op_call(scratch + 1, 1, 2)
        bytecode:emit(bc.BC.ADDVV, target_location, target_location, scratch + 1)
    end
end

local function store_bytes_to_mem(bytecode, address, memory_location, value_location, scratch, offset, byte_count)
    bytecode:op_load(scratch, offset)
    bytecode:op_add(scratch, scratch, address)
    for x = 1, byte_count do
        bytecode:op_gget(scratch + 1, "tonumber")
        bytecode:op_tget(scratch + 3, 1, "S", bytecode:const("band"))
        bytecode:op_tget(scratch + 5, 1, "S", bytecode:const("rshift"))
        bytecode:op_move(scratch + 7, value_location)
        bytecode:op_load(scratch + 8, (x - 1) * 8)
        bytecode:op_call(scratch + 5, 1, 2)
        bytecode:op_load(scratch + 6, 0xff)
        bytecode:op_call(scratch + 3, 1, 2)
        bytecode:op_call(scratch + 1, 1, 1)
        bytecode:emit(bc.BC.ADDVN, scratch + 2, scratch, bytecode:const(x))
        bytecode:emit(bc.BC.TSETV, scratch + 1, memory_location, scratch + 2)
    end
end

local function emit_bool_to_num_lookup(bytecode, target, scratch, basename, should_print)
    bytecode:jump(basename .. "t", scratch)
    bytecode:op_load(target, false)
    bytecode:jump(basename .. "f", scratch)
    bytecode:here(basename .. "t")
    bytecode:op_load(target, true)
    bytecode:here(basename .. "f")
    bytecode:op_tdup(scratch, 0)
    bytecode:emit(bc.BC.TGETV, target, scratch, target)
end

local compile_instruction = {
    -- CONTROL INSTRUCTIONS ---------------------
    [0x00] = function(bytecode, exec_data, instruction, ins_ptr) -- unreachable
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_gget(stack_top, "error")
        bytecode:op_load(stack_top + 2, "trap: unreachable")
        bytecode:op_call(stack_top, 0, 1)
    end,
    [0x01] = function(bytecode, exec_data, instruction, ins_ptr) -- noop
    end,
    [0x02] = function(bytecode, exec_data, instruction, ins_ptr) -- block
        local type = expand_type(instruction[2], exec_data.module)
        local stack_top = #exec_data.stack_data
        local label = {
            break_point = tostring(ins_ptr),
            type = type,
            result_type = type.to,
            continue_at_end = true,
            stack_height = stack_top + exec_data.stack_start - #type.from
        }
        push(exec_data.labels, label)

        -- validation
        for k, v in ipairs(label.type.from) do
            assert(exec_data.stack_data[stack_top - #label.type.from + k] == v,
                "validation failed! values on the stack are of the wrong type for the block instruction! (func_addr: " ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. label.break_point .. ")")
        end
    end,
    [0x03] = function(bytecode, exec_data, instruction, ins_ptr) -- loop
        local type = expand_type(instruction[2], exec_data.module)
        local stack_top = #exec_data.stack_data
        local label = {
            break_point = tostring(ins_ptr),
            type = type,
            result_type = type.from,
            stack_height = stack_top + exec_data.stack_start - #type.from
        }
        push(exec_data.labels, label)
        bytecode:here(label.break_point)

        -- validation
        for k, v in ipairs(label.type.from) do
            assert(exec_data.stack_data[stack_top - #label.type.from + k] == v,
                "validation failed! values on the stack are of the wrong type for the loop instruction! (func_addr: " ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. label.break_point .. ")")
        end
    end,
    [0x04] = function(bytecode, exec_data, instruction, ins_ptr) -- if
        local type = expand_type(instruction[2], exec_data.module)
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local label = {
            break_point = tostring(ins_ptr),
            branch_point = tostring(ins_ptr) .. "branch",
            type = type,
            result_type = type.to,
            continue_at_end = true,
            stack_height = stack_top + exec_data.stack_start - #type.from - 1
        }
        push(exec_data.labels, label)

        local top_type = pop(exec_data.stack_data)
        bytecode:emit(bc.BC.ISEQN, stack_top, bytecode:const(0))
        bytecode:jump(label.branch_point, stack_top)

        -- validation
        assert(top_type == "i32",
            "validation failed for if-else! value on top of the stack must be an i32! (func_addr: " ..
            tostring(exec_data.func_addr) .. ", ins_ptr: " .. label.break_point .. ")")

        stack_top = stack_top - 1
        for k, v in ipairs(label.type.from) do
            assert(exec_data.stack_data[stack_top - #label.type.from + k] == v,
                "validation failed! values on the stack are of the wrong type for the loop instruction! (func_addr: " ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. label.break_point .. ")")
        end
    end,
    [0x05] = function(bytecode, exec_data, instruction, ins_ptr) -- else
        local label = top(exec_data.labels)

        bytecode:jump(label.break_point, exec_data.stack_start + #exec_data.stack_data + 1)
        label.branch_taken_care_of = true
        bytecode:here(label.branch_point)

        -- massaging the stack
        while #exec_data.stack_data > label.stack_height do
            pop(exec_data.stack_data)
        end
        for x = 1, #label.type.from do
            push(exec_data.stack_data, label.type.from[x])
        end
    end,
    [0x0B] = function(bytecode, exec_data, instruction, ins_ptr) -- end
        local label = pop(exec_data.labels)

        if label.is_function then
            -- we seem to be at the end of a function
            bytecode:here(label.break_point)
            bytecode:op_ret(exec_data.stack_start + 1, #exec_data.returns)
            return
        end

        -- we can't assume the stack is in a correct state
        -- because a br may have happened
        while #exec_data.stack_data > label.stack_height do
            pop(exec_data.stack_data)
        end
        for x = 1, #label.type.from do
            push(exec_data.stack_data, label.type.to[x])
        end

        if label.continue_at_end then
            bytecode:here(label.break_point)
        end
        if label.branch_point and not label.branch_taken_care_of then
            bytecode:here(label.branch_point)
        end
    end,
    [0x0C] = function(bytecode, exec_data, instruction, ins_ptr) -- br
        local label = exec_data.labels[#exec_data.labels - instruction[2]]

        local return_count = #label.result_type

        local target_stack_height = label.stack_height + return_count
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local offset = stack_top - target_stack_height
        if offset ~= 0 then
            for x = 1, return_count do
                local current_location = stack_top - return_count + x
                bytecode:op_move(current_location - offset, current_location)
            end
        end
        bytecode:jump(label.break_point, stack_top - offset + 1)

        -- validation
        for k, v in ipairs(label.result_type) do
            assert(exec_data.stack_data[stack_top - #label.result_type + k] == v,
                "validation failed! values on the stack are of the wrong type for the br instruction! (func_addr: " ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. tostring(ins_ptr) .. ")")
        end
    end,
    [0x0D] = function(bytecode, exec_data, instruction, ins_ptr) -- br_if
        local label = exec_data.labels[#exec_data.labels - instruction[2]]

        local return_count = #label.result_type

        local target_stack_height = label.stack_height + return_count
        local test_var = pop(exec_data.stack_data)
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local offset = stack_top - target_stack_height

        if offset ~= 0 then
            local local_jump_name = tostring(ins_ptr)
            bytecode:emit(bc.BC.ISEQN, stack_top + 1, bytecode:const(0))
            bytecode:jump(local_jump_name, stack_top + 1)
            for x = 1, return_count do
                local current_location = stack_top - return_count + x
                bytecode:op_move(current_location - offset, current_location)
            end
            bytecode:jump(label.break_point, stack_top + 1 - offset)
            bytecode:here(local_jump_name)
        else
            bytecode:emit(bc.BC.ISNEN, stack_top + 1, bytecode:const(0))
            bytecode:jump(label.break_point, stack_top + 1)
        end

        -- validation
        assert(test_var == "i32",
            "validation failed for br_if! value on top of the stack must be an i32! (func_addr: " ..
            tostring(exec_data.func_addr) .. ", ins_ptr: " .. tostring(ins_ptr) .. ")")
        for k, v in ipairs(label.result_type) do
            assert(exec_data.stack_data[stack_top - #label.result_type + k] == v,
                "validation failed! values on the stack are of the wrong type for the br_if instruction! (func_addr: " ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. tostring(ins_ptr) .. ")")
        end
    end,
    [0x0E] = function(bytecode, exec_data, instruction, ins_ptr) -- br_table
        local fallback_label = exec_data.labels[#exec_data.labels - instruction[3]]

        local return_count = #fallback_label.result_type

        local basename = tostring(ins_ptr)

        local selector_var = pop(exec_data.stack_data)

        local fallback_target_stack_height = fallback_label.stack_height + return_count
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local fallback_offset = stack_top - fallback_target_stack_height

        if fallback_offset ~= 0 then
            local local_jump_name = basename .. "_fallback"
            bytecode:op_load(stack_top + 2, #instruction[2])
            bytecode:emit(bc.BC.ISLT, stack_top + 1, stack_top + 2)
            bytecode:jump(local_jump_name, stack_top + 2)
            for x = 1, return_count do
                local current_location = stack_top - return_count + x
                bytecode:op_move(current_location - fallback_offset, current_location)
            end
            bytecode:jump(fallback_label.break_point, stack_top + 1 - fallback_offset)
            bytecode:here(local_jump_name)
        else
            bytecode:op_load(stack_top + 2, #instruction[2])
            bytecode:emit(bc.BC.ISGE, stack_top + 1, stack_top + 2)
            bytecode:jump(fallback_label.break_point, stack_top + 2)
        end
        for x = 1, #instruction[2] do
            local label = exec_data.labels[#exec_data.labels - instruction[2][x]]
            local target_stack_height = label.stack_height + return_count
            local offset = stack_top - target_stack_height
            if offset ~= 0 then
                local local_jump_name = basename .. "_" .. tostring(x)
                bytecode:emit(bc.BC.ISNEN, stack_top + 1, bytecode:const(x - 1))
                bytecode:jump(local_jump_name, stack_top + 2)
                for y = 1, return_count do
                    local current_location = stack_top - return_count + y
                    bytecode:op_move(current_location - offset, current_location)
                end
                bytecode:jump(label.break_point, stack_top + 1)
                bytecode:here(local_jump_name)
            else
                bytecode:emit(bc.BC.ISEQN, stack_top + 1, bytecode:const(x - 1))
                bytecode:jump(label.break_point, stack_top + 2)
            end
        end
    end,
    [0x0F] = function(bytecode, exec_data, instruction, ins_ptr) -- return
        local return_count = #exec_data.returns

        local return_base = #exec_data.stack_data - return_count + 1

        for x = return_count, 1, -1 do
            local type = pop(exec_data.stack_data)

            -- sneaky validation
            assert(exec_data.returns[x] == type,
                "validation failed! values on the stack are of the wrong type for the return instruction! (func_addr: "
                ..
                tostring(exec_data.func_addr) .. ", ins_ptr: " .. tostring(ins_ptr) .. ")")
        end

        bytecode:op_ret(return_base + exec_data.stack_start, return_count)
    end,
    [0x10] = function(bytecode, exec_data, instruction, ins_ptr) -- call
        local func_addr = instruction[2] + 1
        local function_type = exec_data.module.store.funcs[func_addr].type

        local stack_top = #exec_data.stack_data + exec_data.stack_start

        -- grab the function
        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("compiled"))
        bytecode:op_load(stack_top + 2, func_addr)
        bytecode:emit(bc.BC.TGETV, stack_top + 1, stack_top + 1, stack_top + 2)

        -- push the module
        bytecode:op_move(stack_top + 3, 0)

        -- move arguments
        for x = 1, #function_type.from do
            bytecode:op_move(stack_top + 3 + x, stack_top - #function_type.from + x)
        end

        -- call
        bytecode:op_call(stack_top + 1, #function_type.to, #function_type.from + 1)

        -- move returns
        for x = 1, #function_type.to do
            bytecode:op_move(stack_top - #function_type.from + x, stack_top + x)
        end

        -- make sure to keep track of the stack! todo: add validation
        for x = #function_type.from, 1, -1 do
            pop(exec_data.stack_data)
        end
        for x = 1, #function_type.to do
            push(exec_data.stack_data, function_type.to[x])
        end
    end,
    [0x11] = function(bytecode, exec_data, instruction, ins_ptr) -- call_indirect
        local function_type = exec_data.module.types[instruction[2] + 1]

        local stack_top = #exec_data.stack_data + exec_data.stack_start

        -- grab the function
        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("store"))
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("tables"))
        bytecode:emit(bc.BC.TGETB, stack_top + 1, stack_top + 1, instruction[3] + 1)
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("elem"))
        bytecode:emit(bc.BC.TGETV, stack_top, stack_top + 1, stack_top)
        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("compiled"))
        bytecode:emit(bc.BC.ADDVN, stack_top, stack_top, bytecode:const(1))
        bytecode:emit(bc.BC.TGETV, stack_top, stack_top + 1, stack_top)

        stack_top = stack_top - 1

        -- push the module
        bytecode:op_move(stack_top + 3, 0)

        -- move arguments
        for x = 1, #function_type.from do
            bytecode:op_move(stack_top + 3 + x, stack_top - #function_type.from + x)
        end

        -- call
        bytecode:op_call(stack_top + 1, #function_type.to, #function_type.from + 1)

        -- move returns
        for x = 1, #function_type.to do
            bytecode:op_move(stack_top - #function_type.from + x, stack_top + x)
        end

        -- make sure to keep track of the stack! todo: add validation
        pop(exec_data.stack_data)
        for x = #function_type.from, 1, -1 do
            pop(exec_data.stack_data)
        end
        for x = 1, #function_type.to do
            push(exec_data.stack_data, function_type.to[x])
        end
    end,
    -- REFERENCE INSTRUCTIONS ----------------------- WARNING: untested, because no one uses them lol
    [0xD0] = function(bytecode, exec_data, instruction, ins_ptr) -- ref.null
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_load(stack_top + 1, 0)
        push(exec_data.stack_data, "reftype")
    end,
    [0xD1] = function(bytecode, exec_data, instruction, ins_ptr) -- ref.is_null
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local basename = tostring(ins_ptr)
        bytecode:emit(bc.BC.ISEQN, stack_top, bytecode:const(0))
        emit_bool_to_num_lookup(bytecode, stack_top, stack_top + 1, tostring(ins_ptr))
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0xD2] = function(bytecode, exec_data, instruction, ins_ptr) -- ref.func
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:load_op(stack_top, instruction[2])
        push(exec_data.stack_data, "reftype")
    end,
    -- PARAMETRIC INSTRUCTIONS -----------------------
    [0x1A] = function(bytecode, exec_data, instruction, ins_ptr) -- drop
        pop(exec_data.stack_data)
    end,
    [0x1B] = function(bytecode, exec_data, instruction, ins_ptr) -- select
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local basename = tostring(ins_ptr)
        bytecode:emit(bc.BC.ISNEN, stack_top, bytecode:const(0))
        bytecode:jump(basename, stack_top)
        bytecode:op_move(stack_top - 2, stack_top - 1)
        bytecode:here(basename)

        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    -- VARIABLE INSTRUCTIONS -------------------------
    [0x20] = function(bytecode, exec_data, instruction, ins_ptr) -- local.get
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        if exec_data.stashing_locals then
            bytecode:op_load(stack_top + 1, instruction[2])
            bytecode:emit(bc.BC.TGETV, stack_top + 1, 2, stack_top + 1)
        else
            bytecode:op_move(stack_top + 1, instruction[2] + 2)
        end
        if instruction[2] < #exec_data.args then
            push(exec_data.stack_data, exec_data.args[instruction[2] + 1])
        else
            push(exec_data.stack_data, exec_data.locals[instruction[2] - #exec_data.args + 1])
        end
    end,
    [0x21] = function(bytecode, exec_data, instruction, ins_ptr) -- local.set
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        if exec_data.stashing_locals then
            bytecode:op_load(stack_top + 1, instruction[2])
            bytecode:emit(bc.BC.TSETV, stack_top, 2, stack_top + 1)
        else
            bytecode:op_move(instruction[2] + 2, stack_top)
        end
        pop(exec_data.stack_data)
    end,
    [0x22] = function(bytecode, exec_data, instruction, ins_ptr) -- local.tee
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        if exec_data.stashing_locals then
            bytecode:op_load(stack_top + 1, instruction[2])
            bytecode:emit(bc.BC.TSETV, stack_top, 2, stack_top + 1)
        else
            bytecode:op_move(instruction[2] + 2, stack_top)
        end
    end,
    [0x23] = function(bytecode, exec_data, instruction, ins_ptr) -- global.get
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("store"))
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("globals"))
        bytecode:op_load(stack_top + 2, instruction[2] + 1)
        bytecode:emit(bc.BC.TGETV, stack_top + 1, stack_top + 1, stack_top + 2)
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("val"))

        push(exec_data.stack_data, exec_data.module.store.globals[instruction[2] + 1].type)
    end,
    [0x24] = function(bytecode, exec_data, instruction, ins_ptr) -- global.set
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("store"))
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("globals"))
        bytecode:op_load(stack_top + 2, instruction[2] + 1)
        bytecode:emit(bc.BC.TGETV, stack_top + 1, stack_top + 1, stack_top + 2)
        bytecode:op_tset(stack_top + 1, "S", bytecode:const("val"), stack_top)

        pop(exec_data.stack_data)
    end,
    -- TABLE INSTRUCTIONS ----------------------------
    -- unimplemented
    -- MEMORY INSTRUCTIONS ---------------------------
    [0x28] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.load
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            4
        )
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x29] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        bytecode:op_load(stack_top + 1, "line_" .. tostring(ins_ptr))

        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            4
        )
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 3,
            stack_top + 4,
            instruction[2][2] + 4,
            4
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("to_u64"))
        bytecode:op_call(stack_top, 1, 2)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x2A] = function(bytecode, exec_data, instruction, ins_ptr) -- f32.load
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 4,
            stack_top + 5,
            instruction[2][2],
            4
        )
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("UInt32ToFloat"))
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:op_move(stack_top, stack_top + 2)
        exec_data.stack_data[#exec_data.stack_data] = "f32"
    end,
    [0x2B] = function(bytecode, exec_data, instruction, ins_ptr) -- f64.load
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 4,
            stack_top + 5,
            instruction[2][2],
            4
        )
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 5,
            stack_top + 6,
            instruction[2][2] + 4,
            4
        )
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("UInt32sToDouble"))
        bytecode:op_call(stack_top + 2, 1, 2)
        bytecode:op_move(stack_top, stack_top + 2)
        exec_data.stack_data[#exec_data.stack_data] = "f64"
    end,
    [0x2C] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.load8_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 4,
            stack_top + 5,
            instruction[2][2],
            1
        )
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("extend_8_to_32"))
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:op_move(stack_top, stack_top + 2)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x2D] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.load8_u

        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            1
        )
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x2E] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.load16_s

        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 4,
            stack_top + 5,
            instruction[2][2],
            2
        )
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("extend_16_to_32"))
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:op_move(stack_top, stack_top + 2)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x2F] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.load16_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            2
        )
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x30] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load8_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            1
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("i8_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x31] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load8_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            1
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("u32_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x32] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load16_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            2
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("i16_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x33] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load16_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            2
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("u32_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x34] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load32_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            4
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("i32_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x35] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.load32_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        load_bytes_from_mem(
            bytecode,
            stack_top,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2],
            4
        )
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("u32_to_u64"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i64"
    end,
    [0x36] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.store
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            4
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x37] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.store
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            4
        )
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("rshift"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_load(stack_top + 5, 32)
        bytecode:op_call(stack_top + 2, 1, 2)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top + 2,
            stack_top + 3,
            instruction[2][2] + 4,
            4
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x38] = function(bytecode, exec_data, instruction, ins_ptr) -- f32.store
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("FloatToUInt32"))
        bytecode:op_move(stack_top + 3, stack_top)
        bytecode:op_call(stack_top + 1, 1, 1)
        load_memory_array(bytecode, stack_top + 2)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 2,
            stack_top + 1,
            stack_top + 3,
            instruction[2][2],
            4
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x39] = function(bytecode, exec_data, instruction, ins_ptr) -- f64.store
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("DoubleToUInt32s"))
        bytecode:op_move(stack_top + 3, stack_top)
        bytecode:op_call(stack_top + 1, 2, 1)
        load_memory_array(bytecode, stack_top + 3)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 3,
            stack_top + 1,
            stack_top + 4,
            instruction[2][2],
            4
        )
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 3,
            stack_top + 2,
            stack_top + 4,
            instruction[2][2] + 4,
            4
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3A] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.store8
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            1
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3B] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.store16
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            2
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3C] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.store8
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            1
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3D] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.store16
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            2
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3E] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.store32
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        store_bytes_to_mem(
            bytecode,
            stack_top - 1,
            stack_top + 1,
            stack_top,
            stack_top + 2,
            instruction[2][2],
            4
        )
        pop(exec_data.stack_data)
        pop(exec_data.stack_data)
    end,
    [0x3F] = function(bytecode, exec_data, instruction, ins_ptr) -- memory.size
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        load_memory_array(bytecode, stack_top + 1)
        bytecode:op_len(stack_top + 3, stack_top + 1)
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("rshift"))
        bytecode:op_load(stack_top + 4, 16)
        bytecode:op_call(stack_top + 1, 1, 2)
        push(exec_data.stack_data, "i32")
    end,
    [0x40] = function(bytecode, exec_data, instruction, ins_ptr) -- memory.grow
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        bytecode:op_tget(stack_top + 1, 0, "S", bytecode:const("store"))
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("mems"))
        bytecode:emit(bc.BC.TGETB, stack_top + 1, stack_top + 1, 1)

        bytecode:op_tget(stack_top + 2, stack_top + 1, "S", bytecode:const("data"))

        bytecode:op_len(stack_top + 4, stack_top + 2)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("rshift"))
        bytecode:op_load(stack_top + 5, 16)
        bytecode:op_call(stack_top + 2, 1, 2)

        local basename = tostring(ins_ptr)
        bytecode:op_tget(stack_top + 3, stack_top + 1, "S", bytecode:const("type"))
        bytecode:op_tget(stack_top + 3, stack_top + 3, "S", bytecode:const("max"))
        bytecode:emit(bc.BC.ISEQP, stack_top + 3, 0)
        bytecode:jump(basename .. "success", stack_top + 4)
        bytecode:op_add(stack_top + 4, stack_top, stack_top + 2)
        bytecode:emit(bc.BC.ISLT, stack_top + 3, stack_top + 4)
        bytecode:jump(basename .. "success", stack_top + 4)
        bytecode:op_load(stack_top, 0xFFFFFFFF)
        bytecode:jump(basename .. "instruction_done", stack_top + 1)
        bytecode:here(basename .. "success")
        bytecode:op_tget(stack_top + 1, stack_top + 1, "S", bytecode:const("data"))
        bytecode:op_tget(stack_top + 3, 1, "S", bytecode:const("lshift"))
        bytecode:op_move(stack_top + 5, stack_top + 2)
        bytecode:op_load(stack_top + 6, 16)
        bytecode:op_call(stack_top + 3, 1, 2)
        bytecode:op_tget(stack_top + 4, 1, "S", bytecode:const("lshift"))
        bytecode:op_move(stack_top + 6, stack_top)
        bytecode:op_load(stack_top + 7, 16)
        bytecode:op_call(stack_top + 4, 1, 2)
        bytecode:op_load(stack_top + 5, 1)
        local loop = bytecode:op_fori(stack_top + 3)
        bytecode:op_load(stack_top + 7, 0)
        bytecode:emit(bc.BC.TSETV, stack_top + 7, stack_top + 1, stack_top + 6)
        bytecode:op_forl(stack_top + 3, loop)
        bytecode:op_move(stack_top, stack_top + 2)
        bytecode:here(basename .. "instruction_done")

        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    -- NUMERICS -----------------------------
    [0x41] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.const
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_load(stack_top + 1, instruction[2])
        push(exec_data.stack_data, "i32")
    end,
    [0x42] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.const
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        local i64 = bit.to_u64(instruction[2].l, instruction[2].h)
        bytecode:op_load(stack_top + 1, i64)
        push(exec_data.stack_data, "i64")
    end,
    [0x43] = function(bytecode, exec_data, instruction, ins_ptr) -- f32.const
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_load(stack_top + 1, instruction[2])
        push(exec_data.stack_data, "f32")
    end,
    [0x44] = function(bytecode, exec_data, instruction, ins_ptr) -- f64.const
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_load(stack_top + 1, instruction[2])
        push(exec_data.stack_data, "f64")
    end,
    [0x45] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.eqz
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISEQN, stack_top, bytecode:const(0))
        emit_bool_to_num_lookup(bytecode, stack_top, stack_top + 1, tostring(ins_ptr))
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x46] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.eq
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISEQV, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x47] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.ne
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISNEV, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x48] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.lt_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 3, stack_top - 1)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:emit(bc.BC.ISLT, stack_top + 1, stack_top + 2)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x49] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.lt_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISLT, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x4A] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.gt_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 3, stack_top - 1)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:emit(bc.BC.ISGT, stack_top + 1, stack_top + 2)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x4B] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.gt_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISGT, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x4C] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.le_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 3, stack_top - 1)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("signed_32"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:emit(bc.BC.ISLE, stack_top + 1, stack_top + 2)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x4D] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.le_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISLE, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x4F] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.ge_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISGE, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x52] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.ne
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISNEV, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x56] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.gt_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("u64_to_i64"))
        bytecode:op_move(stack_top + 3, stack_top - 1)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("u64_to_i64"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:emit(bc.BC.ISGT, stack_top + 1, stack_top + 2)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    -- WARNING: KNOWN BUG, NO IDEA WHATS WRONG
    [0x59] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.ge_s
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("u64_to_i64"))
        bytecode:op_move(stack_top + 3, stack_top - 1)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("u64_to_i64"))
        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_call(stack_top + 2, 1, 1)
        bytecode:emit(bc.BC.ISGE, stack_top + 1, stack_top + 2)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x5A] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.ge_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISGE, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x63] = function(bytecode, exec_data, instruction, ins_ptr) -- f64.lt
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:emit(bc.BC.ISLT, stack_top - 1, stack_top)
        emit_bool_to_num_lookup(bytecode, stack_top - 1, stack_top, tostring(ins_ptr))
        pop(exec_data.stack_data)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x67] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.clz
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("clz"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x68] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.ctz
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top, 1, "S", bytecode:const("ctz"))
        bytecode:op_call(stack_top, 1, 1)
        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
    [0x6A] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.add
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        bytecode:op_add(stack_top + 1, stack_top - 1, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("band"))
        bytecode:op_load(stack_top + 2, 0xFFFFFFFF)
        bytecode:op_call(stack_top - 1, 1, 2)

        pop(exec_data.stack_data)
    end,
    [0x6B] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.sub
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_sub(stack_top + 1, stack_top - 1, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("band"))
        bytecode:op_load(stack_top + 2, 0xFFFFFFFF)
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x6C] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.mul
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_mul(stack_top + 1, stack_top - 1, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("band"))
        bytecode:op_load(stack_top + 2, 0xFFFFFFFF)
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x6E] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.div_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_div(stack_top + 1, stack_top - 1, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("trunc"))
        bytecode:op_call(stack_top - 1, 1, 1)
        pop(exec_data.stack_data)
    end,
    [0x70] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.rem_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_tget(stack_top + 1, 1, "S", bytecode:const("trunc"))
        bytecode:op_div(stack_top + 3, stack_top - 1, stack_top)
        bytecode:op_call(stack_top + 1, 1, 1)
        bytecode:op_mul(stack_top, stack_top, stack_top + 1)
        bytecode:op_sub(stack_top - 1, stack_top - 1, stack_top)

        pop(exec_data.stack_data)
    end,
    [0x71] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.and
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("band"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x72] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.or
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("bor"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x73] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.xor
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("bxor"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x74] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.shl
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("lshift"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x76] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.shr_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("rshift"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x77] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.rotl
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("lrotate"))
        bytecode:op_call(stack_top - 1, 1, 2)
        pop(exec_data.stack_data)
    end,
    [0x7D] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.sub
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_sub(stack_top - 1, stack_top - 1, stack_top)
        pop(exec_data.stack_data)
    end,
    [0x7E] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.mul
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_mul(stack_top - 1, stack_top - 1, stack_top)
        pop(exec_data.stack_data)
    end,
    [0x80] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.div_u
        local stack_top = exec_data.stack_start + #exec_data.stack_data
        bytecode:op_div(stack_top - 1, stack_top - 1, stack_top)
        pop(exec_data.stack_data)
    end,
    [0x89] = function(bytecode, exec_data, instruction, ins_ptr) -- i64.rotl
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        bytecode:op_move(stack_top + 1, stack_top - 1)
        bytecode:op_move(stack_top + 2, stack_top)
        bytecode:op_tget(stack_top - 1, 1, "S", bytecode:const("lrotate"))
        bytecode:op_call(stack_top - 1, 1, 2)

        pop(exec_data.stack_data)
    end,
    [0xA7] = function(bytecode, exec_data, instruction, ins_ptr) -- i32.wrap_i64
        local stack_top = exec_data.stack_start + #exec_data.stack_data

        bytecode:op_move(stack_top + 4, stack_top)
        bytecode:op_tget(stack_top + 2, 1, "S", bytecode:const("band"))
        bytecode:op_load(stack_top + 5, 0xFFFFFFFF)
        bytecode:op_call(stack_top + 2, 1, 2)
        bytecode:op_gget(stack_top, "tonumber")
        bytecode:op_call(stack_top, 1, 1)

        exec_data.stack_data[#exec_data.stack_data] = "i32"
    end,
}

--[[
    this function creates the bytecode for a function with this api:
    function(module, args...)
        -- code
        return rets...
    end
]]

function magic_print(a)
    print(serpent.block(a))
end

local function compile_function(func_addr, module)
    local func = module.store.funcs[func_addr]
    --[[
        register allocation:
        0: module
        1: bit library
        2..#locals+#args+2: locals
        #locals+#args+2..: stack

    ]]
    local exec_data = {}


    exec_data.module = module
    exec_data.args = func.type.from
    exec_data.locals = func.code.locals
    exec_data.returns = func.type.to
    exec_data.func = func
    exec_data.func_addr = func_addr
    exec_data.stashing_locals = (#exec_data.locals + #exec_data.args) > 35
    exec_data.stack_start = (exec_data.stashing_locals and 1 or (#exec_data.locals + #exec_data.args)) + 2
    exec_data.stack_data = {}

    --[[
        label format:
        {
            break_point: string, just the tostring of the ins_ptr of the instruction which made the label
            branch_point: string, the above with "_branch" appended, the instruction that the else in an if will branch to
            type: the type of the label, used for validation
            result_type: the types the stack must contain for a br to that label to be valid
            continue_at_end: whether the end instruction needs to do a bytecode:here for the break_point
            branch_taken_care_of: whether the else instruction has taken care of the branch, if nil the end must do it instead
            is_function: whether it is the outer label for the entire function
            }
    ]]
    exec_data.labels = {
        {
            break_point = "entire_function",
            type = { from = exec_data.args, to = exec_data.returns },
            result_type = exec_data.to,
            continue_at_end = true,
            is_function = true
        }
    }

    --[[
        how to call a function:
        
        ... {1,9} 5 3 1 12 5
                      ------ 
                       args
        push the function
        ... {1,9} 5 3 1 12 5 f
                      ------ 
                       args
        get and push the push the module from register 0
        ... {1,9} 5 3 1 12 5 f # module
                      ------
                       args
        move arguments up
        ... {1,9} 5 3 # # # f # module 1 12 5
                                       ------
                                        args
        bytecode "CALL f_loc return_count+1 arg_count+2"
        ... {1,9} 5 3 # # # {6,5} 252
                            ---------
                             returns
        move return back down
        ... {1,9} 5 3 {6,5} 252
                      ---------
                       returns
        done
    ]]

    --[[
        bytecode versions of functions are stored in module.compiled[func_addr]
    ]]

    local bytecode = bc.Proto.new(8, 0, #func.code.body)
    local bool_to_num = create_bool_to_num(bytecode)
    assert(bool_to_num == 0, "bool to num table did not get index 0")
    local i64_zeroed = bit.to_u64(0, 0)

    --if not exec_data.stashing_locals then
    --    for x = 0, #exec_data.args do
    --        bytecode:op_gget(exec_data.stack_start + 1, "print")
    --        bytecode:op_move(exec_data.stack_start + 3, x)
    --        bytecode:op_call(exec_data.stack_start + 1, 0, 1)
    --    end
    --end

    -- when a function is called, the function arguments start at 1..#args so they must be moved up by one
    for x = #exec_data.args, 1, -1 do
        bytecode:op_move(x + 1, x)
    end

    if exec_data.stashing_locals then
        bytecode:op_tnew(1, (#exec_data.args + #exec_data.locals > 255) and 255 or (#exec_data.args + #exec_data.locals))
        for x = 1, #exec_data.args do
            bytecode:emit(bc.BC.TSETB, x + 1, 1, x - 1)
        end
    end

    -- then the locals can be zeroed
    if exec_data.stashing_locals then
        for x = 1, #exec_data.locals do
            if exec_data.locals[x] == "i64" then
                bytecode:op_load(2, i64_zeroed)
                bytecode:op_load(3, x + #exec_data.args - 1)
                bytecode:emit(bc.BC.TSETV, 2, 1, 3)
            else
                bytecode:op_load(2, 0)
                bytecode:op_load(3, x + #exec_data.args - 1)
                bytecode:emit(bc.BC.TSETV, 2, 1, 3)
            end
        end
        bytecode:op_move(2, 1)
    else
        for x = 1, #exec_data.locals do
            if exec_data.locals[x] == "i64" then
                bytecode:op_load(x + #exec_data.args + 1, i64_zeroed)
            else
                bytecode:op_load(x + #exec_data.args + 1, 0)
            end
        end
    end

    -- now we can load the bitops library
    local stack_top = #exec_data.stack_data + exec_data.stack_start
    bytecode:op_gget(stack_top + 1, "require")
    bytecode:op_load(stack_top + 3, require_path .. "bitops")
    bytecode:op_call(stack_top + 1, 1, 1)
    bytecode:op_move(1, stack_top + 1)


    -- and now we are ready to execute instructions
    for k, instruction in ipairs(func.code.body) do
        local compiler = compile_instruction[instruction[1]]
        if compiler == nil then
            error(string.format("can't compile instruction 0x%X yet!", instruction[1]))
        end
        bytecode:line(k)
        local stack_top = #exec_data.stack_data + exec_data.stack_start
        bytecode:op_gget(stack_top + 1, "print")
        bytecode:op_load(stack_top + 3, "func_" .. tostring(func_addr) .. " ins_" .. tostring(k))
        bytecode:op_call(stack_top + 1, 0, 1)
        if func_addr == 156 then
            bytecode:op_gget(stack_top + 1, "require")
            bytecode:op_load(stack_top + 3, require_path .. "bitops")
            bytecode:op_call(stack_top + 1, 1, 1)
            bytecode:op_move(1, stack_top + 1)
        end
        local a = stack_top - 3
        if a < exec_data.stack_start + 1 then
            a = exec_data.stack_start + 1
        end
        bytecode:op_gget(stack_top + 1, "print")
        bytecode:op_move(stack_top + 3, 1)
        bytecode:op_call(stack_top + 1, 0, 1)
        bytecode:op_gget(stack_top + 1, "print")
        bytecode:op_move(stack_top + 3, 5)
        bytecode:op_call(stack_top + 1, 0, 1)
        for x = stack_top, a, -1 do
            bytecode:op_gget(stack_top + 1, "print")
            bytecode:op_move(stack_top + 3, x)
            bytecode:op_call(stack_top + 1, 0, 1)
        end

        compiler(bytecode, exec_data, instruction, k)
    end

    return bc.Dump.new(bytecode, "func " .. tostring(func_addr)):pack()
end

-- 0x00, 0x02, 0x03, 0x04, 0x05, 0x0B (somtimes), 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11
local function instruction_disrupts_ins_ptr(ins)
    local ins = ins[1]
    return ins <= 0x11 and ins ~= 0x01
end

local function full_eval(module, funcaddr, opt_start_stack, do_compile)
    if do_compile then
        if not module.compiled then
            module.compiled = {}
            for addr, func in pairs(module.store.funcs) do
                if func.hostcode then
                    module.compiled[addr] = function(module, ...)
                        return func.hostcode(...)
                    end
                else
                    local bytecode = compile_function(addr, module)
                    local file = io.open("decompiled/func_" .. tostring(addr) .. ".bc", "wb")
                    if file then
                        file:write(bytecode)
                        file:close()
                    end
                    module.compiled[addr] = loadstring(bytecode)
                end
            end
        end
        return module.compiled[funcaddr + 1](module, (table.unpack or unpack)(opt_start_stack or {}))
    else
        local stack = opt_start_stack or {}
        local frames = { { module = module, func_addr = "root", do_compile = do_compile } }
        local labels = {}
        local current_frame = top(frames)
        invoke(funcaddr, stack, frames, labels, module, current_frame)
        current_frame = top(frames)
        current_frame.ins_ptr = current_frame.ins_ptr + 1

        local creating_instruction_cache
        while true do
            local ins = current_frame.func.body[current_frame.ins_ptr]
            --print("ins_ptr:", current_frame.ins_ptr, "ins: ", ins[1], "top_label_is_function: ", top(labels).is_function,
            --    "other: ", ins[2], "label_stack_height: ", #labels, "current_function: ", current_frame.func_addr,
            --    "stack height: ", #stack, "other2: ", ins[3])
            local ins_func = ins[0]
            local result
            if creating_instruction_cache ~= nil then
                --print("inserting into cache, ", ins_func, " ", ins)
                table.insert(creating_instruction_cache, ins_func)
                table.insert(creating_instruction_cache, ins)
                if instruction_disrupts_ins_ptr(ins) then
                    creating_instruction_cache = nil
                end
                result = ins_func(ins, stack, frames, labels, module, current_frame, simple_nop)
            elseif current_frame.decoded_instructions[current_frame.ins_ptr] then
                local decoded_instructions = current_frame.decoded_instructions[current_frame.ins_ptr]
                local instruction_count = (#decoded_instructions) / 2
                --print("executing instruction cache, current ins_ptr: ", current_frame.ins_ptr, " ins_ptr after increment: ",
                --    current_frame.ins_ptr + instruction_count)
                --for x = 1, instruction_count do
                --    print("cache item: ", x, " instruction number: ", decoded_instructions[x * 2][1], "other: ",
                --        decoded_instructions[x * 2][2], "other2: ", decoded_instructions[x * 2][3])
                --end

                current_frame.ins_ptr = current_frame.ins_ptr + instruction_count
                -- it is guaranteed by construction that none of the instruction in the stream
                -- depend on the value of the pointer, except for the last one,
                -- by which point it will be correct again
                result = ins_func(ins, stack, frames, labels, module, current_frame,
                    (table.unpack or unpack)(decoded_instructions))
                --print("new stack height: ", #stack)
            elseif not instruction_disrupts_ins_ptr(ins) then
                --print("creating new cache")
                creating_instruction_cache = {}
                current_frame.decoded_instructions[current_frame.ins_ptr] = creating_instruction_cache
                result = ins_func(ins, stack, frames, labels, module, current_frame, simple_nop)
            else
                result = ins_func(ins, stack, frames, labels, module, current_frame, simple_nop)
            end
            if result == true then
                current_frame = top(frames)
                result = nil
            end
            if frames[2] == nil then
                return stack
            end
            current_frame.ins_ptr = current_frame.ins_ptr + 1
            if result then
                raise_error(result, stack, frames, labels, module)
                return nil, -2, result
            end
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

local function call_function(module, funcidx, args, do_compile)
    if do_compile then
        return full_eval(module, funcidx, args, do_compile)
    else
        full_eval(module, funcidx, args, false)
        return (table.unpack or unpack)(args)
    end
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
