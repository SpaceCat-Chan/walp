



local section_names = {
    [1] = "types",
    [3] = "funcs",
    [4] = "tables",
    [5] = "mems",
    [6] = "globals",
    [9] = "elems",
    [11] = "datas",
    [8] = "start",
    [2] = "imports",
    [7] = "exports",
}

local function merge_func_and_code_secs(mod, funcs_idx, code_idx)
    local new_funcs = {}
    for idx, func in pairs(mod[funcs_idx][3]) do
        local result = {type = func}
        local code = mod[code_idx][3][idx][2]
        local locals = code[1]
        result.locals = {}
        result.body = code[2]
        for _, local_ in ipairs(locals) do
            for x=1,local_[1] do
                table.insert(result.locals, local_[2])
            end
        end
        new_funcs[idx] = result
    end
    mod[funcs_idx][3] = new_funcs
end

local function rename_sections(mod)
    mod.custom_sections = {}
    local remove = {}
    for idx, sec in ipairs(mod) do
        if sec[1] == 0 then
            table.insert(mod.custom_sections, sec[3])
        elseif sec[1] == 10 or sec[1] == 12 then
            --do nothing
        else
            mod[section_names[sec[1]]] = sec[3]
        end
        remove[idx] = true
    end
    for idx,_ in ipairs(remove) do
        mod[idx] = nil
    end
end

local function transform_globals(globals)
    for _, global in pairs(globals) do
        global.type = {type = global[1][1], is_mutable = global[1][2]}
        global.init = global[2]
        global[1] = nil
        global[2] = nil
    end
end

local function transform_datas(datas)
    for _,data in pairs(datas) do
        --[[
            target:
            {
                init: {byte, ...}
                mode: "active"|"passive"
                active_info: {memory: index, offset: expr}
            }
            current:
            the binary encoding
        ]]
        local raw_mode = data[1]
        data[1] = nil
        if raw_mode == 1 then
            data.init = data[2]
            data.mode = "passive"
        else
            data.mode = "active"
            local memory_index = 0
            local magic_offset = 0
            if raw_mode == 2 then
                magic_offset = 1
                memory_index = data[2]
            end
            data.active_info = {memory = memory_index, offset = data[2 + magic_offset]}
            data.init = data[3 + magic_offset]
            data[3] = nil
            data[4] = nil
        end
        data[2] = nil
    end
end

local portdesc_names = {
    [0] = "func",
    [1] = "table",
    [2] = "mem",
    [3] = "global",
}

local function transform_ports(ports)
    for _,port in pairs(ports) do
        if port[3] then
            port.module = port[1]
            port.name = port[2]
            port.desc = port[3]
        else
            port.name = port[1]
            port.desc = port[2]
        end
        port.desc[portdesc_names[port.desc[1]]] = port.desc[2]
        port[1] = nil
        port[2] = nil
        port[3] = nil
        port.desc[1] = nil
        port.desc[2] = nil
    end
end

local function flatten_single_block(block)
    local new_block = {}
    local pos = 1
    for _,ins in ipairs(block) do
        if ins[1] == 0x02 or ins[1] == 0x03 then
            new_block[pos] = {ins[1], ins[2]}
            local orig_pos = pos
            local new_ins = flatten_single_block(ins[3])
            for _,new in ipairs(new_ins) do
                pos = pos + 1
                new_block[pos] = new
            end
            pos = pos + 1
            new_block[pos] = {ins[4]}
            new_block[orig_pos][3] = pos - orig_pos
        elseif ins[1] == 0x04 then
            new_block[pos] = {ins[1], ins[2]}
            local orig_pos = pos
            local new_ins = flatten_single_block(ins[3])
            for _,new in ipairs(new_ins) do
                pos = pos + 1
                new_block[pos] = new
            end
            pos = pos + 1
            new_block[pos] = {ins[4]}
            new_block[orig_pos][3] = pos - orig_pos
            new_block[orig_pos][4] = pos - orig_pos
            if ins[4] == 0x05 then
                local new_ins = flatten_single_block(ins[5])
                for _,new in ipairs(new_ins) do
                    pos = pos + 1
                    new_block[pos] = new
                end
                pos = pos + 1
                new_block[pos] = {ins[6]}
                new_block[orig_pos][3] = pos - orig_pos
            end
        else
            new_block[pos] = ins
        end
        pos = pos + 1
    end
    return new_block
end

local function flatten_blocks(funcs)
    for _,func in pairs(funcs) do
        local new_body = flatten_single_block(func.body[1])
        table.insert(new_body, {func.body[2]})
        func.body = new_body
    end
end

local function module(mod)
    --[[
        step 1
        find code and funcs segments and merge them
    ]]
    local code_idx, funcs_idx
    for idx, sec in ipairs(mod) do
        if sec[1] == 3 then
            funcs_idx = idx
        elseif sec[1] == 10 then
            code_idx = idx
        end
    end
    if (code_idx or funcs_idx) == nil then
        error("unable to find both code and function segment")
    end
    merge_func_and_code_secs(mod, funcs_idx, code_idx)
    rename_sections(mod)
    for _,name in pairs(section_names) do
        if name ~= "start" then
            mod[name] = mod[name] or {}
        end
    end
    flatten_blocks(mod.funcs)
    transform_globals(mod.globals)
    transform_datas(mod.datas)
    if mod.start then
        mod.start = {func = mod.start}
    end
    transform_ports(mod.exports)
    transform_ports(mod.imports)
    mod.EXPORTS = {}
    for _,export in pairs(mod.exports) do
        mod.EXPORTS[export.name] = {} -- will be filled during instatiation
    end
end

return {
    module = module,
}