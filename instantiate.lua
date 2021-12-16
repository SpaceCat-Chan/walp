local require_path = (...):match("(.-)[^%.]+$")
local eval = require(require_path.."eval")

local function check_imports(module)
    if module.IMPORTS == nil and #module.imports ~= 0 then
        error("missing imports!")
    end
    for _,import in pairs(module.imports) do
        local mod = module.IMPORTS[import.module]
        if mod == nil or mod[import.name] == nil then
            error("missing import "..import.name.." in "..import.module.."!")
        end
    end
end

local function add_functions_to_store(module)
    module.store.funcs = {}
    for _,import in pairs(module.imports) do
        if import.desc.func then
            local type = module.types[import.desc.func+1]
            table.insert(module.store.funcs, {
                type = type,
                hostcode = module.IMPORTS[import.module][import.name]
            })
        end
    end
    for _,func in pairs(module.funcs) do
        local type = module.types[func.type+1]
        table.insert(module.store.funcs, {
            type = type,
            module = module,
            code = func
        })
    end
end

local function add_tables_to_store(module)
    module.store.tables = {}
    for _,import in pairs(module.imports) do
        if import.desc.table then
            local tab = {
                type = import.desc.table,
                elem = {}
            }
            for x=1,tab.type[2].min do
                tab.elem[x] = 0
            end
            table.insert(module.store.tables, tab)
        end
    end
    for _,table_ in pairs(module.tables) do
        local tab = {
            type = table_,
            elem = {}
        }
        for x=1,tab.type[2].min do
            tab.elem[x] = 0
        end
        table.insert(module.store.tables, tab)
    end
end

local function add_memories_to_store(module)
    module.store.mems = {}
    for _,import in pairs(module.imports) do
        if import.desc.mem then
            local m = {
                type = import.desc.mem,
                data = {}
            }
            for x=1,(m.type.min * 65536) do
                m.data[x] = 0
            end
            table.insert(module.store.mems, m)
        end
    end
    for _,mem in pairs(module.mems) do
        local m = {
            type = mem,
            data = {}
        }
        for x=1,(m.type.min * 65536) do
            m.data[x] = 0
        end
        table.insert(module.store.mems, m)
    end
end

local function add_globals_to_store(module)
    module.store.globals = {}
    for _,import in pairs(module.imports) do
        if import.desc.global then
            table.insert(module.store.global, {
                type = import.desc.global,
                val = module.IMPORTS[import.module][import.name]
            })
        end
    end
    for _,global in pairs(module.globals) do
        table.insert(module.store.globals, {
            type = global.type,
            val = eval.simple(global.init)
        })
    end
end

local function add_elems_to_store(module)
    module.store.elems = {}
    for _,elem in pairs(module.elems) do
        table.insert(module.store.elems, {
            type = elem.type,
            elem = eval.simple_list(elem.init)
        })
    end
end

local function add_datas_to_store(module)
    module.store.datas = {}
    for _,data in pairs(module.datas) do
        table.insert(module.store.datas, {
            data = data.init
        })
    end
end

local function create_store(module)
    module.store = {}
    add_functions_to_store(module)
    add_tables_to_store(module)
    add_memories_to_store(module)
    add_globals_to_store(module)
    add_elems_to_store(module)
    add_datas_to_store(module)
end

local function fill_exports(module)
    for idx,export in pairs(module.exports) do
        local interface_export = module.EXPORTS[export.name]
        if export.desc.func then
            interface_export.call = function(...)
                eval.call_function(module, export.desc.func, {...})
            end
        elseif export.desc.mem then
            eval.make_memory_interface(module, export.desc.mem, interface_export)
        elseif export.desc.table then
            interface_export.elements = module.store.tables.elem
        elseif export.desc.global then
            interface_export.get = function()
                return module.store.globals[export.desc.global].val
            end
            if module.store.globals[export.desc.global].type.is_mutable then
                interface_export.set = function(set_to)
                    module.store.globals[export.desc.global].val = set_to
                end
            end
        end
    end
end

local function instantiate(module)
    eval.pre_lookup_instructions(module)

    check_imports(module)
    create_store(module)
    eval.fill_elems(module)
    eval.fill_datas(module)
    eval.call_start(module)

    fill_exports(module)
end

return instantiate