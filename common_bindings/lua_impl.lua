return function(module, alt_name, memory)
    alt_name = alt_name or "env"
    memory = memory or module.EXPORTS.memory
    module.IMPORTS[alt_name] = module.IMPORTS[alt_name] or {}

    module.IMPORTS[alt_name].print = function(ptr, len)
        for x=ptr, ptr+len-1 do
            io.write(string.char(memory.read8(x)))
        end
    end
    local math_random = math.random
    module.IMPORTS[alt_name].math_random = function()
        return math_random()
    end

    module.IMPORTS[alt_name].tonumber = function(ptr, len)
        local str = ""
        for x=str_ptr, ptr+len-1 do
            str = str..string.char(memory.read8(x))
        end
        return tonumber(str) or 0
    end

    local string_table = {}

    module.IMPORTS[alt_name].tostring = function(number)
        table.insert(string_table, tostring(number))

        return #string_table
    end

    module.IMPORTS[alt_name].get_string_len = function(index)
        if string_table[index] == nil then return 0xFFFFFFFF end -- 32bit -1
        return string.len(string_table[index])
    end

    module.IMPORTS[alt_name].write_string_to_ptr = function(index, ptr, len)
        if string_table[index] == nil then return 0 end
        local s = string_table[index]
        local min_len = math.min(string.len(s), len)
        for x=0, min_len-1 do
            memory.write8(ptr+x, string.byte(s, x+1))
        end
        return 1
    end

    module.IMPORTS[alt_name].delete_string = function(index)
        string_table[index] = nil
    end

    module.IMPORTS[alt_name].store_string = function(ptr, len)
        local str = ""
        for x=str_ptr, ptr+len-1 do
            str = str..string.char(memory.read8(x))
        end
        table.insert(string_table, str)
        return #string_table
    end
    module.IMPORTS[alt_name].print_ssi = function(index)
        if string_table[index] == nil then return end
        io.write(string_table[index])
    end
    module.IMPORTS[alt_name].read_line = function()
        local string = io.read("L")
        table.insert(string_table, string)
        return #string_table
    end
    return {
        create_ssi_string = function(string)
            table.insert(string_table, string)
            return #string_table
        end,

        load_ssi_string = function(ssi)
            return string_table[ssi]
        end,
    }
end
