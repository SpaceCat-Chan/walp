#include <cstddef>
#include <cinttypes>

using SSI = uint32_t;

#define WALP false // toggle to false for testing, true for compiling for WALP
#if WALP

extern "C"
{
    void print(const char *str_ptr, uint32_t size);
    double math_random();
    SSI tostring(double number);
    double tonumber(const char *str_ptr, uint32_t size);
    uint32_t get_string_len(SSI str_idx);
    bool write_string_to_ptr(SSI str_idx, char *str, uint32_t size);
    void delete_string(SSI str_idx);
    SSI store_string(const char *str_ptr, uint32_t size);
    void print_ssi(SSI str_idx);
    SSI read_line();
}

#else

#include <cstdio>
#include <random>
#include <unordered_map>
#include <string>
#include <stdlib.h>
#include <string>
#include <cassert>
#include <iostream>

static std::unordered_map<SSI, std::string> str_map;

void print(const char *str_ptr, uint32_t size) { printf("%.*s", size, str_ptr); }

static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_real_distribution<> dis(0.0, 1.0);
double math_random() { return dis(gen); }

double tonumber(const char *str_ptr, uint32_t size) { return strtod(str_ptr, (char**)str_ptr + size); }

SSI tostring(double number)
{
    std::string temp_str(std::to_string(number));
    SSI temp_hash = std::hash<std::string>{}(temp_str);
    str_map.try_emplace(temp_hash, std::move(temp_str));
    return temp_hash;
}

uint32_t get_string_len(SSI str_idx)
{
    auto str_ref = str_map.find(str_idx);
    if (str_ref != str_map.end())
    {
        return str_ref->second.size();
    }
    else
    {
        return 0xFFFFFFFF; // -1
    }
}

bool write_string_to_ptr(SSI str_idx, char *str, uint32_t size)
{
    auto str_ref = str_map.find(str_idx);
    if (str_ref != str_map.end())
    {
        for (size_t i = 0; i < size; ++i)
        {
            str[i] = str_ref->second[i];
        }
        return true;
    }
    return false;
}

void delete_string(SSI str_idx) { str_map.erase(str_idx); }

SSI store_string(const char *str_ptr, uint32_t size)
{
    std::string temp_str(std::string_view(str_ptr, size));
    SSI temp_hash = std::hash<std::string>{}(str_ptr);
    str_map.try_emplace(temp_hash, std::move(temp_str));
    return temp_hash;
}

void print_ssi(SSI str_idx)
{
    auto &str_ref = str_map.at(str_idx);
    printf("%.*s", str_ref.size(), str_ref.data());
}

SSI read_line()
{
    std::string str;
    getline(std::cin, str);
    SSI res = std::hash<std::string>{}(str);
    str_map.try_emplace(res, std::move(str));
    return res;
}

#endif

std::pair<SSI, std::string> read_line_str()
{
    SSI index = read_line();
    uint32_t str_size = get_string_len(index);
    std::string str(new char[str_size], str_size);
    write_string_to_ptr(index, str.data(), str_size);
    return {index, str};
}

constexpr size_t length(const char* str) { return *str ? 1 + length(str + 1) : 0; }

// convenient wrapper
struct WasmString
{
    SSI index;

    WasmString(double val) : index(tostring(val)) {}
    WasmString(SSI index) : index(index) {}
    WasmString(const char *c_str) { store_string(c_str, length(c_str)); }
    WasmString(std::string &&str) { store_string(str.data(), str.size()); }
    WasmString(std::string_view &str_view) { store_string(str_view.data(), str_view.size()); }
    ~WasmString() { delete_string(index); }
};
