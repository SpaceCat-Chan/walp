#include <cstddef>
#include <cinttypes>
#define WALP false //toggle to false for testing, true for compiling for WALP

using SSI = uint32_t;

#if WALP
extern "C"
{

    void print(const char *str_ptr, uint32_t size);
    double math_random();
    double tonumber(const char *str_ptr, uint32_t size);
    SSI tostring(double number);
    uint32_t get_string_len(SSI str_idx);
    bool write_string_to_ptr(SSI str_idx, char *str, uint32_t size);
    void delete_string(SSI str_idx);
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

void print(const char *str_ptr, int32_t size) { printf("%.*s", size, str_ptr); }

static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_real_distribution<> dis(0.0, 1.0);
double math_random() { return dis(gen); }

double tonumber(const char *str_ptr, int32_t size)
{
    double res;
    strtod(str_ptr, (char **)&res);
    return res;
}

SSI tostring(double number)
{
    std::string temp_str(std::to_string(number));
    SSI temp_hash = std::hash<std::string>{}(temp_str);
    str_map.try_emplace(temp_hash, std::move(temp_str));
    return temp_hash;
}

int32_t get_string_len(SSI str_idx)
{
    auto str_ref = str_map.find(str_idx);
    if (str_ref != str_map.end())
    {
        return str_ref->second.size();
    }
    else
    {
        return 0xFFFFFFFF;
    }
}

bool write_string_to_ptr(SSI str_idx, char *str, int32_t size)
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

SSI store_string(const char *str_ptr, int32_t size)
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
    std::cin >> str;
    SSI res = std::hash<std::string>{}(str);
    str_map.try_emplace(res, std::move(str));
    return res;
}
#endif

//convenient wrapper
struct WasmString
{
    SSI index;

    WasmString(double val) : index(tostring(val)) {}
    WasmString(const char *c_str)
    {
        std::string temp_str(c_str);
        index = std::hash<std::string>{}(c_str);
        str_map.try_emplace(index, std::move(temp_str));
    }
    WasmString(std::string &&str)
    {
        index = std::hash<std::string>{}(str);
        str_map.try_emplace(index, std::move(str));
    }
    WasmString(std::string_view &str_view)
    {
        index = std::hash<std::string_view>{}(str_view);
        str_map.try_emplace(index, str_view);
    }
    ~WasmString()
    {
        delete_string(index);
    }
};
