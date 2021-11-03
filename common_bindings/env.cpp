#pragma once
#include <cstddef>
#include <cinttypes>
#define WALP false //toggle to false for testing, true for compiling for WALP

#if WALP
extern "C"
{

    void print(char *str, size_t size);
    double math_random();
    double tonumber(const char *str, size_t size);
    size_t tostring(double number);
    size_t get_string_len(size_t str_idx);
    void write_string_to_ptr(size_t str_idx, char *str, size_t size);
    void delete_string(int32_t str_idx)
}
#else

#include <cstdio>
void print(char *ptr, size_t size) { printf(ptr); }

#include <random>
static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_real_distribution<> dis(0.0, 1.0);
double math_random() { return dis(gen); }

#include <unordered_map>
#include <string>
static std::unordered_map<int32_t, std::string> str_map;

#include <stdlib.h>
double tonumber(char *str, int32_t size)
{
    double res;
    strtod(str, (char **)&res);
    return res;
}
int32_t tostring(double number)
{
    std::string temp_str(std::to_string(number));
    int32_t temp_hash = std::hash<std::string>{}(temp_str);
    str_map.try_emplace(temp_hash, std::move(temp_str));
    return temp_hash;
}
int32_t get_string_len(int32_t str_idx)
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
bool write_string_to_ptr(int32_t str_idx, char *str, int32_t size)
{
    auto str_ref = str_map.find(str_idx);
    if (str_ref != str_map.end())
    {
        str_ref->second = std::string_view(str, size);
        return true;
    }
    return false;
}
void delete_string(int32_t str_idx) { str_map.erase(str_idx); }

#endif
