#include <cstddef>
#include <cinttypes>
#define WALP false //toggle to false for testing, true for compiling for WALP

using SSI = int32_t;

#if WALP
extern "C"
{

    void print(const char *str, int32_t size);
    double math_random();
    double tonumber(const char *str, int32_t size);
    SSI tostring(double number);
    int32_t get_string_len(SSI str_idx);
    bool write_string_to_ptr(SSI str_idx, char *str, int32_t size);
    void delete_string(SSI str_idx)
}
#else
#include <cstdio>
#include <random>
#include <unordered_map>
#include <string>
#include <stdlib.h>
#include <string>
#include <cassert>

static std::unordered_map<SSI, std::string> str_map;

void print(const char *ptr, int32_t size) { printf("%.*s", size, ptr); }

static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_real_distribution<> dis(0.0, 1.0);
double math_random() { return dis(gen); }

double tonumber(char *str, int32_t size)
{
    double res;
    strtod(str, (char **)&res);
    return res;
}
SSI tostring(double number)
{
    std::string temp_str(std::to_string(number));
    int32_t temp_hash = std::hash<std::string>{}(temp_str);
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
        str_ref->second = std::string_view(str, size);
        return true;
    }
    return false;
}
void delete_string(SSI str_idx) { str_map.erase(str_idx); }

#endif
