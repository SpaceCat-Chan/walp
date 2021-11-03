#include <cinttypes>
#define WALP false //toggle to false for testing, true for compiling for WALP

#if WALP
#ifdef __cplusplus
extern "C"
{
#endif

    void print(char *ptr, uint32_t length);
    double math_random();
    char *tostring(double number);
    double tonumber(char *str);

#ifdef __cplusplus
}
#endif
#else

void print(char *ptr, uint32_t length) { printf(ptr); }

#include <random>
static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_real_distribution<> dis(0.0, 1.0);
double math_random() { return dis(gen); }

char *tostring(double number)
{
    char *str = new char[11];
    sprintf(str, "%lf", number);
    return str;
}

double tonumber(char *str) { return std::stod(str); }

#endif
