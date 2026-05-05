#include <stdint.h>
#include <unistd.h>

typedef int8_t scalar_i8_alias;
typedef uint16_t scalar_u16_alias;

enum scalar_signed_enum {
    SCALAR_ENUM_NEG = -3,
    SCALAR_ENUM_POS = 7,
};

enum scalar_big_enum {
    SCALAR_ENUM_BIG = 4000000000U,
};

static volatile uintptr_t scalar_sink;

__attribute__((noinline)) static void scalar_anchor(
    volatile int8_t *i8p,
    volatile uint8_t *u8p,
    volatile short *i16p,
    volatile unsigned short *u16p,
    volatile int *i32p,
    volatile unsigned int *u32p,
    volatile int32_t *i32minp,
    volatile long *ilongp,
    volatile unsigned long *ulongp,
    volatile long long *i64p,
    volatile uint64_t *u64p,
    volatile _Bool *truep,
    volatile _Bool *falsep,
    volatile float *f32p,
    volatile double *f64p,
    volatile long double *ldp)
{
    uintptr_t mix = (uintptr_t)i8p;
    mix ^= (uintptr_t)u8p;
    mix ^= (uintptr_t)i16p;
    mix ^= (uintptr_t)u16p;
    mix ^= (uintptr_t)i32p;
    mix ^= (uintptr_t)u32p;
    mix ^= (uintptr_t)i32minp;
    mix ^= (uintptr_t)ilongp;
    mix ^= (uintptr_t)ulongp;
    mix ^= (uintptr_t)i64p;
    mix ^= (uintptr_t)u64p;
    mix ^= (uintptr_t)truep;
    mix ^= (uintptr_t)falsep;
    mix ^= (uintptr_t)f32p;
    mix ^= (uintptr_t)f64p;
    mix ^= (uintptr_t)ldp;
    scalar_sink ^= mix;
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void scalar_extra_anchor(
    volatile char *charp,
    volatile signed char *scharp,
    volatile unsigned char *ucharp,
    volatile scalar_i8_alias *alias_i8p,
    volatile const scalar_u16_alias *qualified_u16p,
    volatile enum scalar_signed_enum *enum_negp,
    volatile enum scalar_big_enum *enum_bigp,
    volatile float *neg_zerop,
    volatile double *infp,
    volatile double *nanp)
{
    uintptr_t mix = (uintptr_t)charp;
    mix ^= (uintptr_t)scharp;
    mix ^= (uintptr_t)ucharp;
    mix ^= (uintptr_t)alias_i8p;
    mix ^= (uintptr_t)qualified_u16p;
    mix ^= (uintptr_t)enum_negp;
    mix ^= (uintptr_t)enum_bigp;
    mix ^= (uintptr_t)neg_zerop;
    mix ^= (uintptr_t)infp;
    mix ^= (uintptr_t)nanp;
    scalar_sink ^= mix;
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void scalar_by_value(
    int8_t i8v,
    uint8_t u8v,
    short i16v,
    unsigned short u16v,
    uint32_t u32v,
    uint64_t u64v,
    scalar_i8_alias alias_i8v,
    enum scalar_signed_enum enum_negv,
    enum scalar_big_enum enum_bigv)
{
    scalar_sink ^= (uintptr_t)(uint8_t)i8v;
    scalar_sink ^= (uintptr_t)u8v;
    scalar_sink ^= (uintptr_t)(uint16_t)i16v;
    scalar_sink ^= (uintptr_t)u16v;
    scalar_sink ^= (uintptr_t)u32v;
    scalar_sink ^= (uintptr_t)u64v;
    scalar_sink ^= (uintptr_t)(uint8_t)alias_i8v;
    scalar_sink ^= (uintptr_t)(int)enum_negv;
    scalar_sink ^= (uintptr_t)(uint64_t)enum_bigv;
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void scalar_float_bool_by_value(
    _Bool bool_truev,
    _Bool bool_falsev,
    float f32v,
    double f64v)
{
    scalar_sink ^= (uintptr_t)bool_truev;
    scalar_sink ^= (uintptr_t)bool_falsev;
    scalar_sink ^= (uintptr_t)(int)f32v;
    scalar_sink ^= (uintptr_t)(long long)f64v;
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void scalar_stack_by_value(
    uint64_t reg1,
    uint64_t reg2,
    uint64_t reg3,
    uint64_t reg4,
    uint64_t reg5,
    uint64_t reg6,
    int8_t stack_i8v,
    uint8_t stack_u8v,
    int32_t stack_i32v,
    uint64_t stack_u64v)
{
    scalar_sink ^= (uintptr_t)reg1;
    scalar_sink ^= (uintptr_t)reg2;
    scalar_sink ^= (uintptr_t)reg3;
    scalar_sink ^= (uintptr_t)reg4;
    scalar_sink ^= (uintptr_t)reg5;
    scalar_sink ^= (uintptr_t)reg6;
    scalar_sink ^= (uintptr_t)(uint8_t)stack_i8v;
    scalar_sink ^= (uintptr_t)stack_u8v;
    scalar_sink ^= (uintptr_t)(uint32_t)stack_i32v;
    scalar_sink ^= (uintptr_t)stack_u64v;
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void scalar_probe(int iter)
{
    volatile int8_t i8_neg = (int8_t)-5;
    volatile uint8_t u8_big = (uint8_t)250u;
    volatile short i16_neg = (short)-1234;
    volatile unsigned short u16_big = (unsigned short)60000u;
    volatile int i32_neg = -12345678;
    volatile unsigned int u32_big = 4000000000U;
    volatile int32_t i32_min = INT32_MIN;
    volatile long ilong_neg = -4444444444L;
    volatile unsigned long ulong_big = 9000000000UL;
    volatile long long i64_neg = -9000000000000000000LL;
    volatile uint64_t u64_big = UINT64_C(18446744073709551610);
    volatile _Bool bool_true = iter >= 0;
    volatile _Bool bool_false = 0;
    volatile float f32_val = -12.5f;
    volatile double f64_val = 123456.25;
    volatile long double ldouble_val = -3.5L;
    volatile char plain_char = 'A';
    volatile signed char schar_neg = (signed char)-7;
    volatile unsigned char uchar_big = (unsigned char)240u;
    volatile scalar_i8_alias alias_i8_neg = (scalar_i8_alias)-9;
    volatile const scalar_u16_alias qualified_u16_big = (scalar_u16_alias)65000u;
    volatile enum scalar_signed_enum enum_neg = SCALAR_ENUM_NEG;
    volatile enum scalar_big_enum enum_big = SCALAR_ENUM_BIG;
    volatile float f32_neg_zero = -0.0f;
    volatile double f64_inf = __builtin_huge_val();
    volatile double f64_nan = __builtin_nan("");

    scalar_anchor(
        &i8_neg,
        &u8_big,
        &i16_neg,
        &u16_big,
        &i32_neg,
        &u32_big,
        &i32_min,
        &ilong_neg,
        &ulong_big,
        &i64_neg,
        &u64_big,
        &bool_true,
        &bool_false,
        &f32_val,
        &f64_val,
        &ldouble_val);

    scalar_extra_anchor(
        &plain_char,
        &schar_neg,
        &uchar_big,
        &alias_i8_neg,
        &qualified_u16_big,
        &enum_neg,
        &enum_big,
        &f32_neg_zero,
        &f64_inf,
        &f64_nan);

    scalar_by_value(
        i8_neg,
        u8_big,
        i16_neg,
        u16_big,
        u32_big,
        u64_big,
        alias_i8_neg,
        enum_neg,
        enum_big);

    scalar_float_bool_by_value(
        bool_true,
        bool_false,
        f32_val,
        f64_val);

    scalar_stack_by_value(
        11,
        22,
        33,
        44,
        55,
        66,
        i8_neg,
        u8_big,
        i32_neg,
        u64_big);
}

int main(void)
{
    int iter = 0;

    while (iter < 20000) {
        scalar_probe(iter++);
        usleep(10000);
    }

    return 0;
}
