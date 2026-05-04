#include <stdint.h>
#include <unistd.h>

static volatile uintptr_t scalar_sink;

__attribute__((noinline)) static void scalar_anchor(
    volatile int8_t *i8p,
    volatile uint8_t *u8p,
    volatile short *i16p,
    volatile unsigned short *u16p,
    volatile int *i32p,
    volatile unsigned int *u32p,
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

__attribute__((noinline)) static void scalar_probe(int iter)
{
    volatile int8_t i8_neg = (int8_t)-5;
    volatile uint8_t u8_big = (uint8_t)250u;
    volatile short i16_neg = (short)-1234;
    volatile unsigned short u16_big = (unsigned short)60000u;
    volatile int i32_neg = -12345678;
    volatile unsigned int u32_big = 4000000000U;
    volatile long ilong_neg = -4444444444L;
    volatile unsigned long ulong_big = 9000000000UL;
    volatile long long i64_neg = -9000000000000000000LL;
    volatile uint64_t u64_big = UINT64_C(18446744073709551610);
    volatile _Bool bool_true = iter >= 0;
    volatile _Bool bool_false = 0;
    volatile float f32_val = -12.5f;
    volatile double f64_val = 123456.25;
    volatile long double ldouble_val = -3.5L;

    scalar_anchor(
        &i8_neg,
        &u8_big,
        &i16_neg,
        &u16_big,
        &i32_neg,
        &u32_big,
        &ilong_neg,
        &ulong_big,
        &i64_neg,
        &u64_big,
        &bool_true,
        &bool_false,
        &f32_val,
        &f64_val,
        &ldouble_val);
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
