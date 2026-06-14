#include "backtrace_dlopen_lib.h"

volatile uint64_t dlopen_lib_sink = 0;

__attribute__((noinline)) static uint64_t dlopen_lib_leaf(
    uint64_t value,
    dlopen_callback_fn callback)
{
    uint64_t result = callback(value + 7);
    dlopen_lib_sink += result;
    asm volatile("" ::: "memory");
    return dlopen_lib_sink;
}

__attribute__((noinline)) static uint64_t dlopen_lib_middle(
    uint64_t value,
    dlopen_callback_fn callback)
{
    return dlopen_lib_leaf(value + 5, callback) + 3;
}

__attribute__((noinline)) uint64_t dlopen_lib_driver(
    uint64_t value,
    dlopen_callback_fn callback)
{
    return dlopen_lib_middle(value + 3, callback) + 1;
}
