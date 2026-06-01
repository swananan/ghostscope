#include "backtrace_cross_module_lib.h"

volatile unsigned long cross_module_shared_sink = 0;

__attribute__((noinline)) unsigned long cross_module_lib_leaf(unsigned long value)
{
    asm volatile("" : "+r"(value) :: "memory");
    return value + 17;
}

__attribute__((noinline)) unsigned long cross_module_lib_probe(unsigned long value)
{
    unsigned long result = cross_module_lib_leaf(value + 1);
    cross_module_shared_sink += result;
    asm volatile("" ::: "memory");
    return cross_module_shared_sink;
}
