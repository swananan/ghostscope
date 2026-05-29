#include "cast_types_program.h"

extern volatile unsigned long long cast_types_shared_sink;

struct FallbackDuplicate {
    int lib_b_marker;
    int lib_b_value;
};

__attribute__((noinline)) void cast_extra_fallback_probe(struct FallbackDuplicate *dup, int seq) {
    dup->lib_b_value += seq & 1;
    cast_types_shared_sink += (unsigned long long)dup->lib_b_marker + (unsigned long long)dup->lib_b_value;
}

void cast_call_extra_lib(int seq) {
    struct FallbackDuplicate fallback = {
        .lib_b_marker = 6000 + seq,
        .lib_b_value = 7000 + seq,
    };
    cast_extra_fallback_probe(&fallback, seq);
}
