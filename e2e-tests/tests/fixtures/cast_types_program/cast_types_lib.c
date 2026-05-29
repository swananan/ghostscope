#include "cast_types_program.h"

extern volatile unsigned long long cast_types_shared_sink;

struct Duplicate {
    int lib_marker;
    int lib_value;
};

struct FallbackDuplicate {
    int lib_a_marker;
    int lib_a_value;
};

__attribute__((noinline)) void cast_lib_duplicate_probe(struct Duplicate *dup, int seq) {
    dup->lib_value += seq & 1;
    cast_types_shared_sink += (unsigned long long)dup->lib_marker + (unsigned long long)dup->lib_value;
}

__attribute__((noinline)) void cast_lib_fallback_probe(struct FallbackDuplicate *dup, int seq) {
    dup->lib_a_value += seq & 1;
    cast_types_shared_sink += (unsigned long long)dup->lib_a_marker + (unsigned long long)dup->lib_a_value;
}

void cast_call_lib(int seq) {
    struct Duplicate dup = {
        .lib_marker = 2000 + seq,
        .lib_value = 3000 + seq,
    };
    struct FallbackDuplicate fallback = {
        .lib_a_marker = 4000 + seq,
        .lib_a_value = 5000 + seq,
    };
    cast_lib_duplicate_probe(&dup, seq);
    cast_lib_fallback_probe(&fallback, seq);
}
