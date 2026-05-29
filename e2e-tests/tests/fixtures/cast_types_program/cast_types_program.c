#include <stdint.h>
#include <unistd.h>

#include "cast_types_program.h"

enum CastKind {
    CAST_KIND_ZERO = 0,
    CAST_KIND_ONE = 1,
    CAST_KIND_NEG = -1,
};

union CastPayload {
    int signed_value;
    uint32_t unsigned_value;
    char bytes[4];
};

typedef struct CastNode {
    uint32_t words[4];
    union CastPayload payload;
    enum CastKind kind;
    int negative;
    unsigned long long wide;
    void *opaque;
    const volatile struct CastNode *qualified_next;
} CastNode;

struct Duplicate {
    int main_marker;
    int main_value;
};

volatile unsigned long long cast_types_shared_sink;

__attribute__((noinline)) void cast_main_duplicate_probe(struct Duplicate *dup, CastNode *node, void *raw_words,
                                                         int seq) {
    dup->main_value += seq & 1;
    cast_types_shared_sink +=
        (unsigned long long)dup->main_marker +
        (unsigned long long)dup->main_value +
        (unsigned long long)node->words[seq & 3] +
        (unsigned long long)node->payload.unsigned_value +
        (unsigned long long)(uintptr_t)raw_words;
}

int main(void) {
    CastNode node = {0};
    struct Duplicate dup = {0};

    for (int seq = 0; seq < 20000; seq++) {
        for (int i = 0; i < 4; i++) {
            node.words[i] = (uint32_t)(seq * 10 + i);
        }
        node.payload.signed_value = 700 + seq;
        node.kind = CAST_KIND_ONE;
        node.negative = -1;
        node.wide = 0xff00ULL + (unsigned long long)seq;
        node.opaque = node.words;
        node.qualified_next = &node;

        dup.main_marker = 1000 + seq;
        dup.main_value = 1100 + seq;

        cast_main_duplicate_probe(&dup, &node, node.words, seq);
        cast_call_lib(seq);
        cast_call_extra_lib(seq);
        usleep(200000);
    }

    return (int)(cast_types_shared_sink == 0);
}
