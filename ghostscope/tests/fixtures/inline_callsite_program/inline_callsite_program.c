#include <unistd.h>

/*
 * This fixture covers optimized inline-call scenarios.
 *
 * Useful check:
 *   dwarfdump inline_callsite_program | rg 'DW_TAG_(subprogram|inlined_subroutine|formal_parameter|lexical_block)' -A5 -B2
 *
 * What this fixture is trying to model:
 *
 * 1. add3(a, b, c) is declared inline and is actually inlined into wrapper().
 * 2. consume_state(state, delta) is declared inline and is actually inlined into
 *    wrapper_state().
 * 3. The inlined bodies still need to expose both scalar parameters and an
 *    aggregate pointer parameter to tracing.
 * 4. The inlined bodies also contain nested lexical blocks, so the DWARF has both:
 *    - direct children under the inline site
 *    - deeper descendants inside that inline site
 *
 * The resulting DWARF shape is useful because it contains both sides of inline
 * parameter recovery and chain access:
 *
 *   wrapper
 *     inlined_subroutine
 *       formal_parameter ...
 *       formal_parameter ...
 *       formal_parameter ...
 *       lexical_block
 *
 *   add3
 *     formal_parameter a
 *     formal_parameter b
 *     formal_parameter c
 *     lexical_block
 *
 * In other words, this fixture is meant to answer:
 * "When we trace a line inside an optimized inline body, can we still recover
 * all inline parameters correctly, and can we still perform member access from
 * an inline aggregate parameter, even when that inline site also has nested
 * scope under it?"
 */
static inline __attribute__((always_inline)) int add3(int a, int b, int c) {
    int t = a + b + c;
    if (t & 1) {
        int k = c + 1;
        return t + k;
    }
    return t - c;
}

__attribute__((noinline)) int wrapper(int n) {
    return add3(n, n + 1, n + 2);
}

struct InlineState {
    int total_bytes;
    int stream_id;
};

static struct InlineState g_inline_states[2] = {
    {10, 8},
    {20, 9},
};

static inline __attribute__((always_inline)) int consume_state(
    struct InlineState *state,
    int delta
) {
    int total = state->total_bytes + delta;
    if (total & 1) {
        int bonus = state->stream_id + delta;
        return total + bonus;
    }
    return total - state->stream_id;
}

__attribute__((noinline)) static struct InlineState *pick_state(int n) {
    return &g_inline_states[n & 1];
}

__attribute__((noinline)) int wrapper_state(int n) {
    return consume_state(pick_state(n), n);
}

int main(void) {
    volatile int sink = 0;
    int i = 0;

    while (i < 20000) {
        sink = wrapper(i) + wrapper_state(i);
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
