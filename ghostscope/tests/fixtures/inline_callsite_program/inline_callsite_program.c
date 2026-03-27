#include <unistd.h>

/*
 * This fixture covers an optimized inline-call scenario.
 *
 * Useful check:
 *   dwarfdump inline_callsite_program | rg 'DW_TAG_(subprogram|inlined_subroutine|formal_parameter|lexical_block)' -A5 -B2
 *
 * What this fixture is trying to model:
 *
 * 1. add3(a, b, c) is declared inline and is actually inlined into wrapper().
 * 2. The inlined body still needs to expose all three parameters a/b/c to tracing.
 * 3. The inlined body also contains a nested lexical block, so the DWARF has both:
 *    - direct children under the inline site
 *    - deeper descendants inside that inline site
 *
 * The resulting DWARF shape is useful because it contains both sides of inline
 * parameter recovery:
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
 * all inline parameters correctly, even when that inline site also has nested
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

int main(void) {
    volatile int sink = 0;
    int i = 0;

    while (i < 20000) {
        sink = wrapper(i);
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
