#include <unistd.h>

/*
 * This fixture targets a specific inline-parameter recovery bug:
 * the traced line is after an internal call made from an inlined body, so the
 * original inline parameters may be optimized out while the inline DIE still
 * contains call_site_parameter children for that internal call.
 */
__attribute__((noinline)) static int consume_pair(int lhs, int rhs) {
    asm volatile("" ::: "memory");
    return lhs * rhs;
}

static inline __attribute__((always_inline)) int inline_after_call(
    int original_x,
    int original_y
) {
    // Keep this on the first executable pre-call line so tests can assert the
    // original inline parameters before consume_pair's call-site clobbers them.
    asm volatile("" : "+r"(original_x), "+r"(original_y) :: "memory");
    int combined = consume_pair(original_x + original_y, original_x - original_y);
    int after_call = combined + 7;
    if (after_call & 1) {
        after_call += 3;
    } else {
        after_call -= 2;
    }
    // Keep this on the first executable line after the post-call work.
    asm volatile("" : "+r"(after_call) :: "memory");
    return after_call;
}

__attribute__((noinline)) static int wrapper(int seed) {
    int local_x = seed * 7;
    int local_y = seed + 11;

    asm volatile("" : "+r"(local_x), "+r"(local_y) :: "memory");
    return inline_after_call(local_x, local_y);
}

int main(void) {
    volatile int sink = 0;
    int i = 1;

    while (i < 20000) {
        sink = wrapper(i);
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
