#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * This fixture is meant to produce a DW_AT_ranges-backed subprogram with a
 * cold partition that can sort before the real entry address.
 *
 * Useful manual checks:
 *   nm -an partitioned_ranges_program | rg 'partitioned_target(\.cold)?'
 *   readelf --debug-dump=Ranges partitioned_ranges_program
 */

static volatile int cold_trigger = 0;
static volatile int global_sink = 0;

__attribute__((noinline)) int partitioned_target(int x) {
    if (__builtin_expect(cold_trigger != 0, 0)) {
        volatile int acc = x;

        acc = acc * 3 + 11;
        acc = acc * 5 - 7;
        acc = acc * 7 + 13;
        acc = acc * 11 - 17;
        acc = acc * 13 + 19;
        acc = acc * 17 - 23;
        acc = acc * 19 + 29;
        acc = acc * 23 - 31;
        acc = acc * 29 + 37;
        acc = acc * 31 - 41;
        acc = acc * 37 + 43;
        acc = acc * 41 - 47;
        acc = acc * 43 + 53;
        acc = acc * 47 - 59;
        acc = acc * 53 + 61;
        acc = acc * 59 - 67;

        global_sink = acc;
        abort();
    }

    global_sink += x;
    return x + 1;
}

int main(void) {
    volatile int input = 1;

    for (int i = 0; i < 20000; ++i) {
        input = (i & 1023) + 1;
        global_sink += partitioned_target(input);
        usleep(1000);
    }

    return global_sink == 42 ? 0 : 0;
}
