#include <unistd.h>

/*
 * This fixture intentionally contains both:
 *   1. a file-scope static
 *   2. a function-scope static
 *
 * The file-scope static is the stable control case for index lookups.
 * The function-scope static is present so the same fixture can be rebuilt with
 * clang/DWARF5 and used to exercise DW_OP_addrx-based static locations.
 */
static int file_scope_static_counter = 17;

static int bump_counters(int seed) {
    static int function_scope_static_counter = 41;
    int regular_local = seed + 3;

    function_scope_static_counter += regular_local;
    file_scope_static_counter += 1;
    return function_scope_static_counter + file_scope_static_counter + regular_local;
}

static int binding_scope_one(void);
static int binding_scope_unrelated(void);
extern int binding_scope_two(void);
extern int binding_state;

int main(void) {
    while (1) {
        int snapshot = bump_counters(2);
        snapshot += binding_scope_one() + binding_scope_two();
        snapshot += binding_scope_unrelated();
        if (snapshot == -1) {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

static struct { int own; int common; } cfg = {11, 1};

__attribute__((noinline)) static int binding_scope_one(void) {
    return cfg.own + cfg.common + binding_state;
}

__attribute__((noinline)) static int binding_scope_unrelated(void) {
    static int binding_state = 999;
    static struct { int own; int common; } cfg = {777, 778};
    return binding_state + cfg.own + cfg.common;
}
