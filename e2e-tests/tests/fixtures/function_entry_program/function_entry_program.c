#include <unistd.h>

static volatile int sink;

/* With GCC -O2, the first is_stmt PC after entry is in the negative branch.
 * x/y keep fixed register expressions rather than location lists here. */
__attribute__((noinline)) int register_branch(int x, int y) {
    if (x < 0) {
        sink += y;
        return x - y;
    }
    return x + y;
}

/* Changing x also exercises a parameter described by an optimized loclist. */
__attribute__((noinline)) int loclist_branch(int x, int y) {
    if (x < 0) {
        sink += y;
        x -= y;
    }
    return x + y;
}

/* Incoming stack arguments use fixed fbreg expressions even with -O2. */
__attribute__((noinline)) int stack_branch(
    int a, int b, int c, int d, int e, int f, int x, int y
) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    if (x < 0) {
        sink += y;
        return x - y;
    }
    return x + y;
}

/* Keep IPA from cloning stack_branch with a reduced register-only ABI. */
typedef int (*stack_branch_fn)(int, int, int, int, int, int, int, int);
static stack_branch_fn volatile call_stack_branch = stack_branch;

/* GCC -O0 uses fixed RSP-relative locations after stack realignment. */
__attribute__((noinline)) int realigned_spill(int x, int y) {
    _Alignas(64) volatile int buf[16];
    buf[0] = x;
    buf[15] = y;
    return buf[0] + buf[15];
}

/* These nonnegative CFA offsets are callee-initialized register home slots. */
__attribute__((ms_abi, noinline)) int home_slot_spill(int x, int y) {
    return x + y;
}

/* Reuse the caller's shadow space with different values before the traced call. */
__attribute__((ms_abi, noinline)) int poison_home_slots(int x, int y) {
    return x + y;
}

int main(void) {
    for (int i = 0; i < 20000; ++i) {
        sink = register_branch(7, 31);
        sink = register_branch(-7, 31);
        sink = loclist_branch(7, 31);
        sink = loclist_branch(-7, 31);
        sink = call_stack_branch(1, 2, 3, 4, 5, 6, 7, 31);
        sink = call_stack_branch(1, 2, 3, 4, 5, 6, -7, 31);
        sink = realigned_spill(7, 31);
        sink = realigned_spill(-7, 31);
        sink = poison_home_slots(101, 202);
        sink = home_slot_spill(7, 31);
        sink = poison_home_slots(101, 202);
        sink = home_slot_spill(-7, 31);
        usleep(10000);
    }
    return 0;
}
