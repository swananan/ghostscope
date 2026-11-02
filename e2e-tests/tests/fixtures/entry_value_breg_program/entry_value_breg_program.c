#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void clobber_regs(int value) {
#if defined(__aarch64__)
    asm volatile("" : : "r"(value)
                 : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                   "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                   "x16", "x17", "memory");
#else
    asm volatile("" : : "r"(value)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
                   "r11", "memory");
#endif
}

__attribute__((noinline)) int stack_entry_target(
    int a1,
    int a2,
    int a3,
    int a4,
    int a5,
    int a6,
#if defined(__aarch64__)
    int a7,
    int a8,
#endif
    int payload
) {
    volatile int scratch[8];
    int sum = a1 + a2 + a3 + a4 + a5 + a6;
#if defined(__aarch64__)
    sum += a7 + a8;
#endif
    scratch[0] = sum;
    scratch[7] = payload;
    clobber_regs(scratch[0]);
    asm volatile(
        ".globl entry_value_breg_anchor\n"
        "entry_value_breg_anchor:\n"
        :
        :
        : "memory");
    return scratch[7] * 5 + a4;
}

int main(void) {
    volatile int sink = 0;
    int i = 1;

    setvbuf(stdout, NULL, _IONBF, 0);

    while (i < 20000) {
        int result = stack_entry_target(11, 12, 13, 14, 15, 16,
#if defined(__aarch64__)
                                        17, 18,
#endif
                                        i);
        printf("ACTUAL:%d:%d\n", i, result);
        sink = result;
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
