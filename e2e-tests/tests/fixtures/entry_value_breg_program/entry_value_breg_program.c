#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void clobber_regs(int value) {
    asm volatile("" : : "r"(value)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
                   "r11", "memory");
}

__attribute__((noinline)) int stack_entry_target(
    int a1,
    int a2,
    int a3,
    int a4,
    int a5,
    int a6,
    int payload
) {
    volatile int scratch[8];
    int sum = a1 + a2 + a3 + a4 + a5 + a6;
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
        int result = stack_entry_target(11, 12, 13, 14, 15, 16, i);
        printf("ACTUAL:%d:%d\n", i, result);
        sink = result;
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
