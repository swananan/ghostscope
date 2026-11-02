#include <unistd.h>

volatile long architecture_global = 73;
__thread long architecture_tls = 91;

__attribute__((noinline)) void architecture_probe(long a, long b, long c, long d,
                                                 long e, long f, long g, long h) {
    asm volatile("" : : "r"(a), "r"(b), "r"(c), "r"(d), "r"(e), "r"(f),
                 "r"(g), "r"(h) : "memory");
}

int main(void) {
    for (;;) {
        architecture_probe(11, 22, 33, 44, 55, 66, 77, 88);
        /* Keep a real TLS reference in the executable for ARM TLS tests. */
        architecture_tls++;
        usleep(10000);
    }
}
