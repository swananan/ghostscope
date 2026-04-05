#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

static volatile uint64_t bench_sink = 0;

__attribute__((noinline, noclone))
static uint64_t bench_hot_fn(int x, uint64_t seed, unsigned long inner_work) {
    uint64_t acc = ((uint64_t)(uint32_t)x << 32) ^ seed ^ 0x9e3779b97f4a7c15ULL;
    volatile uint64_t local_probe = acc ^ 0xdbe6d5d5fe4cce2fULL;
    local_probe ^= (seed >> 11) + 0x100000001b3ULL; /* BENCH_LOCAL_PROBE_LINE */

    for (unsigned long i = 0; i < inner_work; ++i) {
        acc ^= acc << 13;
        acc ^= acc >> 7;
        acc ^= acc << 17;
        acc += (uint64_t)i + 0x94d049bb133111ebULL;
    }

    bench_sink ^= acc ^ (uint64_t)local_probe;
    return acc;
}

static uint64_t monotonic_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static unsigned long parse_arg(const char *raw, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, raw);
        exit(2);
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <iterations> <inner_work>\n", argv[0]);
        return 2;
    }

    const unsigned long iterations = parse_arg(argv[1], "iterations");
    const unsigned long inner_work = parse_arg(argv[2], "inner_work");

#ifdef __linux__
#ifdef PR_SET_PTRACER
    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
#endif

    fprintf(stderr, "READY pid=%ld\n", (long)getpid());
    fflush(stderr);

    if (fgetc(stdin) == EOF) {
        fprintf(stderr, "stdin barrier was not released\n");
        return 3;
    }

    uint64_t seed = 0x243f6a8885a308d3ULL;
    const uint64_t start_ns = monotonic_now_ns();

    for (unsigned long i = 0; i < iterations; ++i) {
        seed = bench_hot_fn((int)i, seed + (uint64_t)i, inner_work);
    }

    const uint64_t elapsed_ns = monotonic_now_ns() - start_ns;
    printf(
        "RESULT iterations=%lu inner_work=%lu elapsed_ns=%" PRIu64 " sink=%" PRIu64 "\n",
        iterations,
        inner_work,
        elapsed_ns,
        bench_sink ^ seed
    );
    fflush(stdout);
    return 0;
}
