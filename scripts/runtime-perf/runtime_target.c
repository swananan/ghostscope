#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct RuntimePayload {
    uint64_t index;
    struct {
        uint64_t low;
        uint64_t high;
    } bounds;
    uint64_t values[16];
    char label[32];
};

static volatile uint64_t bench_sink;

__attribute__((noinline, noclone))
static uint64_t runtime_hot_fn(struct RuntimePayload *payload, uint64_t seed,
                               unsigned long inner_work) {
    uint64_t acc = seed ^ payload->index;
    for (unsigned long i = 0; i < inner_work; ++i) {
        acc ^= acc << 13;
        acc ^= acc >> 7;
        acc ^= acc << 17;
        acc += (uint64_t)i + 0x94d049bb133111ebULL;
    }
    bench_sink ^= acc;
    return acc;
}

/* Retain a known application call chain for the DWARF backtrace workload. */
__attribute__((noinline, noclone))
static uint64_t runtime_layer_1(struct RuntimePayload *p, uint64_t s, unsigned long n) {
    return runtime_hot_fn(p, s, n) ^ bench_sink;
}

__attribute__((noinline, noclone))
static uint64_t runtime_layer_2(struct RuntimePayload *p, uint64_t s, unsigned long n) {
    return runtime_layer_1(p, s, n) + bench_sink;
}

__attribute__((noinline, noclone))
static uint64_t runtime_layer_3(struct RuntimePayload *p, uint64_t s, unsigned long n) {
    return runtime_layer_2(p, s, n) ^ bench_sink;
}

static uint64_t monotonic_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static unsigned long parse_arg(const char *raw) {
    char *end;
    errno = 0;
    unsigned long value = strtoul(raw, &end, 10);
    if (errno || end == raw || *end || raw[0] == '-' || !value) {
        fprintf(stderr, "invalid argument: %s\n", raw);
        exit(2);
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <iterations> <inner_work>\n", argv[0]);
        return 2;
    }
    unsigned long iterations = parse_arg(argv[1]);
    unsigned long inner_work = parse_arg(argv[2]);
    struct RuntimePayload payload = {
        .bounds = {11, 97},
        .values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
        .label = "runtime-performance",
    };
    fprintf(stderr, "READY pid=%ld\n", (long)getpid());
    fflush(stderr);
    if (fgetc(stdin) == EOF) {
        return 3;
    }

    uint64_t seed = 0x243f6a8885a308d3ULL;
    uint64_t started = monotonic_now_ns();
    for (unsigned long i = 0; i < iterations; ++i) {
        payload.index = i;
        seed = runtime_layer_3(&payload, seed + i, inner_work);
    }
    uint64_t elapsed_ns = monotonic_now_ns() - started;
    printf("RESULT iterations=%lu inner_work=%lu elapsed_ns=%" PRIu64
           " sink=%" PRIu64 "\n", iterations, inner_work, elapsed_ns, bench_sink ^ seed);
    fflush(stdout);

    /* Keep maps and the watched PID alive while userspace drains trace output.
     * Draining and observer shutdown are outside the timed target interval. */
    return fgetc(stdin) == EOF ? 3 : 0;
}
