#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ROUNDS 140
struct Payload { uint64_t value; };
static struct Payload *missing_page;
static struct Payload ready_page = {202};
static char comparison_a[601], comparison_b[601];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int run_b, cpu, round_number;
static volatile sig_atomic_t started;
static char status_path[128];

static void status(const char *message) {
    FILE *file = fopen(status_path, "w");
    if (file) { fprintf(file, "%s\n", message); fclose(file); }
}
static void fail(const char *what) {
    char message[256];
    snprintf(message, sizeof(message), "ERROR %s: %s", what, strerror(errno));
    status(message);
    exit(1);
}
static void start(int sig) { (void)sig; started = 1; }
static void pin(void) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus)) fail("affinity");
}

__attribute__((noinline)) void overlap_probe(int owner, struct Payload *page, int iteration, char *a, char *b) {
    // A reads a fresh anonymous page each round; B reads resident memory.
    volatile uint64_t value = page->value + owner + iteration;
    (void)value;
    asm volatile("" : : "r"(a), "r"(b) : "memory");
    asm volatile("" ::: "memory");
}
__attribute__((noinline)) static void overlap_chain(int depth, int owner, struct Payload *page) {
    if (depth) overlap_chain(depth - 1, owner, page);
    else overlap_probe(owner, page, round_number, comparison_a, comparison_b);
    asm volatile("" ::: "memory");
}
__attribute__((noinline)) void overlap_owner_a(void) { overlap_chain(6, 101, missing_page); }
__attribute__((noinline)) void overlap_owner_b(void) { overlap_chain(6, 202, &ready_page); }
static void *worker_a(void *arg) { (void)arg; pin(); overlap_owner_a(); return NULL; }
static void *worker_b(void *arg) {
    (void)arg;
    pin();
    pthread_mutex_lock(&mutex);
    while (!run_b) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    overlap_owner_b();
    return NULL;
}

int main(void) {
    snprintf(status_path, sizeof(status_path), "/tmp/ghostscope-overlap-%d.status", getpid());
    struct sigaction action = {.sa_handler = start};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) fail("sigaction");
    // Bound failure modes in case BPF loading or the controller fails.
    alarm(120);
    size_t size = (size_t)sysconf(_SC_PAGESIZE);
    missing_page = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (missing_page == MAP_FAILED) fail("mmap");
    cpu_set_t cpus;
    if (sched_getaffinity(0, sizeof(cpus), &cpus)) fail("sched_getaffinity");
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus); cpu++) {}
    if (cpu == CPU_SETSIZE) fail("empty affinity");
    memset(comparison_a, 'x', 600);
    memset(comparison_b, 'x', 600);
    // Keep the target's mappings stable after attach. Fresh pthread-managed
    // stacks can trigger asynchronous module-map refreshes during unwinding;
    // custom stacks also avoid libc discarding stack pages between rounds.
    const size_t stack_size = 1024 * 1024;
    pthread_attr_t attr_a, attr_b;
    if (pthread_attr_init(&attr_a) || pthread_attr_init(&attr_b)) fail("pthread_attr_init");
    void *stack_a = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    void *stack_b = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack_a == MAP_FAILED || stack_b == MAP_FAILED) fail("stack mmap");
    memset(stack_a, 0, stack_size);
    memset(stack_b, 0, stack_size);
    if (pthread_attr_setstack(&attr_a, stack_a, stack_size) ||
        pthread_attr_setstack(&attr_b, stack_b, stack_size)) fail("pthread_attr_setstack");
    // Warm pthread TLS/allocation paths and the complete call chain before
    // GhostScope snapshots the process mappings. These probes are not attached.
    pthread_t warm_a, warm_b;
    run_b = 1;
    if (pthread_create(&warm_b, &attr_b, worker_b, NULL) ||
        pthread_create(&warm_a, &attr_a, worker_a, NULL)) fail("warm pthread_create");
    pthread_join(warm_b, NULL);
    pthread_join(warm_a, NULL);
    status("READY");
    while (!started) usleep(10000);
    for (round_number = 0; round_number < ROUNDS; round_number++) {
        run_b = 0;
        if (madvise(missing_page, size, MADV_DONTNEED)) fail("madvise");
        pthread_t a, b;
        if (pthread_create(&b, &attr_b, worker_b, NULL) || pthread_create(&a, &attr_a, worker_a, NULL)) fail("pthread_create");
        pthread_mutex_lock(&mutex);
        run_b = 1;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
        pthread_join(b, NULL);
        pthread_join(a, NULL);
        usleep(1000);
    }
    pthread_attr_destroy(&attr_a);
    pthread_attr_destroy(&attr_b);
    status("DONE 140");
    // Keep the target alive until the tracing controller has drained events.
    for (;;) pause();
}
