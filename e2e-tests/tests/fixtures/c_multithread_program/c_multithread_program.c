#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

enum {
    WORKER_COUNT = 3,
    TLS_WORKER_STRIDE = 100000,
};

static volatile int multithread_sink;
static _Thread_local volatile int worker_tls_counter = -1;

typedef struct WorkerConfig {
    int worker_id;
} WorkerConfig;

__attribute__((noinline)) void multithread_tls_probe(
    int worker_id,
    int iter,
    volatile int *tls_valuep,
    int tls_snapshot)
{
    multithread_sink += worker_id + iter + *tls_valuep + tls_snapshot;
    asm volatile("" ::: "memory");
}

static void *worker_main(void *data)
{
    const WorkerConfig *config = (const WorkerConfig *)data;

    for (int iter = 0;; iter++) {
        worker_tls_counter = config->worker_id * TLS_WORKER_STRIDE + iter;
        volatile int *tls_valuep = &worker_tls_counter;
        int tls_snapshot = worker_tls_counter;

        multithread_tls_probe(config->worker_id, iter, tls_valuep, tls_snapshot);
        usleep(50000);
    }

    return NULL;
}

int main(void)
{
    pthread_t threads[WORKER_COUNT];
    WorkerConfig configs[WORKER_COUNT];

    for (int i = 0; i < WORKER_COUNT; i++) {
        configs[i].worker_id = i + 1;
        int rc = pthread_create(&threads[i], NULL, worker_main, &configs[i]);
        if (rc != 0) {
            fprintf(stderr, "pthread_create failed for worker %d: %d\n", i + 1, rc);
            return 1;
        }
    }

    for (int i = 0; i < WORKER_COUNT; i++) {
        int rc = pthread_join(threads[i], NULL);
        if (rc != 0) {
            fprintf(stderr, "pthread_join failed for worker %d: %d\n", i + 1, rc);
            return 1;
        }
    }

    return 0;
}
