#include "backtrace_dlopen_lib.h"

#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static volatile uint64_t dlopen_main_sink = 0;

__attribute__((noinline)) uint64_t dlopen_main_callback(uint64_t value)
{
    dlopen_main_sink += value;
    asm volatile("" ::: "memory");
    return dlopen_main_sink;
}

static int trigger_exists(void)
{
    return access("dlopen.trigger", F_OK) == 0;
}

static void wait_for_trigger(void)
{
    while (keep_running && !trigger_exists()) {
        usleep(1000);
    }
}

static void handle_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

int main(void)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("backtrace_dlopen_program ready");

    wait_for_trigger();
    if (!keep_running) {
        return 0;
    }

    void *handle = dlopen("./libbacktrace_dlopen_target.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    dlopen_lib_driver_fn driver = (dlopen_lib_driver_fn)dlsym(handle, "dlopen_lib_driver");
    if (driver == NULL) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 3;
    }

    puts("backtrace_dlopen_program loaded");
    for (uint64_t i = 0; keep_running; i++) {
        dlopen_main_sink += driver(i, dlopen_main_callback);
        usleep(1000);
    }

    return 0;
}
