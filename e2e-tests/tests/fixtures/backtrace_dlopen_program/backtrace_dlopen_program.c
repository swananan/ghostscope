#include "backtrace_dlopen_lib.h"

#include <dlfcn.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_DLOPEN_MODULES 128

static volatile sig_atomic_t keep_running = 1;
static volatile uint64_t dlopen_main_sink = 0;

__attribute__((noinline)) uint64_t dlopen_main_callback(uint64_t value)
{
    dlopen_main_sink += value;
    asm volatile("" ::: "memory");
    return dlopen_main_sink;
}

__attribute__((noinline)) uint64_t dlopen_main_heartbeat(uint64_t value)
{
    dlopen_main_sink += value;
    asm volatile("" ::: "memory");
    return dlopen_main_sink;
}

__attribute__((noinline)) uint64_t dlopen_main_after_limit_heartbeat(uint64_t value)
{
    dlopen_main_sink += value;
    asm volatile("" ::: "memory");
    return dlopen_main_sink;
}

static int trigger_exists(void)
{
    return access("dlopen.trigger", F_OK) == 0;
}

static int after_limit_trigger_exists(void)
{
    return access("dlopen.after_limit.trigger", F_OK) == 0;
}

static void wait_for_trigger(void)
{
    while (keep_running && !trigger_exists()) {
        usleep(1000);
    }
}

static size_t read_module_paths(char paths[][PATH_MAX])
{
    FILE *trigger = fopen("dlopen.trigger", "r");
    if (trigger == NULL) {
        perror("failed to open dlopen.trigger");
        return 0;
    }

    size_t count = 0;
    while (count < MAX_DLOPEN_MODULES && fgets(paths[count], PATH_MAX, trigger) != NULL) {
        paths[count][strcspn(paths[count], "\r\n")] = '\0';
        if (paths[count][0] != '\0') {
            count++;
        }
    }
    if (ferror(trigger)) {
        perror("failed to read dlopen.trigger");
        fclose(trigger);
        return 0;
    }
    fclose(trigger);

    if (count == 0) {
        snprintf(paths[0], PATH_MAX, "%s", "./libbacktrace_dlopen_target.so");
        count = 1;
    }
    return count;
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

    char module_paths[MAX_DLOPEN_MODULES][PATH_MAX];
    void *handles[MAX_DLOPEN_MODULES] = {0};
    dlopen_lib_driver_fn drivers[MAX_DLOPEN_MODULES] = {0};
    size_t module_count = read_module_paths(module_paths);
    if (module_count == 0) {
        return 2;
    }

    for (size_t i = 0; i < module_count; i++) {
        handles[i] = dlopen(module_paths[i], RTLD_NOW | RTLD_LOCAL);
        if (handles[i] == NULL) {
            fprintf(stderr, "dlopen failed for %s: %s\n", module_paths[i], dlerror());
            return 3;
        }

        drivers[i] = (dlopen_lib_driver_fn)dlsym(handles[i], "dlopen_lib_driver");
        if (drivers[i] == NULL) {
            fprintf(stderr, "dlsym failed for %s: %s\n", module_paths[i], dlerror());
            return 4;
        }
    }

    printf("backtrace_dlopen_program loaded %zu module(s)\n", module_count);
    for (uint64_t i = 0; keep_running; i++) {
        size_t module_index = (size_t)(i % module_count);
        dlopen_main_sink += drivers[module_index](i, dlopen_main_callback);
        dlopen_main_sink += dlopen_main_heartbeat(i);
        if (after_limit_trigger_exists()) {
            dlopen_main_sink += dlopen_main_after_limit_heartbeat(i);
        }
        usleep(module_count > 1 ? 10000 : 1000);
    }

    for (size_t i = 0; i < module_count; i++) {
        dlclose(handles[i]);
    }

    return 0;
}
