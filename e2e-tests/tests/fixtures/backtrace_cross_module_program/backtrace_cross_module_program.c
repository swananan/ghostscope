#include "backtrace_cross_module_lib.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static volatile unsigned long cross_module_main_sink = 0;

__attribute__((noinline)) static unsigned long cross_module_main_caller(unsigned long value)
{
    unsigned long result = cross_module_lib_probe(value + 1);
    asm volatile("" ::: "memory");
    return result;
}

__attribute__((noinline)) static void cross_module_main_loop(unsigned long value)
{
    cross_module_main_sink += cross_module_main_caller(value + 1);
    asm volatile("" ::: "memory");
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
    puts("backtrace_cross_module_program ready");

    for (unsigned long i = 0; keep_running; i++) {
        cross_module_main_loop(i);
        usleep(1000);
    }

    return (int)(cross_module_main_sink & 1);
}
