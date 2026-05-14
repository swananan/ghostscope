#include <unistd.h>

volatile int short_lived_global = 41;

__attribute__((noinline)) int short_lived_probe(void) {
    return short_lived_global;
}

int main(void) {
    /*
     * Give sysmon a narrow window to consume sched_process_exec and prefill
     * offsets, then fire exactly one probe before periodic refresh can recover
     * a missed exec event.
     */
    usleep(100000);
    int value = short_lived_probe();
    usleep(10000);
    return value == 41 ? 0 : 1;
}
