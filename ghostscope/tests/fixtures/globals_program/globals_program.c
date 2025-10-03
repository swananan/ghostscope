#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "globals_program.h"
#include "gvars_lib.h"

// Executable-level globals
int g_counter = 42;                         // .data
static int s_internal = 7;                  // .data
static int s_bss_counter;                    // .bss
const char g_message[] = "Hello, Global!";   // .rodata
char g_bss_buffer[1024];                     // .bss

// Complex global state
GlobalState G_STATE = {"INIT", 0, {0, 0.0}, {1, 2, 3, 4}}; // .data

static void tick_once(int i) {
    // Local aliases to globals to expose via DWARF at this PC
    GlobalState* s = &G_STATE;
    GlobalState* ls = &LIB_STATE;
    volatile int* p_s_internal = &s_internal;
    volatile int* p_s_bss = &s_bss_counter;
    volatile int* p_lib_internal = lib_get_internal_counter_ptr();
    const char* gm = g_message;
    const char* lm = lib_message;
    char* gb = g_bss_buffer;
    char* lb = lib_bss;
    // mutate executable globals
    g_counter += 1;
    s_internal += 2;
    s_bss_counter += 3;

    // update complex state
    G_STATE.counter += 1;
    G_STATE.inner.x += (i % 5);
    G_STATE.inner.y += 0.5;
    G_STATE.array[(unsigned)i % 4] += i;
    if ((i % 8) == 0) {
        strncpy(G_STATE.name, "RUNNING", sizeof(G_STATE.name) - 1);
        G_STATE.name[sizeof(G_STATE.name) - 1] = '\0';
    }

    // touch rodata and bss (keep locals live as well)
    (void)gm;
    (void)lm;
    // Perform a volatile read to ensure DWARF keeps locations for these aliases
    volatile int sink = *p_s_internal + *p_s_bss + *p_lib_internal;
    (void)sink;
    gb[0] = (char)(gb[0] + 1);
    lb[0] = (char)(lb[0] + 1);

    if (i % 2 == 0) {
        G_STATE.lib = NULL;
    } else {
        G_STATE.lib = &LIB_STATE;
    }
    // tick library globals
    lib_tick();
}

int main() {
    // warm-up
    for (int j = 0; j < 2; j++) {
        tick_once(j);
    }

    // long-running loop
    int i = 0;
    while (i < 20000) {
        tick_once(i);
        i++;
        sleep(1);
    }
    return 0;
}
