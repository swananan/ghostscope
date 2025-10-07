#include "gvars_lib.h"
#include <string.h>

// Visible globals
int lib_counter = 100;                 // .data
const char lib_message[] = "LIB_MESSAGE"; // .rodata
char lib_bss[512];                      // .bss (zero-initialized)
GlobalState LIB_STATE = {"LIB", 1, {123, 4.5}, {9,8,7,6}}; // .data
// 300-byte pattern buffer for tests (filled at library load)
unsigned char lib_pattern[300]; // .bss -> becomes .data after constructor fills

// Internal file-scope static (should appear as static in DWARF)
static int lib_internal_counter;        // .bss
static const char lib_internal_const[] = "LIB_INTERNAL"; // .rodata

void lib_tick(void) {
    lib_counter += 3;
    lib_internal_counter += 5;
    if (LIB_STATE.counter < 0) {
        LIB_STATE.counter = 0;
    }
    LIB_STATE.counter += 2;
    LIB_STATE.inner.x += 11;
    LIB_STATE.inner.y += 1.25;
    for (int i = 0; i < 4; i++) {
        LIB_STATE.array[i] += 1;
    }
    // touch rodata references to keep them live
    (void)lib_message;
    (void)lib_internal_const;
    // keep lib_bss referenced
    lib_bss[0] = (char)(lib_bss[0] + 1);
}

int* lib_get_internal_counter_ptr(void) {
    return &lib_internal_counter;
}

// Initialize lib_pattern with a simple ascending pattern: 0x00,0x01,...,0xFF,0x00,... (length 300)
#if defined(__GNUC__)
__attribute__((constructor))
#endif
static void init_lib_pattern(void) {
    for (int i = 0; i < 300; i++) {
        lib_pattern[i] = (unsigned char)(i & 0xFF);
    }
}
