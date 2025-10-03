#ifndef GVARS_LIB_H
#define GVARS_LIB_H

#include "globals_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

// Library-level globals
extern int lib_counter;            // .data
extern const char lib_message[];   // .rodata
extern char lib_bss[512];          // .bss
extern GlobalState LIB_STATE;      // .data

// Ticking function to mutate library globals periodically
void lib_tick(void);

// Accessor for internal static counter (not directly visible outside TU)
int* lib_get_internal_counter_ptr(void);

#ifdef __cplusplus
}
#endif

#endif // GVARS_LIB_H
