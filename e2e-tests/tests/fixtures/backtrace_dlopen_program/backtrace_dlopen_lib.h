#ifndef BACKTRACE_DLOPEN_LIB_H
#define BACKTRACE_DLOPEN_LIB_H

#include <stdint.h>

typedef uint64_t (*dlopen_callback_fn)(uint64_t value);
typedef uint64_t (*dlopen_lib_driver_fn)(uint64_t value, dlopen_callback_fn callback);

uint64_t dlopen_lib_driver(uint64_t value, dlopen_callback_fn callback);

#endif
