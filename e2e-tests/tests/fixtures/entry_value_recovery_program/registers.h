#if defined(__aarch64__)
#define ENTRY_VALUE_CALLEE_SAVED_REGISTER "x19"
#else
#define ENTRY_VALUE_CALLEE_SAVED_REGISTER "rbx"
#endif
