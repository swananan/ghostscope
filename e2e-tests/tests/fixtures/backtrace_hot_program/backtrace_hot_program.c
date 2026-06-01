#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static volatile uint64_t hot_sink = 0;

typedef struct Dummy0 { uint64_t a; uint64_t b; char name[32]; } Dummy0;
typedef struct Dummy1 { uint64_t a; uint64_t b; char name[32]; } Dummy1;
typedef struct Dummy2 { uint64_t a; uint64_t b; char name[32]; } Dummy2;
typedef struct Dummy3 { uint64_t a; uint64_t b; char name[32]; } Dummy3;
typedef struct Dummy4 { uint64_t a; uint64_t b; char name[32]; } Dummy4;
typedef struct Dummy5 { uint64_t a; uint64_t b; char name[32]; } Dummy5;
typedef struct Dummy6 { uint64_t a; uint64_t b; char name[32]; } Dummy6;
typedef struct Dummy7 { uint64_t a; uint64_t b; char name[32]; } Dummy7;
typedef struct Dummy8 { uint64_t a; uint64_t b; char name[32]; } Dummy8;
typedef struct Dummy9 { uint64_t a; uint64_t b; char name[32]; } Dummy9;
typedef struct Dummy10 { uint64_t a; uint64_t b; char name[32]; } Dummy10;
typedef struct Dummy11 { uint64_t a; uint64_t b; char name[32]; } Dummy11;
typedef struct Dummy12 { uint64_t a; uint64_t b; char name[32]; } Dummy12;
typedef struct Dummy13 { uint64_t a; uint64_t b; char name[32]; } Dummy13;
typedef struct Dummy14 { uint64_t a; uint64_t b; char name[32]; } Dummy14;
typedef struct Dummy15 { uint64_t a; uint64_t b; char name[32]; } Dummy15;
typedef struct Dummy16 { uint64_t a; uint64_t b; char name[32]; } Dummy16;
typedef struct Dummy17 { uint64_t a; uint64_t b; char name[32]; } Dummy17;
typedef struct Dummy18 { uint64_t a; uint64_t b; char name[32]; } Dummy18;
typedef struct Dummy19 { uint64_t a; uint64_t b; char name[32]; } Dummy19;
typedef struct Dummy20 { uint64_t a; uint64_t b; char name[32]; } Dummy20;
typedef struct Dummy21 { uint64_t a; uint64_t b; char name[32]; } Dummy21;
typedef struct Dummy22 { uint64_t a; uint64_t b; char name[32]; } Dummy22;
typedef struct Dummy23 { uint64_t a; uint64_t b; char name[32]; } Dummy23;
typedef struct Dummy24 { uint64_t a; uint64_t b; char name[32]; } Dummy24;
typedef struct Dummy25 { uint64_t a; uint64_t b; char name[32]; } Dummy25;
typedef struct Dummy26 { uint64_t a; uint64_t b; char name[32]; } Dummy26;
typedef struct Dummy27 { uint64_t a; uint64_t b; char name[32]; } Dummy27;
typedef struct Dummy28 { uint64_t a; uint64_t b; char name[32]; } Dummy28;
typedef struct Dummy29 { uint64_t a; uint64_t b; char name[32]; } Dummy29;
typedef struct Dummy30 { uint64_t a; uint64_t b; char name[32]; } Dummy30;
typedef struct Dummy31 { uint64_t a; uint64_t b; char name[32]; } Dummy31;

/*
 * Keep a sizeable set of compact DWARF CFI rows before the real hot stack.
 * This makes the runtime row lookup exercise non-trivial map indexes instead
 * of only the first few rows.
 */
#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define DECL_BT_FILLER() \
    __attribute__((noinline, used, unused)) static uint64_t CAT(bt_filler_, __COUNTER__)(uint64_t value) \
    { \
        asm volatile("" : "+r"(value)); \
        return value + (uint64_t)__COUNTER__; \
    }
#define REPEAT_1(M) M()
#define REPEAT_2(M) REPEAT_1(M) REPEAT_1(M)
#define REPEAT_4(M) REPEAT_2(M) REPEAT_2(M)
#define REPEAT_8(M) REPEAT_4(M) REPEAT_4(M)
#define REPEAT_16(M) REPEAT_8(M) REPEAT_8(M)
#define REPEAT_32(M) REPEAT_16(M) REPEAT_16(M)
#define REPEAT_64(M) REPEAT_32(M) REPEAT_32(M)
#define REPEAT_128(M) REPEAT_64(M) REPEAT_64(M)
#define REPEAT_256(M) REPEAT_128(M) REPEAT_128(M)
#define REPEAT_512(M) REPEAT_256(M) REPEAT_256(M)

REPEAT_512(DECL_BT_FILLER)

__attribute__((noinline)) static uint64_t dummy_touch(uint64_t value)
{
    Dummy0 d0 = {value, value + 1, "d0"};
    Dummy7 d7 = {value + 7, value + 8, "d7"};
    Dummy15 d15 = {value + 15, value + 16, "d15"};
    Dummy31 d31 = {value + 31, value + 32, "d31"};
    return d0.a + d7.b + d15.a + d31.b;
}

__attribute__((noinline)) static void hot_bt_leaf(uint64_t value)
{
    hot_sink += dummy_touch(value);
    asm volatile("" ::: "memory");
}

__attribute__((noinline)) static void hot_bt_mid(uint64_t value)
{
    hot_bt_leaf(value + 1);
}

__attribute__((noinline)) void hot_bt_probe(uint64_t value)
{
    hot_bt_mid(value + 1);
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
    puts("backtrace_hot_program ready");

    for (uint64_t i = 0; keep_running; i++) {
        hot_bt_probe(i);
        usleep(1000);
    }

    return (int)(hot_sink & 1);
}
