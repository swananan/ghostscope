#include <stdio.h>
#include <unistd.h>

struct EntryState {
    int total_bytes;
    int stream_id;
};

static struct EntryState g_states[2] = {
    {10, 8},
    {20, 9},
};

__attribute__((noinline)) static int touch(int x, struct EntryState *state) {
    asm volatile("" : : "r"(state) : "memory");
    return x * 3;
}

__attribute__((noinline)) static int wrapper_state(int seed, struct EntryState *state) {
    int combined = touch(seed, state);
    int after_call = state->total_bytes + combined;
    if (after_call & 1) {
        after_call += state->stream_id;
    }
    asm volatile("" ::: "rbx", "memory");
    asm volatile("" : "+r"(after_call) :: "memory");
    return after_call;
}

int main(void) {
    volatile int sink = 0;
    int i = 1;

    setvbuf(stdout, NULL, _IONBF, 0);

    while (i < 20000) {
        struct EntryState *state = &g_states[i & 1];
        int result = wrapper_state(i, state);
        printf("ACTUAL:%d:%d:%d:%d\n", i, state->total_bytes, state->stream_id, result);
        sink = result;
        i++;
        usleep(10000);
    }

    return sink == 42 ? 0 : 0;
}
