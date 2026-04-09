#ifndef GLOBALS_SHARED_H
#define GLOBALS_SHARED_H

typedef struct {
    int x;
    double y;
} Inner;

typedef struct GlobalState {
    char name[32];
    int counter;
    Inner inner;
    int array[4];
    struct GlobalState* lib; // pointer to library GlobalState for deref-chain tests
} GlobalState;

#endif // GLOBALS_SHARED_H
