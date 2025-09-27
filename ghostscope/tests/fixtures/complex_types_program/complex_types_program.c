#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "complex_types_program.h"

void update_complex(struct Complex* c, int i) {
    if (!c) return;
    c->age += 1;
    c->status = (i % 2) ? STATUS_ACTIVE : STATUS_INACTIVE;
    c->data.i = i;
    c->arr[i % 8] = i * 2;
    c->active = (i & 1);
    c->flags = (i & 0x7);
    if (c->friend_ref) {
        c->friend_ref->age += 1;
    }
}

int main() {
    struct Complex a = {"Alice", 25, STATUS_INACTIVE, {.i = 0}, {0}, 1, 0, NULL};
    struct Complex b = {"Bob", 30, STATUS_ACTIVE, {.i = 0}, {0}, 0, 0, &a};

    int i = 0;
    while (i < 20000) {
        update_complex(&a, i);
        update_complex(&b, i);
        i++;
        sleep(1);
    }
    return 0;
}

