#ifndef COMPLEX_TYPES_PROGRAM_H
#define COMPLEX_TYPES_PROGRAM_H

enum Status {
    STATUS_INACTIVE = 0,
    STATUS_ACTIVE = 1,
    STATUS_ERROR = -1
};

union Data {
    int i;
    double d;
};

struct Complex {
    char name[16];
    unsigned int age;
    enum Status status;
    union Data data;
    int arr[8];
    unsigned active:1;
    int flags:3;
    struct Complex* friend_ref;
};

void update_complex(struct Complex* c, int i);

#endif // COMPLEX_TYPES_PROGRAM_H

