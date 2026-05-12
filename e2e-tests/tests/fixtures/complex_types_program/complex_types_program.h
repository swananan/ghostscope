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

extern volatile unsigned long long ghostscope_complex_sink;

#define GHOSTSCOPE_COMPLEX_TOUCH(c_, i_) \
    do { \
        ghostscope_complex_sink += (unsigned long long)(c_)->age + \
                                   (unsigned long long)(c_)->data.i + \
                                   (unsigned long long)(c_)->arr[(i_) % 8] + \
                                   (unsigned long long)(c_)->active + \
                                   (unsigned long long)(c_)->flags; \
    } while (0)

void update_complex(struct Complex* c, int i);

#endif // COMPLEX_TYPES_PROGRAM_H
