#include <stdint.h>
#include <unistd.h>

typedef unsigned char u_char;

typedef struct {
    size_t len;
    u_char *data;
} ngx_str_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t value;
} ngx_table_elt_t;

typedef struct {
    u_char *pos;
    u_char *last;
    u_char *start;
    u_char *end;
} ngx_buf_t;

typedef struct {
    ngx_str_t request_line;
    ngx_buf_t header_in;
} ngx_http_request_t;

__attribute__((noinline)) static void trace_member_pointer(int iter) {
    u_char request_line_buf[] = "POST /demo HTTP/1.1";
    u_char header_key_buf[] = "X-Demo";
    u_char header_value_buf[] = "hello";
    u_char body_buf[] = {0x00, 0x01, 0x02, 'h', 'e', 'l', 'l', 'o'};

    volatile ngx_http_request_t req = {
        .request_line =
            {
                .len = sizeof("POST /demo HTTP/1.1") - 1,
                .data = request_line_buf,
            },
        .header_in =
            {
                .pos = body_buf,
                .last = body_buf + sizeof(body_buf),
                .start = body_buf,
                .end = body_buf + sizeof(body_buf),
            },
    };
    volatile ngx_table_elt_t hdr = {
        .key =
            {
                .len = sizeof("X-Demo") - 1,
                .data = header_key_buf,
            },
        .value =
            {
                .len = sizeof("hello") - 1,
                .data = header_value_buf,
            },
    };

    ngx_http_request_t *r = (ngx_http_request_t *)&req;
    ngx_table_elt_t *h = (ngx_table_elt_t *)&hdr;

    body_buf[0] = (iter & 1) ? 0x00 : 0x01;
    header_key_buf[0] = 'X';

    /* Keep r, h, h.key.data, and r.header_in.pos live at this PC. */
    volatile uintptr_t sink =
        (uintptr_t)r->request_line.data + (uintptr_t)h->key.data +
        (uintptr_t)r->header_in.pos + (uintptr_t)h->value.data;
    (void)sink;
}

typedef struct {
    int a;
    int b;
} value_backed_pair_t;

__attribute__((noinline)) static int trace_value_backed_aggregate(int seed) {
    value_backed_pair_t s = {
        .a = seed + 1,
        .b = seed + 2,
    };
    int total = s.a + s.b;
    asm volatile("" : "+r"(total) : : "memory");
    return total;
}

__attribute__((noinline)) static int trace_shadowed_state(int seed) {
    int state = seed + 100;
    int total = state;
    {
        int state __attribute__((unused));
        asm volatile("" : : : "memory");
        total += seed;
    }
    asm volatile("" : "+r"(total) : : "memory");
    return total;
}

int main(void) {
    int iter = 0;
    while (iter < 20000) {
        trace_member_pointer(iter);
        volatile int semantic_sink =
            trace_value_backed_aggregate(iter) + trace_shadowed_state(iter);
        (void)semantic_sink;
        iter++;
        sleep(1);
    }
    return 0;
}
