#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdint>

int g_counter = 0;
const char* g_msg = "hello cpp";
static int s_internal = 123;

namespace ns1 {
struct Point { int x; int y; };

struct Outer {
    struct Nested {
        int shadow;
        int payload;
    };

    int tag;
    Nested nested;
    int tail;
};

class Foo {
public:
    static int s_val;
    __attribute__((noinline)) int bar(int v) { return v + 1; }
    __attribute__((noinline)) int bar(double d) { return (int)d + 2; }
};

int Foo::s_val = 7;

__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int add(double a, double b) { return (int)(a + b); }

__attribute__((noinline)) int nested_member_probe(int v) {
    volatile Outer outer = {
        101,
        {202 + v, 303},
        404,
    };
    Outer* o = (Outer*)&outer;
    volatile std::uintptr_t sink = (std::uintptr_t)o + (std::uintptr_t)o->nested.shadow;
    return (int)sink;
}

struct BlockPathBox { int m; };
volatile int block_path_sink;

__attribute__((noinline)) int sibling_block_member_probe(int x) {
    { int v0  = x; block_path_sink = v0;  }
    { int v1  = x; block_path_sink = v1;  }
    { int v2  = x; block_path_sink = v2;  }
    { int v3  = x; block_path_sink = v3;  }
    { int v4  = x; block_path_sink = v4;  }
    { int v5  = x; block_path_sink = v5;  }
    { int v6  = x; block_path_sink = v6;  }
    { int v7  = x; block_path_sink = v7;  }
    { int v8  = x; block_path_sink = v8;  }
    { int v9  = x; block_path_sink = v9;  }
    { int v10 = x; block_path_sink = v10; }
    { int v11 = x; block_path_sink = v11; }
    { int v12 = x; block_path_sink = v12; }
    { int v13 = x; block_path_sink = v13; }
    { int v14 = x; block_path_sink = v14; }
    { int v15 = x; block_path_sink = v15; }
    { int v16 = x; block_path_sink = v16; }
    { int v17 = x; block_path_sink = v17; }
    {
        BlockPathBox b{x};
        block_path_sink = b.m;
    }
    return block_path_sink;
}

// Variables purposely ending with ::h and ::h264 to validate demangled leaf handling
int h = 5;
int h264 = 7;
}

static void touch_globals() {
    g_counter += 1;
    s_internal += 2;
    if (g_msg[0] == '\0') std::cout << "";
}

int main() {
    ns1::Foo f;
    int acc = 0;
    for (int i = 0; i < 50000; ++i) {
        acc += f.bar(i);
        acc += ns1::add(i, i+1);
        acc += ns1::add(1.5, 2.5);
        acc += ns1::nested_member_probe(i);
        acc += ns1::sibling_block_member_probe(i);
        touch_globals();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    std::cout << "acc=" << acc << std::endl;
    return 0;
}
