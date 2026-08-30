namespace ns1 {
struct Inner {
    long value;
};
}  // namespace ns1

namespace ns2 {
template <typename T>
struct Box {
    T value;
};

Box<ns1::Inner> qualified_global = {{17}};

__attribute__((noinline)) int f(int value) {
    return value + 1;
}

__attribute__((noinline)) int f(double value) {
    return static_cast<int>(value) + 2;
}

__attribute__((noinline)) int local_entities() {
    static int counter = 41;
    struct LocalType {
        long value;
    };
    volatile LocalType local = {counter};
    return static_cast<int>(local.value) + counter;
}
}  // namespace ns2

int main() {
    return ns2::f(1) + ns2::f(2.0) + ns2::local_entities()
        + static_cast<int>(ns2::qualified_global.value.value);
}
