volatile int instance_marker = 0;

__attribute__((noinline)) int instance_tick(int expected)
{
    asm volatile("" ::: "memory");
    return instance_marker == expected;
}
