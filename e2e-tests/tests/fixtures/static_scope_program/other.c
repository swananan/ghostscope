static struct { int other; int common; } cfg = {99, 2};
int binding_state = 11;

__attribute__((noinline)) int binding_scope_two(void) {
    return cfg.other + cfg.common;
}
