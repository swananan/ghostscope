#include <unistd.h>

/*
 * This fixture covers mixed CU-scope and function-scope variables in one CU.
 *
 * Useful check:
 *   dwarfdump late_globals_program | rg 'DW_TAG_(subprogram|formal_parameter|variable)' -A4 -B2
 *
 * What this fixture is trying to model:
 *
 * 1. The compilation unit contains real globals that should be indexed as globals.
 * 2. The same compilation unit also contains a normal function subtree with:
 *    - a formal parameter
 *    - a local variable
 * 3. While walking that CU, the parser needs to keep those scopes separate:
 *    - late_global / late_static belong in the global index
 *    - x / tmp do not
 *
 * The compact subtree we rely on is:
 *
 *   DW_TAG_subprogram       local_fn
 *     DW_TAG_formal_parameter x
 *     DW_TAG_variable         tmp
 *
 * In other words, this fixture is meant to answer:
 * "When one CU contains both true globals and ordinary function locals, does
 * the global-variable index include only the CU-scope variables?"
 */
int local_fn(int x) {
    int tmp = x + 1;
    return tmp;
}

/* Keep a couple of real CU-scope globals in the same unit as the local_fn subtree. */
int late_global = 123;
static int late_static = 7;

int main(void) {
    while (1) {
        late_global += local_fn(late_static);
        usleep(10000);
    }
    return 0;
}
