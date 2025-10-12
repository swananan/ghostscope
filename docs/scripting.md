# GhostScope Script Language Reference

GhostScope uses a domain‑specific language to define trace points and actions. You can write scripts inline in the TUI with the `trace` command or load them from a script file.

## Table of Contents
1. [Basic Syntax](#basic-syntax)
2. [Trace Statements](#trace-statements)
3. [Variables](#variables)
4. [Print Statement](#print-statement)
5. [Conditional Statements](#conditional-statements)
6. [Expressions](#expressions)
7. [Built-in Functions](#built-in-functions)
8. [Special Variables](#special-variables)
9. [Examples](#examples)
10. [Limitations](#limitations)
11. [Runtime Expression Failures (ExprError)](#runtime-expression-failures-exprerror)

## Basic Syntax

### Comments

```ghostscope
// Single line comment

/*
   Multi-line
   comment
*/
```

### Statement Types

GhostScope supports the following statements:
- `trace` — define trace points and their actions
- `print` — output formatted text
- `backtrace` / `bt` — print call stack (in progress)
- `if` / `else` — conditional execution
- `let` — script variable declaration
- Expression statements

## Trace Statements

The `trace` statement is the top‑level construct used only at the script file level (not nested inside other trace blocks).

### Syntax

```ghostscope
trace <pattern> {
    // statements executed when the trace point fires
}
```

### Trace Patterns

#### Function Name
```ghostscope
trace main {
    print "Main called";
}

trace calculate_something {
    print "Calculating...";
}
```

#### Source Line
```ghostscope
// Trace a specific file and line
trace sample.c:42 {
    print "Hit line 42";
}

// Supports various path formats
trace /home/user/project/src/utils.c:100 {
    print "Utility function";
}
```

#### Address
```ghostscope
// Module‑relative address (DWARF PC)
trace 0x401234 {
    print "Hit address";
}

// Module suffix + address (full path or unique suffix)
trace libc.so.6:0x1234 {
    print "Hit libc address";
}
```

Notes:
- For `0xADDR`, the default module depends on startup mode: `-t <binary>` uses `<binary>`; `-p <pid>` uses the main executable.
- `module_suffix:0xADDR` allows selecting a module by full path or unique suffix; ambiguous suffixes will list candidates.

## Variables

### Script Variables

**Script variables are immutable.** Within a single trace block, a name can be bound only once; redeclaration is a compile error, and there is no assignment statement (`x = ...` is not supported).

Declare with `let`:

```ghostscope
let count = 0;
let threshold = 100;
let message = "hello";
let result = a + b;
```

#### Types and capabilities

| Type | Literal/Example | Description | Ops/Comparisons |
| --- | --- | --- | --- |
| Integer (i64) | `123`, `-42` | 64‑bit signed integer | +, -, *, /; mixes with DWARF integer‑like scalars |
| Boolean (bool) | `true`, `false`, or from comparison `a < b` | From literals/comparisons/logical ops | logical AND/OR; when mixing with DWARF integers, treated as 0/1 |
| String | `"hello"` | UTF‑8 string literal | Equality `==`, `!=` with DWARF C strings; no ordering |
| Alias (DWARF expr alias) | `let a = global.arr;`, `let p = &buf[0];` | A named alias to any DWARF expression (variable, member, array, pointer deref, or address‑of). Lets you give short names to complex types/paths and reuse them. | Supports the same complex access as the underlying DWARF type: member access (`a.field`), constant index (`a[0]`), address‑of (`&a`), and use in `memcmp/strncmp/starts_with` and `{:x.N}`/`{:s.N}`/`{:p}`. Pointer arithmetic remains limited to adding a non‑negative constant. |

Notes:
1. Script variables do not expose structs/arrays/pointers. Access those through DWARF variables (member access, deref, constant index) to obtain scalars first. The exception is an alias variable, which can bind to any DWARF expression and be used as a reusable base for member/index access, address‑of, and memory formatting.

Examples:

```ghostscope
// Alias a complex DWARF path and reuse it
let a = global_var.arr;   // arr is DWARF array/aggregate
print "ptr={:p}", &a;     // take address of alias
print a[1];               // index on alias

// Address-of aliases still work
let p = &conn.buf[0];
print "h={:x.16}", p;
```
2. Floats are not supported in scripts or runtime.
3. Unary minus `-` is supported and can nest (e.g., `-1`, `-(-1)`), parsed as `0 - expr`.
4. Transport encodes booleans as 0/1; renderers display `true/false`.

#### Scoping & Shadowing

- Block scope: every `{ ... }` creates a new lexical scope; `if`’s then/else are independent sub‑scopes. A variable is visible only within its declaring scope and nested sub‑scopes; it is not visible after the scope ends.
- No shadowing between script variables: inner scopes cannot re‑bind a name that exists in an outer scope (even though they are different scopes).
- Friendly errors:
  - Assignment: `Assignment is not supported: variables are immutable. Use 'let a = ...' to bind once.`
  - Same‑scope redeclaration: `Redeclaration in the same scope is not allowed: 'x'`
  - Shadowing: `Shadowing is not allowed for immutable variables: 'x'`
  - Out‑of‑scope use: `Use of variable 'y' outside of its scope`

### DWARF Variables

DWARF variables include locals, parameters, and globals from the traced program.

#### DWARF Types

| DWARF Type | Example (source language) | Mapping/Display | Access/Operations |
| --- | --- | --- | --- |
| Signed/Unsigned Integers (1/2/4/8 bytes) | `int`, `long`, `unsigned int`, `size_t` | I8/I16/I32/I64 or U8/U16/U32/U64 | Printable; mixes with script integers/bools for arithmetic and comparisons (after width/sign normalization) |
| Boolean | `bool` | Bool (`true`/`false`) | Printable; comparable with script booleans/integers |
| Float | `float`, `double` | Printable | eBPF has no FP; scripts don’t support float literals/ops |
| Char | `char`, `unsigned char` | 1‑byte int/char | Printed as 1‑byte integer; arrays/pointers see below |
| C string | `char*`, `const char*`, `char[]` | CString (rendered as string) | Printable; equality `==`, `!=` with script strings |
| Pointer | `T*`, `void*`, function pointer | Pointer/NullPointer (address) | Supports `*` deref and `==`/`!=`; auto‑deref for locals/params/globals when safe |
| Array | `T[N]` | Array | Constant index reads (top‑level or chain‑tail); dynamic/mid indexes and multi‑dim not supported |
| Struct/Class | `struct Foo`, `class Bar` | Struct | Use `.` member access; operate on scalar members only |
| Union | `union U` | Union | Show one member view; access members then treat as scalar |
| Enum | `enum E` | Enum (via base int) | Printed as `Type::Variant`; arithmetic/compare uses base integer |
| Bitfield | `int flags:3` | Bitfield → integer view | Extracted integer; mixes with script ints/bools |
| Typedef/Qualified | `typedef`, `const`, `volatile` | Typedef/QualifiedType | Treated as underlying type |
| Optimized‑out | variable optimized away | OptimizedOut | Read fails; renders `<OPTIMIZED_OUT>`; operations follow failure semantics |
| Unknown | unsupported/unknown | Unknown | Renders `<UNKNOWN_TYPE_N_BYTES>` |

#### Supported Complex Access

```ghostscope
// Simple variable
print x;

// Member access (struct fields)
print person.name;
print config.settings.timeout;

// Array access
print arr[0];
print arr[i];

// Pointer dereference
print *ptr;
print *(ptr);

// Address‑of
print &variable;

// Chained access
print obj.field.subfield;
print arr[0].name;
```

Tips:
- Auto‑dereference is supported for locals/params/globals. You don’t need to write `*ptr` or `->`; when safe, pointers are read and dereferenced automatically.
- Array access: supported for top‑level `arr[const]` and chain‑tail `a.b.c[const]`. Not supported: chain‑middle indices (`a.b[2].c`), dynamic indices (`arr[i]`), and multi‑dim arrays.

## Special Variables

Start with `$` and expose runtime info:

- `$pid` — current process ID (tgid), low 32 bits of `bpf_get_current_pid_tgid`.
- `$tid` — current thread ID (tid), high 32 bits of `bpf_get_current_pid_tgid`.
- `$timestamp` — monotonic timestamp (ns), from `bpf_ktime_get_ns`.

All behave as integers for comparisons/arithmetic.

Example:

```ghostscope
trace sample.c:42 {
    if $pid == 12345 { print "match"; }
    print "PID:{} TID:{} TS:{}", $pid, $tid, $timestamp;
}
```

Note: Currently only `$pid`, `$tid`, `$timestamp` are supported. Register‑related specials may be added later if needed.

### Variable Lookup Order

1. Script variables declared with `let`
2. Locals/params resolved from DWARF
3. Program globals

Note: script variables can shadow program variables; choose names carefully.

## Print Statement

### Basic Forms

```ghostscope
// String literal
print "Hello, World";

// Variable
print count;

// Complex expressions
print person.name;
print arr[0];
print *ptr;
```

### Formatted Printing

Rust‑like placeholders:

```ghostscope
print "Value: {}", value;
print "X: {}, Y: {}", x, y;
print "Name: {}, Age: {}", person.name, person.age;
```

Extended specifiers and dynamic length:

```ghostscope
// Hex / pointer / ASCII bytes
print "A={:x} B={:08X}", a, b;
print "p={:p}", ptr;
print "s={:s}", cstr;            // for char*/char[N], `{}` prints quoted C string

// Memory dump from pointer/array
print "h={:x.16}", buf;          // read 16B as hex
print "ascii={:s.32}", name;      // read 32B as ASCII (char* stops at first NUL)

// Dynamic length (star): length argument comes before value
print "buf={:x.*}", len, buf;

// Dynamic length via capture
let n = tail_len;
print "tail={:s.n$}", p;
```

Notes:
- `{}` default; `{:x}`/`{:X}` for integers; `{:p}` pointer; `{:s}` ASCII bytes.
- Length suffixes:
  - `.{N}`: static length (decimal/`0x..`/`0o..`/`0b..`).
  - `.*`: dynamic (consumes two args: len then value).
  - `.name$`: capture script variable `name` as length; does not consume an extra value arg.
- Kernel performs bounded reads; user space renders hex/ASCII. For `{:s}` ASCII, rendering stops at first NUL; non‑printables show as `\xNN`.
- Per‑argument read cap is controlled by `ebpf.mem_dump_cap` (default 4096 bytes). Requests beyond cap are truncated; if event payload is exceeded, output may also truncate with `…`.
- On read failure (e.g., null deref, offsets unavailable, permission), extended specifiers print `<MISSING_ARG>`.

**Note**: Format strings use Rust‑style placeholders, not `%d`/`%s`.

## Conditional Statements

```ghostscope
// Simple if
if x > 100 {
    print "Large";
}

// If-else
if result == 0 {
    print "Success";
} else {
    print "Failed";
}

// Nested if-else
if x > 100 {
    print "Large";
} else if x > 50 {
    print "Medium";
} else {
    print "Small";
}
```

Note: When a conditional depends on DWARF‑backed reads and a read fails at runtime, GhostScope does not silently treat the condition as false. It emits a structured ExprError and applies soft‑abort semantics for that condition. See “Runtime Expression Failures (ExprError)”.

## Expressions

### Arithmetic

```ghostscope
let sum = a + b;
let diff = a - b;
let product = a * b;
let quotient = a / b;

// Integer literals
let x = 123;           // decimal
let h = 0x1f;          // hex (31)
let o = 0o755;         // octal (493)
let b = 0b1010;        // binary (10)
let neg = -0x10;       // unary minus is parsed as 0 - 16
```

### Precedence

1. Parentheses `()`
2. Member access `.`, Array access `[]`
3. Pointer deref `*`, Address‑of `&`, Unary minus `-`, Logical NOT `!`
4. Multiplication `*`, Division `/`
5. Addition `+`, Subtraction `-`
6. Comparisons `==`, `!=`, `<`, `<=`, `>`, `>=`
7. Logical AND `&&`
8. Logical OR `||`

### Grouping

```ghostscope
let result = (a + b) * c;
let complex = (x + y) / (a - b);
```

### Logical Operators

- `!` (logical NOT), `&&` (logical AND), `||` (logical OR)
- Non‑zero is true
- `||`/`&&` short‑circuit

Examples:

```ghostscope
trace main:entry {
    if a > 10 && b == 0 {
        print "AND";
    } else if a < 100 || p == 0 {
        print "OR";
    }

    print "NOT1:{}", !starts_with(activity, "main");
    print "NOT2:{}", !strncmp(record, "HTTP", 4);
}
```

### Unary Minus

Semantics: negate an expression; recursive nesting is supported. Parsing is treated as `0 - expr`.

```ghostscope
trace foo.c:42 {
    let a = -1;
    let b = -(-1);
    print a;
    print "X:{}", b;
}
```

### Cross‑type Operations with DWARF Values

- Arithmetic (+, -, *, /)
  - Supported: script int/bool with DWARF integer‑like scalars
    - BaseType (signed/unsigned 1/2/4/8 bytes), Enum (as underlying), Bitfield (extracted integer), char/unsigned char (1 byte)
  - Not supported: aggregates (struct/union/array), pointers, floats
- Comparisons (==, !=, <, <=, >, >=)
  - Supported: script int/bool with DWARF integer‑like types
  - Pointers: only equality/inequality (pointer==pointer, pointer==0)
  - CString equality: DWARF char* or char[] vs script string literal via bounded read
  - Not supported: relational string comparisons; aggregates; floats
- Floats: not supported (eBPF runtime)

Error semantics: If a DWARF read fails (null deref/read error/offsets unavailable), comparisons return false and arithmetic returns 0; event status carries the error code.

### CString Equality (char*/char[])

GhostScope supports equality/inequality between a script string literal and a DWARF‑side C string:

- Supported forms: `const char*` / `char*` and fixed‑size `char[N]`.
- Operators: `==` and `!=`.
- Semantics (strict NUL): let the literal length be `L`.
  - For `char*`: perform a bounded `bpf_probe_read_user_str` of up to `L+1` bytes. Equality requires the helper to return exactly `L+1`, the byte at index `L` to be `\0`, and the first `L` bytes to match the literal.
  - For `char[N]`: perform a bounded `bpf_probe_read_user` of `min(N, L+1)` bytes. Equality requires `L+1 <= N`, the byte at index `L` to be `\0`, and the first `L` bytes to match the literal.
  - Any read failure (invalid address, permission, etc.) evaluates to `false`.

## Built-in Functions

### `strncmp(a, b, n)`
  - Check equality within the first `n` bytes (no NUL required).
  - At least one side (`a` or `b`) must be a string: string literal or a script string variable (e.g., `let s = "AB";`).
  - The other side can be: DWARF pointer/array, DWARF alias, or another string.
  - If both sides are strings, the result folds at compile time. If exactly one side is a string, runtime reads the other side and compares (read failures produce ExprError).
  - `n` must be a non‑negative integer literal; effective length is `min(n, compare_cap, string length, readable bytes)` (compare_cap defaults to 64).

### `starts_with(a, b)`
  - Check if `a` starts with `b`, equivalent to `strncmp(a, b, len(b))`.
  - At least one side must be a string (literal or script string variable); the other side can be an address expression (DWARF pointer/array or alias) or a string.
  - If both sides are strings, the result folds at compile time; if exactly one side is a string, runtime reads `len(b)` bytes from the other side and compares (read failures produce ExprError).

### `memcmp(expr_a, expr_b, len)`
  - Boolean semantics: returns `true` if the first `len` bytes at `expr_a` and `expr_b` are identical.
  - Pointer sources: `expr_a`/`expr_b` may be DWARF pointer or array (any element type), or address‑of forms (e.g., `&expr`, `&arr[0]`). For literal string comparisons, use `strncmp`/`starts_with`.
  - Bare integer addresses as pointer arguments are not supported. To match raw bytes, use `hex("...")`.
    - If either operand is `hex("...")`, `len` may be omitted; the parser infers `len` from the hex size. If both sides are `hex(...)`, sizes must match.
    - With a literal `len` and `hex(...)`, negative lengths and lengths greater than the hex size are rejected at parse time.
  - `len` accepts script integer expressions (decimal, `0x..`, `0o..`, `0b..`). At runtime, negative values are clamped to 0; literal negatives are rejected by the parser.
  - No NUL semantics; raw byte comparison (length in bytes).
  - If `len == 0`, result is `true` (no user‑memory reads).
  - Any DWARF read failure on either side evaluates to `false` (see ExprError).

Verifier friendliness and performance:
- Compiles to branch‑light byte comparisons (e.g., XOR/OR accumulation) to avoid verifier state explosion.
- Avoid packing many large string checks into a single hot probe; consider splitting trace points or attaching at less‑hot sites.

Examples: `strncmp`

```ghostscope
// Function parameter (const char* activity)
trace log_activity {
    print "eq5:{}", strncmp(activity, "main_", 5);
}

// Global/rodata C strings or fixed arrays
trace globals_program.c:32 {
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);    // lm: const char*
}

// Generic pointer (read failure → false)
trace process_record {
    print "rec_http:{}", strncmp(record, "HTTP", 4); // record: struct* -> false
}
```

Examples: `starts_with`

```ghostscope
// Prefix match (equivalent to strncmp(expr, lit, len(lit)))
trace log_activity {
    print "is_main:{}", starts_with(activity, "main");
}

trace globals_program.c:32 {
    print "gm_hello:{}", starts_with(gm, "Hello"); // gm: const char*
}
```

Examples: `memcmp`

```ghostscope
// Raw memory equality between two pointers
trace globals_program.c:32 {
    // Equal bytes
    if memcmp(&lib_pattern[0], &lib_pattern[0], 16) { print "EQ"; } else { print "NE"; }
    // Different due to offset
    if memcmp(&lib_pattern[0], &lib_pattern[1], 16) { print "EQ2"; } else { print "NE2"; }
    // len=0 → true (no user-memory reads)
    if memcmp(&lib_pattern[0], &lib_pattern[1], 0) { print "Z0"; }
    // Dynamic length from script variable
    let n = 10;
    if memcmp(&lib_pattern[0], &lib_pattern[0], n) { print "DYN_EQ"; }
}

// Match against byte patterns (hex)
trace foo {
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }          // first 2 bytes are "PO"
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }  // 4-byte magic
}
```

### Hex Literal Helper (`hex`)

- Syntax: `hex("<HEX BYTES>")`
  - Only hex digits (`0-9a-fA-F`) and spaces; after removing spaces, there must be an even number of digits. Tabs and other separators are not allowed.
  - Parse‑time validation: rejects any non‑hex character and odd digit count; with `memcmp(expr, hex(...), len_literal)`, literal `len` must be non‑negative and must not exceed the hex size.
- Semantics: parses two hex digits per byte left‑to‑right; no endianness involved; no `0x` inside the string.
- Scope: as an argument to `memcmp` to compare memory against raw bytes (headers, magic constants, etc.).
- Examples:

```ghostscope
trace foo {
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }
}
```

## Stack Backtrace (not implemented)

Backtrace printing via `backtrace;` or `bt;` is planned but not implemented yet. The syntax is reserved, and a dedicated section will be added once available.

## Examples

This section highlights common and high‑value patterns (inspired by e2e tests).

### Basic Function Trace & Process Info

```ghostscope
trace main {
    print "Program start";
    print "PID:{} TID:{} TS:{}", $pid, $tid, $timestamp;
}
```

### Conditional Trace & Backtrace

```ghostscope
trace malloc {
    if size > 1_048_576 {  // 1 MB
        print "Large allocation: {} bytes", size;
        backtrace;          // (in progress)
    }
}
```

### DWARF Auto‑Deref & Member Access

```ghostscope
trace process_user {
    print "user:{}", user.name;
    print "status:{}", user.status;

    // auto‑deref pointer to struct when safe
    print "friend:{}", user.friend_ref.name;
}
```

### Array Access & Address‑Of

```ghostscope
trace foo.c:42 {
    print "arr0:{}", arr[0];
    print "name0:{}", person.names[0];

    // address‑of used in builtins or dumps
    print "p(&buf[0])={:p}", &buf[0];
}
```

### CString Comparisons (char*/char[])

```ghostscope
trace log_activity {
    print "prefix:{}", starts_with(activity, "main");
    print "eq:{}", strncmp(activity, "main_", 5);
}

trace globals_program.c:32 {
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);
}
```

### Raw Memory Compare (memcmp) & hex Byte Strings

```ghostscope
trace globals_program.c:32 {
    if memcmp(&lib_pattern[0], &lib_pattern[0], 16) { print "EQ"; } else { print "NE"; }
    if memcmp(&lib_pattern[0], &lib_pattern[1], 16) { print "EQ2"; } else { print "NE2"; }
    if memcmp(&lib_pattern[0], &lib_pattern[1], 0) { print "Z0"; }
    let n = 10;
    if memcmp(&lib_pattern[0], &lib_pattern[0], n) { print "DYN_EQ"; }
}

trace foo {
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }
}
```

### else‑if Chains & ExprError Soft‑Abort

```ghostscope
// G_STATE.lib can be NULL at times; read failure triggers ExprError
trace globals_program.c:32 {
    if memcmp(G_STATE.lib, hex("00"), 1) { print "A"; }
    else if memcmp(gm, hex("48"), 1) { print "B"; }
    else { print "C"; }
}
// Expect: an ExprError line and "B" printed; A/C suppressed by soft‑abort
```

### Struct Pretty Print & Pointer Deref

```ghostscope
// Example adapted from complex_types_program
trace complex_types_program.c:25 {
    print s.name;   // char[16] -> string
    print s;        // pretty‑print struct
    print *ls;      // deref pointer then pretty‑print
}
```

### Dynamic Length Formatting & Dumps

```ghostscope
trace foo {
    let n = 32;
    print "h={:x.*}", n, buf;
    print "ascii={:s.n$}", name;
}
```

## Limitations

1. No loops (`for`, `while`)
2. No user‑defined functions
3. Read‑only (no mutation of target program state)
4. Limited string operations (CString equality and built‑ins only)
5. Limited arithmetic (no bitwise operators yet)
6. No dynamic memory allocation in eBPF

## Best Practices

1. Keep it simple to minimize overhead
2. Filter early with conditions
3. Include context in print outputs
4. Avoid complicated logic in probes
5. Build up incrementally

## Notes

- `let` declares script‑local variables, not program variables
- All variables are dynamically typed in script space
- String literals must use double quotes
- Most statements require semicolons
- Trace pattern matching supports fuzzy file suffix (see Command Reference)

## Runtime Expression Failures (ExprError)

When an `if/else if` condition or a builtin (`memcmp`, `strncmp`, `starts_with`) depends on DWARF‑backed runtime reads and a read fails, GhostScope does not silently treat the condition as `false`. Instead, it sends a structured warning (ExprError) to user space and applies soft‑abort semantics:

- Soft‑abort:
  - For a failing `if`: skip the current then/else. An `else if` chain continues; if a later condition succeeds, its branch runs. The final `else` behaves normally unless a previous condition in the chain already succeeded.
  - For `print`: do not abort the line; per‑variable statuses render inline. If a builtin fails inside `print`, an additional ExprError is emitted.

### ExprError Fields

- `expr`: human‑readable expression text (UTF‑8 safe truncation)
- `code`: aligned with `VariableStatus` semantics:
  - 1 = NullDeref
  - 2 = ReadError (includes probe_read_user failures)
  - 3 = AccessError
  - 4 = Truncated
  - 5 = OffsetsUnavailable (missing ASLR offsets)
  - 6 = ZeroLength (requested length is 0)
- `flags`: bitmask (builtin‑specific meanings)
  - `memcmp`:
    - `0x01` → first‑arg read‑fail
    - `0x02` → second‑arg read‑fail
    - `0x04` → len‑clamped (compare length truncated to cap)
    - `0x08` → len=0
  - `strncmp/starts_with`:
    - `0x01` → read‑fail
    - `0x04`, `0x08` reserved (length clamped/zero)
- `failing_addr`: the pointer address involved (or 0 if unknown). When zero, renderers show `at NULL`.

Console example:

```
ExprError: memcmp(buf, hex("504f"), 2) (read error at 0x0000000100000000, flags: first-arg read-fail,len-clamped)
```

When the failing address is zero:

```
ExprError: memcmp(G_STATE.lib, hex("00"), 1) (read error at NULL, flags: first-arg read-fail)
```
### Comparison Operators

The comparison operators are `==`, `!=`, `<`, `<=`, `>`, `>=`.

- Operands may be script integers/bools and DWARF integer‑like scalars; the engine normalizes width/sign before comparing.
- For C strings (char*/char[]), use equality `==`/`!=` with string literals or script string variables under “CString Equality”, or prefer the built‑ins `strncmp`/`starts_with` for bounded and prefix checks.
- Pointer equality supports `==`/`!=` on pointers (including auto‑dereferenced locals/params/globals when applicable).
