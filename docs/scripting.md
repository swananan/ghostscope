# GhostScope Script Language Reference

GhostScope uses a domain-specific language for defining trace points and actions. Scripts are written when using the `trace` command in TUI or loaded from script files.

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

GhostScope supports the following statement types:
- `trace` - Define trace points with actions
- `print` - Output formatted text
- `backtrace` / `bt` - Print stack backtrace (in progress)
- `if`/`else` - Conditional execution
- `let` - Variable declaration
- Expression statements

## Trace Statements

The `trace` statement is the top-level construct for defining trace points. It's only used in script files, not inside trace blocks.

### Syntax

```ghostscope
trace <pattern> {
    // statements to execute when trace point is hit
}
```

### Trace Patterns

#### Function Names
```ghostscope
trace main {
    print "Main function called";
}

trace calculate_something {
    print "Calculating...";
}
```

#### Source Lines
```ghostscope
// Trace specific file and line
trace sample.c:42 {
    print "Hit line 42";
}

// Supports various path formats
trace /home/user/project/src/utils.c:100 {
    print "Utility function";
}
```

#### Addresses
```ghostscope
// Trace by module-relative address (DWARF PC)
trace 0x401234 {
    print "Hit address";
}

// Trace an address in a specific module (supports full path or unique suffix)
trace libc.so.6:0x1234 {
    print "Hit libc address";
}
```

Notes
- `0xADDR` uses the default module depending on startup mode: `-t <binary>` uses `<binary>`; `-p <pid>` uses the main executable.
- `module_suffix:0xADDR` picks the specified module by full path or unique suffix; ambiguous suffixes will be reported with candidates.


## Variables

### Script Variable Declaration

Declare script variables using the `let` keyword:

```ghostscope
let count = 0;
let threshold = 100;
let message = "hello";
let result = a + b;
```

Script variable types and capabilities:

| Type | Literal/Example | Description | Ops/Comparisons |
| --- | --- | --- | --- |
| Integer (int, internally i64) | `123`, `-42` | Signed 64-bit integer | +, -, *, /; can mix with DWARF integer-like scalars |
| Boolean (bool) | `true`, `false`, or from comparisons like `a < b` | Produced by literals/comparisons/logical expressions | logical AND/OR (script only); when mixing with DWARF integers, treated as 0/1 |
| String | `"hello"` | UTF-8 string literal | Equality `==`, `!=` with DWARF C strings; no ordering comparisons |

Notes:
1. Script variables do not support user-defined structs/arrays/pointers; access such data via DWARF variables (member access, deref, constant index) to obtain scalars first.
2. Floating-point arithmetic is not supported.
3. Unary minus `-` is supported and can be nested (e.g., `-1`, `-(-1)`), parsed as `0 - expr`.
4. Transport encodes booleans as a single byte 0/1; the renderer displays `true`/`false`.

### Local Variables, Parameters, and Global Variables

GhostScope supports complex variable access:

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

// Address of
print &variable;

// Complex chains
print obj.field.subfield;
print arr[0].name;
```

Note:
- Auto-dereference is supported for locals, parameters, and globals. You don't need to write `*ptr` explicitly; when it is safe to do so, the pointer will be read and dereferenced at runtime (with null checks).
- Array access: supported for top-level `arr[const]` and chain-tail `a.b.c[const]`. Not supported: chain-middle indices (e.g., `a.b[2].c`), dynamic indices (`arr[i]`), and multi-dimensional arrays.

## Print Statement

The `print` statement outputs information during tracing.

### Basic Forms

```ghostscope
// Print string literal
print "Hello, World";

// Print variable
print count;

// Print complex expression
print person.name;
print arr[0];
print *ptr;
```

### Formatted Printing

Use Rust-like placeholders in format strings:

```ghostscope
// Format string with arguments
print "Value: {}", value;
print "X: {}, Y: {}", x, y;
print "Name: {}, Age: {}", person.name, person.age;
```

Extended specifiers and dynamic length

```ghostscope
// Hex / pointer / ASCII string
print "A={:x} B={:08X}", a, b;   // hex lower/upper (width/pad planned in phase 2)
print "p={:p}", ptr;             // pointer address 0x...
print "s={:s}", cstr;            // ASCII dump for bytes; for char*/char[N], `{}` still prints quoted CString

// Memory dump from pointer/array
print "h={:x.16}", buf;          // hex dump 16 bytes from buf
print "ascii={:s.32}", name;      // ASCII dump up to 32 bytes (char* stops at first NUL)

// Dynamic length (Rust-style star): length argument comes before value
print "buf={:x.*}", len, buf;    // consumes two args: len then buf

// Dynamic length via capture variable (no extra arg)
let n = tail_len;                 // script variable
print "tail={:s.n$}", p;          // length captured from n
```

Notes
- `{}` is default; `{:x}`/`{:X}` for integers; `{:p}` for pointers; `{:s}` for ASCII bytes.
- Length suffixes:
  - `.{N}`: static length (reads N bytes). `N` supports decimal, hex (`0x..`), octal (`0o..`), and binary (`0b..`).
  - `.*`: dynamic length; consumes two arguments (length first, then value)
  - `.name$`: capture a script variable named `name` as length; does not consume an extra value argument
- Kernel performs bounded reads; user space renders hex/ASCII. For `{:s}` ASCII, rendering stops at the first NUL byte; non-printables are escaped as `\xNN`.
- Memory-dump reads are capped per argument by configuration (`ebpf.mem_dump_cap`, default 4096 bytes). If the requested length exceeds the cap, data is truncated. If the event payload cap is exceeded, the output may be truncated and shown with `…`.
- On read failure (e.g., invalid pointer, missing offsets, null deref), extended specifiers print `<MISSING_ARG>`.

**Note**: The format string uses Rust-style placeholders, not `%d`/`%s` (C-style).

## Conditional Statements

GhostScope uses Rust-style syntax for conditionals:

```ghostscope
// Simple if
if x > 100 {
    print "Large value";
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

### Comparison Operators

- `==` - Equal
- `!=` - Not equal
- `<` - Less than
- `<=` - Less than or equal
- `>` - Greater than
- `>=` - Greater than or equal

## Expressions

### Arithmetic Operations

```ghostscope
let sum = a + b;       // Addition
let diff = a - b;      // Subtraction
let product = a * b;   // Multiplication (not for pointers)
let quotient = a / b;  // Division

// Integer literals
let x = 123;           // decimal
let h = 0x1f;          // hex (31)
let o = 0o755;         // octal (493)
let b = 0b1010;        // binary (10)
let neg = -0x10;       // unary minus applies (parsed as 0 - 16)
```

### Expression Precedence

1. Parentheses `()`
2. Member access `.`, Array access `[]`
3. Pointer dereference `*`, Address of `&`, Unary minus `-`, Logical NOT `!`
4. Multiplication `/`, Division `/`
5. Addition `+`, Subtraction `-`
6. Comparisons `==`, `!=`, `<`, `<=`, `>`, `>=`
7. Logical AND `&&`
8. Logical OR `||`

### Expression Grouping

```ghostscope
// Use parentheses for explicit precedence
let result = (a + b) * c;
let complex = (x + y) / (a - b);
```

### Logical Operators

- `!` (logical NOT), `&&` (logical AND), `||` (logical OR)
- Operands are treated as booleans with "non-zero is true" semantics
- `!expr` yields `true` if `expr` evaluates to zero/false; otherwise `false`.
- `||` and `&&` use short-circuit evaluation
  - `||`: if LHS is true, RHS is not evaluated
  - `&&`: if LHS is false, RHS is not evaluated

Boolean values

- Comparisons and logical operators produce boolean results.
- Transport encodes booleans as a single byte 0/1. The renderer displays them as `true`/`false`.

Examples

```ghostscope
trace main:entry {
    if a > 10 && b == 0 {
        print "AND";
    } else if a < 100 || p == 0 {
        print "OR";
    }

    // Unary logical NOT on expressions that produce booleans
    print "NOT1:{}", !starts_with(activity, "main");
    print "NOT2:{}", !strncmp(record, "HTTP", 4);
}
```

### Unary Minus

- Semantics: negate an expression; recursive nesting is supported.
- Parsing: treated as `0 - expr`, ensuring `-1`, `-x`, and `-(-1)` evaluate as signed integers.

```ghostscope
trace foo.c:42 {
    let a = -1;          // a = -1
    let b = -(-1);       // b = 1
    print a;             // Output: a = -1
    print "X:{}", b;     // Output: X:1
}
```

### Cross-type Operations With DWARF Values

- Arithmetic (+, -, *, /)
  - Supported: script int/bool with DWARF integer-like scalars
    - BaseType (signed/unsigned 1/2/4/8 bytes), Enum (as underlying integer), Bitfield (extracted integer), char/unsigned char (1 byte)
  - Not supported: aggregates (struct/union/array), pointers, floats at runtime
- Comparisons (==, !=, <, <=, >, >=)
  - Supported: script int/bool with the DWARF integer-like types above (after width/sign unification)
  - Pointer: only equality/inequality (pointer==pointer, pointer==0)
  - CString equality: DWARF char* or char[] vs script string literal (==, !=) with bounded read/compare
  - Not supported: relational string compares; aggregates; floats with DWARF
- Floats
  - Not supported: eBPF does not support floating-point runtime operations. GhostScope scripts do not support float literals or float arithmetic.

Error semantics: If a read fails (null deref/read error/offsets unavailable), comparisons return false and arithmetic returns 0; the event status carries the error code.

Examples

```ghostscope
// Integer arithmetic and comparisons with DWARF locals/globals
trace foo.c:42 {
    // DWARF int (e.g., s.counter) mixed with script int
    if s.counter > 100 {
        print "hot";
    }
    print "sum:{}", s.counter + 5;

    // Enum/bitfield compare (treated as integer)
    print "active:{}", a.active == 1;
}

// Pointer equality (no ordering compares)
trace foo.c:50 {
    print "isNull:{}", p == 0;       // pointer vs NULL
    // print "same:{}", p == q;     // pointer vs pointer (if both in scope)
}

// CString equality: DWARF char*/char[] vs script string literal
trace foo.c:60 {
    print "greet-ok:{}", gm == "Hello, Global!"; // gm: const char* or char[]
}

#### CString Equality Details (char*/char[])

GhostScope supports comparing a script string literal with a DWARF-side C string:

- Supported forms: `const char*` / `char*` and fixed-size `char[N]`.
- Operators: `==` and `!=`.
- Semantics (strict NUL): let the literal length be `L`.
  - For `char*`: GhostScope performs a bounded `bpf_probe_read_user_str` of up to `L+1` bytes. Equality requires the helper to return exactly `L+1`, the last byte to be `\0`, and all preceding `L` bytes to match the literal.
  - For `char[N]`: GhostScope performs a bounded `bpf_probe_read_user` of `min(N, L+1)` bytes. Equality requires `L+1 <= N`, the byte at index `L` to be `\0`, and all preceding `L` bytes to match the literal.
  - Any read failure (invalid address, permission, etc.) evaluates to `false`.

Performance and safety notes:

- Comparisons are compiled into bounded, branch-light checks to be verifier-friendly on most kernels. Still, placing many string comparisons in a single probe or attaching at extremely hot sites may add CPU and verifier load.
- Prefer attaching at less-hot lines/functions if you only need occasional confirmation (e.g., update sites for a string field), or split multiple heavy comparisons into separate trace points.
- Builtins (`strncmp`/`starts_with`) cap read length by `ebpf.compare_cap` (default 64 bytes).
  CString equality reads only `L+1` bytes (no extra cap beyond the literal length).

// Floats are not supported in GhostScope scripts.

## Built-in Functions

GhostScope provides built-in functions to make common string checks efficient and verifier-friendly.

Supported built-ins (phase 1):
- `strncmp(expr, "lit", n)`
  - Compares the first `n` bytes of the memory pointed to by `expr` against the string literal `lit`.
  - Does not require a terminating NUL within `n` bytes.
  - `expr` may be a DWARF `char*`, `char[N]`, or a generic pointer expression; GhostScope performs a bounded user-memory read and compares bytes.
  - Any DWARF-backed read failure evaluates to `false` and is surfaced as a structured warning; see “Runtime Expression Failures (ExprError)” below.
  - Read length is capped by configuration `ebpf.compare_cap` (default 64 bytes). If `n` exceeds the cap or the available array size, it is truncated.

- `starts_with(expr, "lit")`
  - Equivalent to `strncmp(expr, "lit", len("lit"))`.
  - Same failure and safety semantics as above.

- `memcmp(expr_a, expr_b, len)`
  - Boolean variant: returns `true` iff the first `len` bytes at `expr_a` and `expr_b` are identical.
  - Pointers: `expr_a` and `expr_b` accept DWARF pointer/array expressions or a raw address literal (decimal/hex `0x..`/octal `0o..`/binary `0b..`). For literal string comparisons, use `strncmp`/`starts_with` instead.
  - Integer expressions semantics: any integer expression (that is not `hex("...")`) is treated as a user virtual address and read via `bpf_probe_read_user`. It is NOT interpreted as a byte pattern. To compare against raw bytes, use `hex("...")` below.
  - `len` can be a script integer expression; supports decimal, hex (`0x..`), octal (`0o..`), and binary (`0b..`) literals. The engine clamps negative values to 0 at runtime; however, the parser rejects literal negative lengths.
  - No NUL-terminator semantics; compares raw bytes only.
  - Any DWARF-backed read failure on either side evaluates to `false` and is surfaced as a structured warning; see “Runtime Expression Failures (ExprError)”.
  - If `len == 0`, the result is `true` and no user-memory read is performed (fast-path).
  - Implementation is verifier-friendly: reads are bounded and comparisons are accumulated without early exits.
  - See also: Hex Literal Helper (`hex`) below.
    - If either operand is `hex("...")`, you may omit `len`; the parser will infer `len` from the hex pattern size. If both operands are `hex(...)`, their sizes must match.
    - When using a literal `len` with `hex("...")`, the parser validates that `len` is non-negative and does not exceed the hex pattern size.

Verifier friendliness and performance:
- Compiles to branch-light byte comparisons (e.g., XOR/OR accumulation) to avoid verifier state explosion.
- Avoid packing many large string checks into a single very hot probe; consider splitting trace points or using less-hot sites when possible.

Examples

```ghostscope
// Function parameter (const char* activity)
trace log_activity {
    print "is_main:{}", starts_with(activity, "main");
    print "eq5:{}", strncmp(activity, "main_", 5);
}

// Global C strings and fixed arrays
trace globals_program.c:32 {
    print "gm_hello:{}", starts_with(gm, "Hello"); // gm: const char*
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);    // lm: const char*
}

// Generic pointer (read failure -> false)
trace process_record {
    print "rec_http:{}", strncmp(record, "HTTP", 4); // record: struct* -> false
}

// Raw memory equality between two pointers
trace globals_program.c:32 {
    // Equal bytes
    if memcmp(&lib_pattern[0], &lib_pattern[0], 16) { print "EQ"; } else { print "NE"; }
    // Different due to offset
    if memcmp(&lib_pattern[0], &lib_pattern[1], 16) { print "EQ2"; } else { print "NE2"; }
    // len=0 → true
    if memcmp(&lib_pattern[0], &lib_pattern[1], 0) { print "Z0"; }
    // Dynamic length from script variable
    let n = 10;
    if memcmp(&lib_pattern[0], &lib_pattern[0], n) { print "DYN_EQ"; }
}
```
```

### Hex Literal Helper (`hex`)

- Syntax: `hex("<HEX BYTES>")`
  - `<HEX BYTES>` must contain only hex digits (`0-9a-fA-F`) and spaces as separators (tabs and other separators are not allowed); after removing spaces, the number of hex digits must be even.
  - Parse-time validation: any non-hex, non-space character or odd number of hex digits causes a clear error. Additionally, with `memcmp(expr, hex(...), len_literal)`, the parser rejects `len_literal` larger than the hex pattern size, and rejects negative literal lengths.
- Semantics: produces a byte sequence interpreted left-to-right (two hex digits per byte). No endianness is involved and no `0x` prefixes are allowed inside the string.
- Scope: supported as an argument to `memcmp` to compare memory against raw bytes (e.g., headers, magic constants).
- Examples:

```ghostscope
trace foo {
    // Compare first 2 bytes with ASCII "PO"
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }

    // Compare 4 bytes 0xDE 0xAD 0xBE 0xEF
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }
}
```

### Special Variables

Special variables start with `$` and expose runtime info from the kernel.

Supported now:

- `$pid` — current process ID (tgid), from `bpf_get_current_pid_tgid` lower 32 bits.
- `$tid` — current thread ID, from `bpf_get_current_pid_tgid` upper 32 bits.
- `$timestamp` — monotonic timestamp in nanoseconds, from `bpf_ktime_get_ns`.

All behave as integers and can be used in comparisons and arithmetic.

Examples

```ghostscope
trace sample.c:42 {
    if $pid == 12345 { print "match"; }
    print "PID:{} TID:{} TS:{}", $pid, $tid, $timestamp;
}
```

Note: Only `$pid`, `$tid` and `$timestamp` are supported at present. Additional register-related specials may be added later.

### Variable Lookup Order

When a variable is encountered in a script, GhostScope searches in this order:
1. Script-defined variables (defined with `let`)
2. Local variables and parameters from the traced program
3. Global variables from the traced program

Note: Script variables can shadow program variables, so be careful with naming.

## Backtrace Statement (In Progress)

Print the current call stack:

```ghostscope
// Full form
backtrace;

// Short form
bt;
```

## Examples

### Basic Function Tracing

```ghostscope
trace main {
    print "Program started";
    print "PID: {}", $pid;
}
```

### Conditional Tracing

```ghostscope
trace malloc {
    if size > 1048576 {  // 1 MB
        print "Large allocation: {} bytes", size;
        backtrace;
    }
}
```

### Struct Field Access

```ghostscope
trace process_user {
    print "User: {}", user.name;
    print "ID: {}", user.id;

    if user.status == 1 {
        print "Active user";
    }
}
```

### Complex Variable Access

```ghostscope
trace handle_request {
    // Array access
    print "First item: {}", items[0];

    // Nested struct access
    print "Config value: {}", config.network.timeout;

    // Pointer operations
    print "Dereferenced: {}", *ptr;
    print "Address: {}", &variable;
}
```

### Multiple Trace Points in Script File

```ghostscope
// script.gs file
trace server_accept {
    print "New connection";
}

trace server_process {
    print "Processing request type: {}", $arg0;
}

trace server_respond {
    print "Sending response code: {}", $arg1;
}
```

## Limitations

1. **No Loops**: For safety reasons, loops (`for`, `while`) are not supported
2. **No Function Definitions**: Cannot define custom functions
3. **Read-Only**: Cannot modify the traced program's state
4. **Limited String Operations**: Supports CString equality (==/!=) and builtins `strncmp`/`starts_with`; no concatenation or general string manipulation
5. **Limited Arithmetic**: Basic operations only, no bitwise operations
6. **No Dynamic Memory**: Cannot allocate memory

## Best Practices

1. **Keep It Simple**: Trace actions should be lightweight to minimize overhead
2. **Filter Early**: Use conditions to reduce trace frequency
3. **Use Meaningful Output**: Include context in print statements
4. **Avoid Complex Logic**: Keep trace logic straightforward
5. **Test Incrementally**: Start with simple traces, add complexity gradually

## Notes

- Variable declarations (`let`) create script-local variables, not program variables
- All variables are dynamically typed
- String literals must use double quotes
- Statement semicolons are required for most statements
- The trace pattern matching supports fuzzy file matching (see [Command Reference](command-reference.md))
## Runtime Expression Failures (ExprError)

When an `if/else if` condition or a builtin (`memcmp`, `strncmp`, `starts_with`) depends on DWARF-backed runtime reads and a read fails, GhostScope does not silently treat the condition as `false`. Instead, it sends a structured warning (ExprError) to user space and applies “soft-abort” semantics:

- Soft-abort semantics
  - For the failing `if`: skip both then and else. An `else if` chain will continue evaluation; if a later condition succeeds, its branch executes.
  - For `print`: do not abort; variables already carry per-variable statuses. If a builtin arg (e.g., `memcmp`) fails inside `print`, an additional ExprError is emitted while the line still renders.

### ExprError fields

- `expr`: human-readable expression text (UTF-8 safe truncated if long).
- `code`: error code aligned with `VariableStatus` meanings:
  - 1 = NullDeref, 2 = ReadError, 3 = AccessError, 4 = Truncated, 5 = OffsetsUnavailable, 6 = ZeroLength
- `flags`: bitmask with builtin-specific meanings:
  - `memcmp`:
    - `0x01` → first-arg read-fail (arg0)
    - `0x02` → second-arg read-fail (arg1)
    - `0x04` → len-clamped (compare length truncated to cap)
    - `0x08` → len=0 (effective length is zero)
  - `strncmp/starts_with`:
    - `0x01` → read-fail
    - `0x04`, `0x08` reserved for length clamped/zero (future use)
- `failing_addr`: the pointer address involved in the failure (0 if unknown).

Console example (no emoji; TUI adds its own styling):

```
ExprError: memcmp(buf, hex("504f"), 2) (read error at 0x0000000100000000, flags: first-arg read-fail,len-clamped)
```

When the failing address is zero, the output shows `at NULL`:

```
ExprError: memcmp(G_STATE.lib, hex("00"), 1) (read error at NULL, flags: first-arg read-fail)
```
