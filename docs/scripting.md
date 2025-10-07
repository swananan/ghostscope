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
| Boolean (bool) | from comparisons: `a < b` | Produced by comparisons/logical expressions | logical AND/OR (script only); when mixing with DWARF integers, treated as 0/1 |
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

Use `{}` as placeholders in format strings:

```ghostscope
// Format string with arguments
print "Value: {}", value;
print "X: {}, Y: {}", x, y;
print "Name: {}, Age: {}", person.name, person.age;
```

**Note**: The format string uses `{}` placeholders (Rust-style), not `%d`/`%s` (C-style).

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
```

### Expression Precedence

1. Parentheses `()`
2. Member access `.`, Array access `[]`
3. Pointer dereference `*`, Address of `&`, Unary minus `-`
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

- `&&` (logical AND), `||` (logical OR)
- Operands are treated as booleans with "non-zero is true" semantics
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
- Builtins (`strncmp`/`starts_with`) cap read length to 64 bytes for safety (see `STRING_BUILTIN_READ_CAP` in `ghostscope-compiler/src/ebpf/expression.rs`).
  CString equality reads only `L+1` bytes (no extra cap beyond the literal length).

// Floats are not supported in GhostScope scripts.

## Built-in Functions

GhostScope provides built-in functions to make common string checks efficient and verifier-friendly.

Supported built-ins (phase 1):
- `strncmp(expr, "lit", n)`
  - Compares the first `n` bytes of the memory pointed to by `expr` against the string literal `lit`.
  - Does not require a terminating NUL within `n` bytes.
  - `expr` may be a DWARF `char*`, `char[N]`, or a generic pointer expression; GhostScope performs a bounded user-memory read and compares bytes.
  - Any read failure evaluates to `false`.
  - Read length is capped at 64 bytes; if `n` exceeds the cap or the available array size, it is truncated. See `STRING_BUILTIN_READ_CAP` in `ghostscope-compiler/src/ebpf/expression.rs`.

- `starts_with(expr, "lit")`
  - Equivalent to `strncmp(expr, "lit", len("lit"))`.
  - Same failure and safety semantics as above.

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
```
```

### Special Variables (In Progress)

Special variables start with `$` and provide access to runtime information:

```ghostscope
// Function arguments (x86_64 calling convention)
$arg0, $arg1, $arg2, $arg3, $arg4, $arg5

// Process information
$pid    // Process ID
$tid    // Thread ID
$comm   // Process name

// Return value (in return probes)
$retval

// CPU registers (architecture-specific)
$pc     // Program counter
$sp     // Stack pointer
```

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

### Monitoring Function Arguments

```ghostscope
trace calculate {
    print "calculate({}, {})", $arg0, $arg1;

    if $arg0 > 1000 {
        print "Large input detected";
        bt;
    }
}
```

### Conditional Tracing

```ghostscope
trace malloc {
    if $arg0 > 1048576 {  // 1 MB
        print "Large allocation: {} bytes", $arg0;
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
