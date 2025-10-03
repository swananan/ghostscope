# GhostScope Script Language Reference

GhostScope uses a domain-specific language for defining trace points and actions. Scripts are written when using the `trace` command in TUI or loaded from script files.

## Table of Contents
1. [Basic Syntax](#basic-syntax)
2. [Trace Statements](#trace-statements)
3. [Variables](#variables)
4. [Print Statement](#print-statement)
5. [Conditional Statements](#conditional-statements)
6. [Expressions](#expressions)
7. [Special Variables](#special-variables)
8. [Examples](#examples)
9. [Limitations](#limitations)

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

Script variables currently support integers, floats, and strings.

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
- Array access in chains (e.g., `a.b[idx].c`) is not supported yet. This version will reject such expressions or return a clear error.

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
3. Pointer dereference `*`, Address of `&`
4. Multiplication `/`, Division `/`
5. Addition `+`, Subtraction `-`
6. Comparisons `==`, `!=`, `<`, `<=`, `>`, `>=`

### Expression Grouping

```ghostscope
// Use parentheses for explicit precedence
let result = (a + b) * c;
let complex = (x + y) / (a - b);
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
4. **No String Operations**: String concatenation or manipulation not supported
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
