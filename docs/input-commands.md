# Input Mode Commands Reference

This document details all commands available in GhostScope's Command Interaction Panel **Input Mode**.

## Quick Reference

Type `help` in Input Mode to see available commands with their shortcuts.

---

## 📊 Tracing Commands

Commands for setting and managing trace points in your application.

### trace - Start Tracing

**Syntax:**
```
trace <target>
t <target>          # Short form
```

**Parameters:**
- `<target>`: Can be:
  - Function name: `function_name`
  - File and line: `file:line` where file can be:
    - Full path: `/path/to/file.c:42`
    - Relative path: `src/file.c:42`
    - Filename (fuzzy match): `file.c:42` or even partial name
  - Address: `0xADDR` or `module_suffix:0xADDR`
    - `0xADDR`: Module-relative virtual address (DWARF PC). Default module depends on startup mode:
      - `-t <binary>`: defaults to `<binary>` (including `.so`)
      - `-p <pid>`: defaults to the process’s main executable
    - `module_suffix:0xADDR`: Address in a specific module. The module part supports full path or unique suffix matching; ambiguous suffixes will be reported with candidates.

**Examples:**
```
trace main                    # Trace main function
trace calculate_something     # Trace specific function
trace /home/user/src/sample.c:42    # Full path
trace src/sample.c:42         # Relative path
trace sample.c:42            # Filename only (fuzzy match)
trace sample:42              # Partial filename (fuzzy match)
t 0x401234                   # Address in default module (depends on -t/-p)
t libc.so.6:0x1234           # Address in a shared library by suffix
t process_data               # Use short form
```

**Description:**
After executing trace command, you enter Script Mode to write trace scripts. Press `Ctrl+S` to save and execute, `Ctrl+C` or `Esc` to cancel.

**Script Mode Workflow:**
1. Execute `trace <target>` → Enter Script Mode with syntax highlighting
2. Write trace script (see [Script Language Reference](scripting.md) for syntax)
3. Submit and compile:
   - `Ctrl+S`: Submit script and compile to eBPF
   - `Ctrl+C` or `Esc`: Cancel and return to Input Mode
4. View compilation results in command panel
5. Check real-time trace output in eBPF Output Panel

**Script Caching:**
- Scripts are automatically cached per target
- Re-entering same target (e.g., `trace sample.c:42` again) restores previous script
- Cache persists until you exit GhostScope
- Useful for iterative debugging: modify → test → modify

**Quick Start Example:**
```bash
# 1. Enter script mode for a function
trace main

# 2. In Script Mode, write:
print "Entering main, argc={}", argc;

# 3. Press Ctrl+S to submit
# 4. See output: ✅ Trace Results: 1 successful, 0 failed

# 5. Later, modify the same trace:
trace main          # Your previous script is restored!

# 6. Edit and press Ctrl+S again
```

#### Inline vs Call Annotations

- When tracing, compilation results now annotate each target with its code origin:
  - `inline`: The target address is inside an inlined function instance (DW_TAG_inlined_subroutine).
  - `call`: The target address is in a non-inlined context (regular function body/entry).
- The command panel shows these as: `— inline|call @ file:line` next to each address.
- This helps distinguish whether your probe lands in an inlined body or a normal function location.

#### Function vs Line Targets

- Function target (`trace <function_name> { ... }`):
  - Non-inline: selects the first executable instruction after the function prologue (prologue-skip).
  - Inline: selects the inline instance start (low_pc semantics of the inline DIE); this is an entry-like point and may not align to a statement boundary. Use a line target if you need precise statement alignment.
  - Multiple inline instances: if a function is inlined at multiple call sites, you’ll see one address per instance (plus one for the non-inline definition, if present).

- Source line target (`trace <file:line> { ... }`):
  - Resolves to the statement boundary on that line for each occurrence (one per inline instance across callers), i.e., statement-level semantics.
  - Typically yields one address per instance where that source line is active.

### enable - Enable Traces

**Syntax:**
```
enable <id|all>
en <id|all>         # Short form
```

**Parameters:**
- `<id>`: Trace point ID number
- `all`: Enable all trace points

**Examples:**
```
enable 1            # Enable trace with ID 1
enable all          # Enable all traces
en 3               # Short form for ID 3
```

### disable - Disable Traces

**Syntax:**
```
disable <id|all>
dis <id|all>        # Short form
```

**Parameters:**
- `<id>`: Trace point ID number
- `all`: Disable all trace points

**Examples:**
```
disable 2           # Disable trace with ID 2
disable all         # Disable all traces
dis 1              # Short form for ID 1
```

### delete - Delete Traces

**Syntax:**
```
delete <id|all>
del <id|all>        # Short form
```

**Parameters:**
- `<id>`: Trace point ID number
- `all`: Delete all trace points

**Examples:**
```
delete 3            # Delete trace with ID 3
delete all          # Delete all traces
del 2              # Short form for ID 2
```

### save traces - Save Trace Points

**Syntax:**
```
save traces [file]
save traces enabled [file]
save traces disabled [file]
s t [file]          # Short form
```

**Parameters:**
- `[file]`: Optional filename (uses default if not provided)
- `enabled`: Save only enabled traces
- `disabled`: Save only disabled traces

**Examples:**
```
save traces                     # Save all to default file
save traces my_traces.gs        # Save to specific file
save traces enabled active.gs   # Save only enabled traces
save traces disabled backup.gs  # Save only disabled traces
s t session.gs                  # Short form
```

### save output - Start Realtime eBPF Output Logging

**Syntax:**
```
save output [file]
s o [file]          # Short form
```

**Parameters:**
- `[file]`: Optional filename (uses timestamped default if not provided)

**Behavior:**
- Starts realtime logging of eBPF trace events to file
- All subsequent trace events are immediately written to file
- File is created if it doesn't exist, or appended if it exists
- Each event is flushed immediately for realtime capture
- Use `stop output` to stop logging

**Examples:**
```
save output                     # Start logging to ebpf_output_TIMESTAMP.log
save output debug.log           # Start logging to debug.log
s o trace_events.log            # Short form
```

### save session - Start Realtime Session Logging

**Syntax:**
```
save session [file]
s s [file]          # Short form
```

**Parameters:**
- `[file]`: Optional filename (uses timestamped default if not provided)

**Behavior:**
- Starts realtime logging of command session (commands + responses)
- All subsequent commands and their responses are immediately written to file
- File is created if it doesn't exist, or appended if it exists
- Commands are marked with `>>>`, responses are indented
- Use `stop session` to stop logging

**Examples:**
```
save session                    # Start logging to command_session_TIMESTAMP.log
save session debug_session.log  # Start logging to debug_session.log
s s my_session.log              # Short form
```

### stop output - Stop Realtime eBPF Output Logging

**Syntax:**
```
stop output
```

**Behavior:**
- Stops realtime eBPF output logging
- Flushes and closes the log file
- Returns error if no logging is active

### stop session - Stop Realtime Session Logging

**Syntax:**
```
stop session
```

**Behavior:**
- Stops realtime session logging
- Flushes and closes the log file
- Returns error if no logging is active

### source - Load Trace Script

**Syntax:**
```
source <file>
s <file>            # Short form (but not "s t")
```

**Parameters:**
- `<file>`: Script file to load

**Examples:**
```
source traces.gs            # Load trace script
source /path/to/script.gs   # Load from path
s my_script.gs             # Short form
```

---

## 🔍 Information Commands

Commands for viewing debug information and trace status.

### info - Show Info Commands

**Syntax:**
```
info                # Show available info subcommands
i                   # Short form
```

**Description:**
Displays list of available info subcommands.

### info trace - View Trace Status

**Syntax:**
```
info trace [id]
i t [id]            # Short form
```

**Parameters:**
- `[id]`: Optional trace ID (shows all if omitted)

**Examples:**
```
info trace          # Show all trace statuses
info trace 1        # Show details for trace ID 1
i t                # Short form for all
i t 2              # Short form for ID 2
```

### info source - List Source Files

**Syntax:**
```
info source
i s                 # Short form
```

**Description:**
Display all loaded source files with debug information.

### info file - Executable File Information

**Syntax:**
```
info file
i file              # Short form
i f                 # Shortest form (no args)
```

**Description:**
Display executable file information including:
- File path and type (ELF 64-bit/32-bit)
- Entry point address
- Symbol table status
- Debug information status (includes .gnu_debuglink detection)
- Section addresses (.text, .data)
- Launch mode (PID mode or static analysis mode)

**Output:**
- **ELF virtual addresses**: For `-t` mode (static analysis)
- **Runtime loaded addresses**: For `-p` mode (attached to process)
- **Debug link**: Shows separate debug file path if using .gnu_debuglink

**Examples:**
```
info file           # Show executable info
i file              # Short form
i f                 # Shortest form
```

### info share - List Shared Libraries

**Syntax:**
```
info share          # Show libraries WITH debug info (default)
info share all      # Show ALL loaded shared libraries
i sh                 # Short form for `info share`
i sh all             # Short form for `info share all`
```

**Description:**
Display loaded shared libraries (dynamic libraries) with:
- Memory address ranges (from/to)
- Symbol table status
- Debug information status
- Library file paths
- Separate debug files (if using .gnu_debuglink)

By default, `info share` only lists libraries that have debug information available.
Use `info share all` to list every loaded library regardless of debug info.

**Output Format:**
```
📚 Shared Libraries (N):

From               To                 Syms  Debug      Shared Object
──────────────────────────────────────────────────────────────────────
0x00007f...        0x00007f...        ✓     ✓          /lib/libc.so.6

Debug files (.gnu_debuglink):
  /lib/libc.so.6 → /usr/lib/debug/.build-id/ab/cdef.debug
```

### info function - Function Debug Info

**Syntax:**
```
info function <name> [verbose|v]
i f <name> [v]      # Short form
```

**Parameters:**
- `<name>`: Function name
- `[verbose|v]`: Optional. Show DWARF location expressions (hidden by default)

**Examples:**
```
info function main       # Show debug info (without DWARF expressions)
info function main v     # Show with DWARF expressions
i f calculate verbose   # Short form with verbose
i f test v              # Shortest form with verbose
```

### info line - Source Line Debug Info

**Syntax:**
```
info line <file:line> [verbose|v]
i l <file:line> [v] # Short form
```

**Parameters:**
- `<file:line>`: File name and line number
- `[verbose|v]`: Optional. Show DWARF location expressions (hidden by default)

**Examples:**
```
info line main.c:42     # Debug info for line 42 (without DWARF expressions)
info line main.c:42 v   # Show with DWARF expressions
i l test.c:100 verbose # Short form with verbose
i l test.c:100 v       # Shortest form with verbose
```

### info address - Address Debug Info

**Syntax:**
```
info address <0xADDR | module_suffix:0xADDR> [verbose|v]
i a <0xADDR | module_suffix:0xADDR> [v]    # Short form
```

**Parameters:**
- `<0xADDR>`: Module-relative virtual address (DWARF/symbol PC) in hex. If no module is specified, the default module applies (see below).
- `module_suffix:0xADDR`: Address in a specific module. The module part supports full path or unique suffix matching; ambiguity will be reported with candidates.
- `[verbose|v]`: Optional. Show DWARF location expressions (hidden by default).

**Defaults and modes:**
- Launched with `-t <binary>` (target mode): the default module is `<binary>`.
- Launched with `-p <pid>` (PID mode): the default module is the main executable of the process. For library addresses, specify the module via suffix or use `-t` with that `.so`.

**Description:**
Shows per-module debug info for a given address: resolves function name (if any), source file:line (if available), and variables/parameters visible at that PC. Also displays the underlying module to attach and performs module suffix matching.

**Examples:**
```
info address 0x401234      # Use default module (depends on -t/-p)
info address libc.so.6:0x1234  # Suffix match shared library + address
info address /usr/bin/nginx:0xdeadbeef v  # Full path + verbose
```

#### Inline vs Call (Info Output)

- For `info function`, `info line`, and `info address`, each address line includes:
  - `— inline` if the PC falls in an inlined subroutine instance, otherwise `— call`.
  - `@ file:line` with the resolved source location when available.
- Same source line may appear multiple times (one per inline instance across different callers).

---

## 🗂️ Source Path Commands

Commands for managing source code path mappings when DWARF debug information contains compilation-time paths that differ from runtime paths.

### srcpath - Show Path Mappings

**Syntax:**
```
srcpath
```

**Description:**
Display current path substitution rules and search directories. Shows both runtime-added rules and config file rules.

### srcpath add - Add Search Directory

**Syntax:**
```
srcpath add <directory>
```

**Parameters:**
- `<directory>`: Directory path to search for source files

**Examples:**
```
srcpath add /usr/local/src           # Add search directory
srcpath add /home/user/sources       # Add user sources directory
```

**Description:**
When a source file cannot be found via exact path or substitution, GhostScope will search in the **root** of these directories by filename (basename matching, non-recursive). For example, after adding `/usr/local/src`, it can find `/usr/local/src/foo.c` but not `/usr/local/src/subdir/bar.c`.

### srcpath map - Map Compilation Path to Runtime Path

**Syntax:**
```
srcpath map <from> <to>
```

**Parameters:**
- `<from>`: Compilation-time path prefix (from DWARF debug info)
- `<to>`: Runtime path prefix (actual location on this machine)

**Examples:**
```
srcpath map /build/project /home/user/project          # CI build path to local
srcpath map /usr/src/linux-5.15 /home/user/kernel     # Kernel sources moved
srcpath map /buildroot/arm /local/embedded            # Cross-compilation paths
```

**Description:**
Replaces path prefixes from compilation time with runtime paths. If you run the same mapping twice with different `<to>` paths, the second one will update the existing mapping.

### srcpath remove - Remove Mapping or Directory

**Syntax:**
```
srcpath remove <path>
```

**Parameters:**
- `<path>`: Path prefix of a mapping or search directory to remove

**Examples:**
```
srcpath remove /build/project        # Remove mapping with this 'from' prefix
srcpath remove /usr/local/src        # Remove search directory
```

**Description:**
Removes a runtime-added rule (mapping or search directory). Config file rules cannot be removed via this command.

### srcpath clear - Clear All Runtime Rules

**Syntax:**
```
srcpath clear
```

**Description:**
Clears all runtime-added rules (both mappings and search directories). Config file rules are preserved.

### srcpath reset - Reset to Config Rules

**Syntax:**
```
srcpath reset
```

**Description:**
Removes all runtime-added rules and resets to config file rules only. Same as `srcpath clear`.

---

### Path Resolution Mechanism

GhostScope uses a **relative path + directory prefix** approach to locate source files:

1. **DWARF Information Contains**:
   - Compilation directory (comp_dir): e.g., `/home/build/nginx-1.27.1`
   - Source file relative path: e.g., `src/core/nginx.c`

2. **Path Composition**:
   - Full path = Compilation directory + Relative path
   - Example: `/home/build/nginx-1.27.1/src/core/nginx.c`

3. **Resolution Order**:
   - **First**: Try original full path
   - **Then**: Apply `map` substitution rules (recommended)
   - **Last**: Search in `add` directories by filename

### Recommended Usage

#### 🌟 Recommended: Use `srcpath map` to Map DWARF Directory

Map the compilation directory from DWARF to your local source directory. This makes **all relative path files automatically resolve**:

```bash
# Check file loading error message for DWARF directory
# Error displays:
# DWARF Directory: /home/build/nginx-1.27.1
# Relative Path: src/core/nginx.c

# Map DWARF directory to local path
srcpath map /home/build/nginx-1.27.1 /home/user/nginx-1.27.1

# Now all files can be found:
# /home/build/nginx-1.27.1/src/core/nginx.c → /home/user/nginx-1.27.1/src/core/nginx.c
# /home/build/nginx-1.27.1/src/http/ngx_http.c → /home/user/nginx-1.27.1/src/http/ngx_http.c
```

**Advantages**:
- ✅ One-time setup, works for all files
- ✅ Preserves directory structure, easy to understand
- ✅ Supports multi-level directories and complex projects
- ✅ File search (`o` key) automatically updates paths

#### Auxiliary: Use `srcpath add` for Search Directories

Only use when `map` cannot solve the problem (e.g., header files scattered across multiple locations):

```bash
# Add additional search directories
srcpath add /usr/local/include
srcpath add /opt/vendor/include
```

**Note**: `add` searches by **filename** (basename) only in directory root (non-recursive), cannot handle subdirectories, and may not find the correct file when names conflict.

### Configuration File Support

Path mappings can be persisted in `config.toml` to avoid manual configuration each time:

```toml
[source]
# Recommended: DWARF directory mappings
substitutions = [
    { from = "/home/build/myproject", to = "/home/user/work/myproject" },
    { from = "/usr/src/linux-5.15", to = "/home/user/kernel/linux-5.15" },
]

# Auxiliary: Additional search directories (searches by filename)
search_dirs = [
    "/usr/local/include",
    "/opt/local/src",
]
```

Runtime rules (via commands) take priority over config file rules.

### Common Use Cases

**Scenario 1: Source compiled on CI server** ⭐ Recommended
```bash
# Check DWARF Directory in error message
# Then map it to your local source root
srcpath map /home/jenkins/workspace/myproject /home/user/myproject
```

**Scenario 2: Compiled in container, debugging locally** ⭐ Recommended
```bash
# Docker container compilation directory: /build/app
# Local source at: /home/user/app
srcpath map /build/app /home/user/app
```

**Scenario 3: Multiple independent header directories**
```bash
# System headers and third-party library headers
srcpath add /usr/local/include
srcpath add /opt/project/vendor
```

**Scenario 4: Correcting a wrong mapping**
```bash
srcpath map /build /wrong/path        # First attempt (wrong)
srcpath map /build /correct/path      # Second attempt (updates existing mapping)
```

### Best Practices

1. **Prefer `map`**: Map DWARF compilation directory, not individual files
2. **Check error messages**: File loading failures display DWARF Directory, map it directly
3. **Preserve directory structure**: Keep same relative path structure as during compilation
4. **Save to config**: Save common mappings to `config.toml` to avoid repeated configuration
5. **Use `add` cautiously**: Only use when `map` cannot solve the problem, as it only searches by filename in directory root (non-recursive), cannot handle subdirectories, and may find wrong files with same names

---

## ⚙️ Control Commands

General control and utility commands.

### help - Show Help

**Syntax:**
```
help
```

**Description:**
Display comprehensive help with all available commands and keyboard shortcuts.

### clear - Clear History

**Syntax:**
```
clear
```

**Description:**
Clear command history (removes all previous commands from history display).

### quit/exit - Exit Program

**Syntax:**
```
quit
exit
```

**Description:**
Exit GhostScope. You can also use `Ctrl+C` twice to quit.

---

## Command Shortcuts Table

| Full Command | Short Form | Description |
|--------------|------------|-------------|
| `trace` | `t` | Set trace point |
| `enable` | `en` | Enable trace |
| `disable` | `dis` | Disable trace |
| `delete` | `del` | Delete trace |
| `info` | `i` | View information |
| `info file` | `i f`, `i file` | View executable file info |
| `info trace` | `i t` | View trace status |
| `info source` | `i s` | View source files |
| `info share` | `i sh` | View libraries WITH debug info |
| `info share all` | `i sh all` | View all shared libraries |
| `info function` | `i f <name>` | View function info |
| `info line` | `i l` | View line info |
| `info address` | `i a` | View address info |
| `save traces` | `s t` | Save trace points |
| `source` | `s` | Load script (except "s t") |
| `srcpath` | - | Manage source path mappings |

---

## Command Completion & History

### Command Completion

GhostScope provides a multi-layered intelligent completion system:

#### 1. Tab Command Completion

Press `Tab` to trigger command and parameter completion:

- **Command Completion**: Auto-complete GhostScope commands (trace, enable, info, etc.)
- **File Path Completion**: Auto-complete file paths for source command
- **Parameter Completion**: Context-aware parameter suggestions

**Examples**:
```
gs > t<Tab>          → trace
gs > info s<Tab>     → info source
gs > source /pa<Tab> → source /path/to/script.gs
```

#### 2. Auto-suggestion (Gray Hints)

As you type, GhostScope displays gray suggestion text based on command history:

- **Trigger Condition**: After typing 3+ characters
- **Source**: Matches prefix from command history
- **Accept Suggestion**: Press `→` (Right arrow) or `Ctrl+E`
- **Ignore Suggestion**: Continue typing or move cursor

**Example**:
```
gs > trace main<typing>
     trace main -s "print(a, b, c)"  ← Gray suggestion

     Press → to accept the entire suggestion
```

#### 3. File Name Completion

For commands requiring file paths, Tab completion supports:

- **Relative Paths**: From current directory
- **Absolute Paths**: From root directory
- **Multi-level Navigation**: Navigate through directory hierarchies
- **Smart Filtering**: Only show relevant file types (.gs script files)

### Command History

GhostScope automatically saves command history for quick reuse and search:

#### History Navigation

| Shortcut | Function |
|----------|----------|
| `↑` or `Ctrl+P` | Previous history command |
| `↓` or `Ctrl+N` | Next history command |

#### History Persistence

- **Auto-save**: Commands automatically saved to `.ghostscope_history` file
- **Cross-session**: History shared across different GhostScope sessions
- **Deduplication**: Consecutive duplicate commands not recorded
- **Capacity Limit**: Stores up to 1000 recent commands by default

#### History Management

Use `clear` command to clear history:

```bash
gs > clear          # Clear command history
```

**Note**: Clearing history deletes all records in `.ghostscope_history` file.

### Completion Configuration

History and completion behavior can be adjusted in config file (see [Configuration](configuration.md)):

```toml
[history]
enabled = true          # Enable history recording
max_entries = 1000     # Maximum history entries

[auto_suggestion]
enabled = true         # Enable auto-suggestion
min_chars = 3         # Minimum chars to trigger suggestion
```

---

## Tips & Best Practices

1. **Use Shortcuts**: Master command shortcuts (`t`, `en`, `dis`) for faster workflow
2. **Tab Completion**: Use `Tab` extensively for completion and command discovery
3. **History Navigation**: Use `Ctrl+P`/`Ctrl+N` or `↑`/`↓` to quickly reuse commands
4. **Batch Operations**: Use `all` parameter to operate on all traces at once
5. **Save Sessions**: Regularly save your trace configuration with `save traces`
6. **Script Reuse**: Save common trace patterns in files and load with `source`

---

## Error Messages

Common error messages and their meanings:

- `"Unknown command"`: Command not recognized. Check spelling or use `help`
- `"Usage: <command> <args>"`: Invalid arguments. Check command syntax
- `"Trace ID not found"`: The specified trace ID doesn't exist
- `"File not found"`: Script file doesn't exist at specified path

---

## Related Documentation

- [TUI Reference Guide](tui-reference.md) - Complete keyboard shortcuts and panel operations
- [Script Language Reference](scripting.md) - Trace script syntax
- [Quick Tutorial](tutorial.md) - Getting started guide
