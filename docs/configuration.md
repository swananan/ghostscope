# Configuration Reference

GhostScope can be configured through command-line arguments, configuration files, and environment variables.

## Configuration Priority

Configuration follows this priority order (highest to lowest):
1. Command-line arguments
2. Environment variables (RUST_LOG)
3. Configuration file (~/.ghostscope/config.toml or ./ghostscope.toml)
4. Default values

## Command-Line Arguments

### Target Selection

```bash
# Attach to a running process by PID
ghostscope -p <PID>
ghostscope --pid <PID>

# Specify target executable or library (with path resolution)
ghostscope -t <PATH>
ghostscope --target <PATH>

# Target path resolution order for relative paths:
# 1. Current working directory
# 2. Same directory as ghostscope executable
# 3. Converts to absolute path if not found

# Both can be used together for PID filtering
ghostscope -t /usr/bin/myapp -p 1234

# Launch a new process with arguments
ghostscope --args /path/to/program arg1 arg2
# Everything after --args is passed to the target program
```

### Script Execution

```bash
# Run inline script
ghostscope -s 'trace("main:entry") { print "Started"; }'
ghostscope --script 'trace("main:entry") { print "Started"; }'

# Run script from file
ghostscope --script-file trace.gs

# Start in TUI mode (default if no script provided)
ghostscope --tui
```

### Debug Information

```bash
# Specify custom debug file (overrides auto-detection)
ghostscope -d /path/to/binary.debug
ghostscope --debug-file /path/to/binary.debug

# Auto-detection searches in order:
# 1. Binary itself (.debug_info sections)
# 2. .gnu_debuglink section
# 3. .gnu_debugdata section (Android/compressed)
# 4. /usr/lib/debug, /usr/local/lib/debug
# 5. Build-ID based paths
# 6. binary.debug, binary.dbg
```

### Logging Configuration

```bash
# Enable file logging (default: ./ghostscope.log)
ghostscope --log

# Disable all logging
ghostscope --no-log

# Enable console output in addition to file
ghostscope --log-console

# Disable console output
ghostscope --no-log-console

# Set log level
ghostscope --log-level debug  # Options: error, warn, info, debug, trace

# Custom log file path
ghostscope --log-file /var/log/ghostscope.log
```

### Debug Output Files

```bash
# Save LLVM IR files (default: enabled in debug builds)
ghostscope --save-llvm-ir
ghostscope --no-save-llvm-ir

# Save eBPF bytecode files (default: enabled in debug builds)
ghostscope --save-ebpf
ghostscope --no-save-ebpf

# Save AST files (default: enabled in debug builds)
ghostscope --save-ast
ghostscope --no-save-ast
```

### UI Layout

```bash
# Set TUI layout mode
ghostscope --layout horizontal  # Panels side by side (default)
ghostscope --layout vertical    # Panels top to bottom
```

### Complete Command Reference

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--pid <PID>` | `-p` | Process ID to attach to | None |
| `--target <PATH>` | `-t` | Target executable or library | None |
| `--script <SCRIPT>` | `-s` | Inline script to execute | None |
| `--script-file <PATH>` | | Script file to execute | None |
| `--debug-file <PATH>` | `-d` | Debug info file path | Auto-detect |
| `--tui` | | Start in TUI mode | Auto |
| `--log` | | Enable file logging | Script: off, TUI: on |
| `--no-log` | | Disable all logging | - |
| `--log-console` | | Enable console logging | Off |
| `--no-log-console` | | Disable console logging | - |
| `--log-level <LEVEL>` | | Set log level | warn |
| `--log-file <PATH>` | | Log file path | ./ghostscope.log |
| `--save-llvm-ir` | | Save LLVM IR files | Debug: on, Release: off |
| `--no-save-llvm-ir` | | Don't save LLVM IR | - |
| `--save-ebpf` | | Save eBPF bytecode | Debug: on, Release: off |
| `--no-save-ebpf` | | Don't save eBPF | - |
| `--save-ast` | | Save AST files | Debug: on, Release: off |
| `--no-save-ast` | | Don't save AST | - |
| `--layout <MODE>` | | TUI layout mode | horizontal |
| `--config <PATH>` | | Custom config file | Auto-detect |
| `--args <PROGRAM> [ARGS...]` | | Launch program with args | None |

## Configuration File

GhostScope looks for configuration files in this order:
1. Path specified with `--config`
2. `~/.ghostscope/config.toml` (user-level)
3. `./ghostscope.toml` (project-level)

### Configuration File Format

```toml
# ~/.ghostscope/config.toml or ./ghostscope.toml

[general]
# Default log file path
log_file = "ghostscope.log"

# Default TUI mode when no script provided
default_tui_mode = true

# Enable/disable file logging
enable_logging = false

# Enable/disable console logging
enable_console_logging = false

# Log level: error, warn, info, debug, trace
log_level = "warn"

[dwarf]
# Debug information search paths
search_paths = [
    "/usr/lib/debug",
    "/usr/local/lib/debug"
]

[files]
# Save LLVM IR files
[files.save_llvm_ir]
debug = true
release = false

# Save eBPF bytecode files
[files.save_ebpf]
debug = true
release = false

# Save AST files
[files.save_ast]
debug = true
release = false

[ui]
# TUI layout mode: Horizontal or Vertical (capitalized)
layout = "Horizontal"

# Default focused panel: Source, EbpfInfo, or InteractiveCommand
default_focus = "InteractiveCommand"

# Panel size ratios [Source, EbpfInfo, InteractiveCommand]
# Must be 3 positive (non-zero) integers
panel_ratios = [4, 3, 3]

[ui.history]
# Enable command history
enabled = true

# Maximum history entries
max_entries = 5000
```

### Configuration Examples

#### Development Configuration

```toml
# Development setup with verbose logging and debug output
[general]
log_level = "debug"
enable_logging = true
enable_console_logging = true

[files]
[files.save_llvm_ir]
debug = true
[files.save_ebpf]
debug = true
[files.save_ast]
debug = true
```

#### Production Configuration

```toml
# Production setup with minimal overhead
[general]
log_level = "error"
enable_logging = true
enable_console_logging = false
log_file = "/var/log/ghostscope.log"

[files]
[files.save_llvm_ir]
debug = false
release = false
[files.save_ebpf]
debug = false
release = false
```

#### UI-Focused Configuration

```toml
# Optimized for interactive debugging
[ui]
layout = "Horizontal"
default_focus = "Source"
panel_ratios = [5, 2, 3]  # Larger source panel

[ui.history]
enabled = true
max_entries = 10000
```

## Environment Variables

### RUST_LOG

Controls log level when `--log-level` is not specified:

```bash
# Set log level via environment
export RUST_LOG=debug
ghostscope -p 1234

# Module-specific logging
export RUST_LOG=ghostscope=debug,ghostscope_compiler=trace
```

Priority: Command line > RUST_LOG > Config file

### LLVM_SYS_*_PREFIX

Specify LLVM installation path if not found automatically:

```bash
# For LLVM 15
export LLVM_SYS_150_PREFIX=/usr/lib/llvm-15

# For LLVM 17
export LLVM_SYS_170_PREFIX=/usr/lib/llvm-17
```

## Default Behaviors

### Logging Defaults

- **TUI Mode**: File logging enabled, console logging disabled
- **Script Mode**: All logging disabled by default
- **Log Level**: `warn` if not specified
- **Log File**: `./ghostscope.log` in current directory

### Debug Output Defaults

- **Debug Builds**: Save LLVM IR, eBPF bytecode, and AST files
- **Release Builds**: Don't save any debug files

### UI Defaults

- **Layout**: Horizontal (panels side by side)
- **Panel Ratios**: 4:3:3 (Source:EbpfInfo:Command)
- **Default Focus**: InteractiveCommand panel
- **History**: Enabled with 5000 entry limit

## File Output Naming

Debug files are saved with this naming convention:
```
gs_{pid}_{exec}_{func}_{index}.{ext}
```

Where:
- `pid`: Process ID
- `exec`: Executable name
- `func`: Function name
- `index`: Unique index for multiple traces
- `ext`: File extension (`.ll` for LLVM IR, `.ebpf` for bytecode, `.ast` for AST)

Example: `gs_1234_myapp_main_0.ll`

## Validation

GhostScope validates configuration at startup:

1. **PID Validation**: Checks if specified PID exists (via `/proc/<PID>` on Linux)
2. **File Validation**: Verifies target, script, and debug files exist
3. **Target Path Resolution**: Converts relative paths to absolute paths
4. **Panel Ratios**: Ensures all 3 values are positive (non-zero) integers
5. **Log Level**: Validates against allowed values (error, warn, info, debug, trace)
6. **Layout Mode**: Validates against allowed values (Horizontal, Vertical - capitalized)

Invalid configuration will produce clear error messages with suggestions for fixes.

### Common Validation Errors

- **"Process with PID X is not running"**: Target process not found. Use `ps -p <PID>` to verify.
- **"Target file does not exist"**: Specified target path not found. Check the file path.
- **"Script file does not exist"**: Specified script file not found.
- **"Invalid log level"**: Use one of: error, warn, info, debug, trace.

## Best Practices

1. **Use Configuration Files**: Store common settings in `~/.ghostscope/config.toml`
2. **Environment-Specific Configs**: Keep separate configs for development and production
3. **Log Rotation**: Configure external log rotation for long-running sessions
4. **Debug Output**: Disable debug file saving in production for performance
5. **Panel Layout**: Use horizontal layout for wide screens, vertical for narrow displays