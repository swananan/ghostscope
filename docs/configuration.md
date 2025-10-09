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
# 2. .gnu_debuglink section (see search paths below)
# 3. .gnu_debugdata section (Android/compressed)
# 4. Build-ID based paths

# .gnu_debuglink search paths (configurable in config.toml):
# 1. Absolute path (if .gnu_debuglink contains absolute path - rare)
# 2. User-configured search_paths + basename (highest priority)
# 3. Same directory as the binary + basename
# 4. .debug subdirectory next to the binary + basename
#
# Note: To use system-wide debug directories like /usr/lib/debug,
# add them to search_paths in config.toml
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

### Advanced eBPF Options

```bash
# Force PerfEventArray mode (for testing only)
# WARNING: Testing purposes only. Forces PerfEventArray even on kernels >= 5.8
ghostscope --force-perf-event-array
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
| `--force-perf-event-array` | | Force PerfEventArray (testing) | Off |
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
# Debug information search paths for .gnu_debuglink files
# When a binary uses .gnu_debuglink to reference separate debug files,
# GhostScope searches these paths to locate the debug file.
#
# Search order (highest priority first):
# 1. Absolute path (if .gnu_debuglink contains an absolute path - rare)
# 2. User-configured search_paths + basename (configured here)
# 3. Same directory as the binary + basename
# 4. .debug subdirectory next to the binary + basename
#
# For each user-configured path, both direct and .debug subdirectory are checked:
#   - <path>/debug_filename
#   - <path>/.debug/debug_filename
#
# Features:
# - Home directory expansion: "~/" is replaced with your home directory
# - Duplicate paths are automatically removed to avoid redundant checks
# - Paths are tried in order until a matching debug file is found
#
# Note: .gnu_debuglink typically uses basename (relative path), but absolute paths
# are also supported. If you need system-wide debug directories like /usr/lib/debug,
# add them to search_paths.
#
# Examples:
search_paths = [
    "/usr/lib/debug",           # System debug symbols (for installed packages)
    "/usr/local/lib/debug",     # Local debug symbols
    "~/.local/lib/debug",       # User debug symbols (~ expands to home)
    "/opt/debug-symbols"        # Custom debug symbol server
]

# Allow non-strict debug file matching (CRC/Build-ID)
# Default: false (strict). When true, GhostScope will allow using a separate
# debug file even if CRC or Build-ID does not match exactly. This is useful for
# ad-hoc environments or partially repackaged symbols, but may cause inaccurate
# symbol/line information. Prefer leaving this off unless you know what you are doing.
allow_loose_debug_match = false

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

# Maximum number of eBPF trace messages to keep in the output panel
# Older messages are automatically discarded when this limit is reached
# Minimum value: 100
# Recommended values:
#   - Low-frequency tracing: 1000-2000
#   - Medium-frequency tracing: 2000-5000 (default: 2000)
#   - High-frequency tracing: 5000-10000
# Note: Larger values consume more memory
ebpf_max_messages = 2000

[ui.history]
# Enable command history
enabled = true

# Maximum history entries
max_entries = 5000

[ebpf]
# RingBuf map size in bytes (must be power of 2)
# Controls the size of the ring buffer for transferring trace events from kernel to userspace
# Valid range: 4096 (4KB) to 16777216 (16MB)
ringbuf_size = 262144  # 256KB (default)

# Recommended values:
#   - Low-frequency tracing: 131072 (128KB)
#   - Medium-frequency tracing: 262144 (256KB)
#   - High-frequency tracing: 524288 (512KB) or 1048576 (1MB)

# PerfEventArray page count per CPU (for older kernels < 5.8)
# Number of memory pages allocated per CPU for PerfEventArray buffers
# Each page is typically 4KB, so 64 pages = 256KB per CPU
# Must be a power of 2. Valid range: 8 to 1024 pages
perf_page_count = 64  # Default (256KB per CPU)

# Recommended values:
#   - Low-frequency tracing: 32 pages (~128KB per CPU)
#   - Medium-frequency tracing: 64 pages (~256KB per CPU)
#   - High-frequency tracing: 128-256 pages (512KB-1MB per CPU)

# Maximum number of (pid, module) offset entries for ASLR translation
# Stores runtime address offsets for each loaded module in each process
# Valid range: 64 to 65536
proc_module_offsets_max_entries = 4096  # Default

# Per-argument memory dump cap for extended format specifiers ({:x}/{:s}).
# Increase to dump more bytes per argument.
mem_dump_cap = 4096

# Compare cap for built-in comparisons (strncmp/starts_with/memcmp).
# Controls the maximum number of bytes compared per call.
# Effective compare length is min(max(len, 0), compare_cap).
# Default: 64 bytes.
compare_cap = 64

# Maximum size of a single trace event (bytes). Applies to PerfEventArray accumulation buffer.
max_trace_event_size = 32768

# Recommended values:
#   - Single process: 1024
#   - Multi-process: 4096
#   - System-wide tracing: 8192 or 16384

# Force use of PerfEventArray instead of RingBuf (TESTING ONLY)
# WARNING: This is for testing purposes only. Set to true to force PerfEventArray
# even on kernels that support RingBuf (>= 5.8). PerfEventArray has performance
# overhead compared to RingBuf and should only be used for compatibility testing.
force_perf_event_array = false  # Default (auto-detect based on kernel version)
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

#### High-Frequency Tracing Configuration

```toml
# Optimized for high-frequency event tracing
[ebpf]
ringbuf_size = 1048576  # 1MB buffer for high event rates
mem_dump_cap = 4096     # Larger per-arg dump
compare_cap = 64        # Max bytes for built-in compares (strncmp/memcmp)
max_trace_event_size = 65536  # Larger event size for big formatted prints
proc_module_offsets_max_entries = 8192  # Support many modules

[general]
log_level = "info"  # Reduce logging overhead
enable_console_logging = false
```

#### Low-Overhead Configuration

```toml
# Minimal resource usage for production
[ebpf]
ringbuf_size = 131072  # 128KB minimal buffer
mem_dump_cap = 512
compare_cap = 32       # Smaller compare cap for minimal overhead
max_trace_event_size = 16384
proc_module_offsets_max_entries = 1024  # Single process only

[general]
log_level = "error"
enable_logging = false

[files]
[files.save_llvm_ir]
debug = false
release = false
[files.save_ebpf]
debug = false
release = false
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
- **eBPF Max Messages**: 2000 messages
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
7. **UI Configuration**:
   - **ebpf_max_messages**: Must be at least 100
8. **eBPF Configuration**:
   - **ringbuf_size**: Must be power of 2, range 4096-16777216 bytes
   - **perf_page_count**: Must be power of 2, range 8-1024 pages
   - **mem_dump_cap**: Per-argument memory dump cap (bytes), e.g., 1024/2048/4096
   - **max_trace_event_size**: Max bytes per trace event (PerfEventArray accumulation buffer)
   - **proc_module_offsets_max_entries**: Must be in range 64-65536

Invalid configuration will produce clear error messages with suggestions for fixes.

### Common Validation Errors

- **"Process with PID X is not running"**: Target process not found. Use `ps -p <PID>` to verify.
- **"Target file does not exist"**: Specified target path not found. Check the file path.
- **"Script file does not exist"**: Specified script file not found.
- **"Invalid log level"**: Use one of: error, warn, info, debug, trace.
- **"ringbuf_size must be a power of 2"**: Use values like 131072, 262144, 524288, etc.
- **"ringbuf_size X is out of reasonable range"**: Must be between 4KB and 16MB.
- **"perf_page_count must be a power of 2"**: Use values like 32, 64, 128, 256, etc.
- **"perf_page_count X is out of reasonable range"**: Must be between 8 and 1024 pages.
- **"proc_module_offsets_max_entries X is out of reasonable range"**: Must be between 64 and 65536.
- **"ebpf_max_messages X is too small"**: Must be at least 100. Increase the value in your config file.

## Best Practices

1. **Use Configuration Files**: Store common settings in `~/.ghostscope/config.toml`
2. **Environment-Specific Configs**: Keep separate configs for development and production
3. **Log Rotation**: Configure external log rotation for long-running sessions
4. **Debug Output**: Disable debug file saving in production for performance
5. **Panel Layout**: Use horizontal layout for wide screens, vertical for narrow displays
6. **eBPF Tuning**:
   - Start with default `ringbuf_size` (256KB) and increase if events are dropped
   - Monitor kernel memory usage when using large ringbuf sizes
   - Use smaller `proc_module_offsets_max_entries` for single-process debugging
   - Increase buffer size for high-frequency tracing scenarios
