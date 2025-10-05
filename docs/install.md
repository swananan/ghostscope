# Installation Guide

## System Requirements

- **Operating System**: Linux (kernel 4.4 or later)
  - **Required kernel features**:
    - eBPF support (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)
    - uprobe support (CONFIG_UPROBE_EVENTS=y) - introduced in Linux 3.5
    - BPF_MAP_TYPE_PERF_EVENT_ARRAY - introduced in Linux 4.3
    - Stable eBPF for tracing - recommended Linux 4.4+
- **Architecture**: x86_64 (AMD64) only currently

## Installation

### Download from GitHub Releases

1. Download the latest release from [GitHub Releases](https://github.com/swananan/ghostscope/releases)

2. Extract the binary:
```bash
tar -xzf ghostscope-v0.1.0-x86_64-linux.tar.gz
```

3. Move to system path (optional):
```bash
sudo mv ghostscope /usr/local/bin/
```

4. Make it executable:
```bash
chmod +x ghostscope
```

5. Verify installation:
```bash
ghostscope --version
```

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check GhostScope version
ghostscope --version

# View help
ghostscope --help
```

### 2. Configure Permissions

GhostScope requires root privileges to attach eBPF programs. You have several options:

#### Option A: Use sudo (Recommended)
```bash
sudo ghostscope -p $(pidof target)
```

#### Option B: Set Capabilities
```bash
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_bpf+eip /path/to/ghostscope
```

#### Option C: Add User to Tracing Group
```bash
# Create tracing group if it doesn't exist
sudo groupadd tracing

# Add your user to the group
sudo usermod -a -G tracing $USER

# Configure permissions for the group
echo 'kernel.perf_event_paranoid = -1' | sudo tee /etc/sysctl.d/10-ghostscope.conf
sudo sysctl -p /etc/sysctl.d/10-ghostscope.conf

# Re-login for group changes to take effect
```

### 3. Debug Symbols (Required)

GhostScope **requires** DWARF debug information in the target binary to function properly. The debug symbols are typically embedded in the binary itself.

```bash
# Check if your binary has debug info (REQUIRED)
readelf -S your_program | grep debug

# Example output with debug info:
# [28] .debug_aranges    PROGBITS         0000000000000000  0070a3c0
# [29] .debug_info       PROGBITS         0000000000000000  007158a0
# [30] .debug_abbrev     PROGBITS         0000000000000000  011b4eb1
# [31] .debug_line       PROGBITS         0000000000000000  012705a2
# [32] .debug_str        PROGBITS         0000000000000000  01542903
```

If no `.debug_*` sections are found, the binary must be recompiled with debug symbols enabled (typically using `-g` flag or equivalent).

**Note**: Without debug symbols, GhostScope cannot resolve function names, variables, or source line information.

#### Separate Debug Files (GNU debuglink)

GhostScope also supports loading debug information from separate debug files using the `.gnu_debuglink` mechanism. This is useful when working with stripped binaries in production environments.

**Check for debuglink section:**
```bash
# Check if binary has .gnu_debuglink pointing to a separate debug file
readelf -x .gnu_debuglink your_program

# Example output:
# Hex dump of section '.gnu_debuglink':
#   0x00000000 6d795f70 726f6772 616d2e64 65627567 my_program.debug
#   0x00000010 00000000 12345678                   ....4Vx
```

**Create separate debug file for a stripped binary:**
```bash
# 1. Extract debug information to a separate file
objcopy --only-keep-debug your_program your_program.debug

# 2. Strip debug information from the binary
objcopy --strip-debug your_program

# 3. Add a link from the binary to the debug file
objcopy --add-gnu-debuglink=your_program.debug your_program

# Verify the debuglink was added
readelf -x .gnu_debuglink your_program
```

**Debug file search paths (following GDB conventions):**

GhostScope automatically searches for debug files in the following locations:
1. Same directory as the binary: `/path/to/your_program.debug`
2. `.debug` subdirectory: `/path/to/.debug/your_program.debug`
3. Global debug directory: `/usr/lib/debug/path/to/your_program.debug`

**Installing system debug packages:**
```bash
# Ubuntu/Debian - install debug symbols for libc
sudo apt install libc6-dbg

# Fedora/RHEL - install debug symbols
sudo dnf debuginfo-install glibc

# The debug files are typically installed in /usr/lib/debug/
```

**Verification:**

GhostScope will automatically detect and use separate debug files. You can verify this in the logs:
```bash
# Run with debug logging to see debuglink resolution
RUST_LOG=debug sudo ghostscope -p $(pidof your_program)

# Look for messages like:
# "Looking for debug file 'your_program.debug' for binary '/path/to/your_program'"
# "Found matching debug file: /path/to/your_program.debug (CRC: 0x12345678)"
```

## Troubleshooting

### Permission Denied Errors

If you get permission errors when running GhostScope:

1. Ensure you're using sudo or have proper capabilities set
2. Check kernel configuration:
   ```bash
   zcat /proc/config.gz | grep BPF
   ```
   Ensure `CONFIG_BPF=y` and `CONFIG_BPF_SYSCALL=y` are set

3. Check if BPF is enabled:
   ```bash
   ls /sys/fs/bpf
   ```

## Next Steps

- Read the [Quick Tutorial](tutorial.md) to learn basic usage
- Configure GhostScope using the [Configuration Guide](configuration.md)
- Explore [example scripts](scripting.md) to understand tracing capabilities

## Getting Help

If you encounter issues during installation:

1. Check the [FAQ](faq.md) for common problems
2. Search [existing issues](https://github.com/swananan/ghostscope/issues)
3. File a new issue with installation logs
