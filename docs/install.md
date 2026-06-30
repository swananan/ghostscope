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

### Quick Install Script (Recommended)

GhostScope ships with an install helper that downloads the latest release binary, copies a default configuration to `~/.ghostscope/config.toml`, and installs everything under `~/.ghostscope/bin` (no sudo required).

```bash
curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/install.sh | bash
```

**Prerequisites**

- `curl`, `tar`, `install` (usually provided by coreutils)
- `python3` (used to pick the correct release asset)

After the script finishes, add the binary path to your shell configuration:

- Bash: `echo 'export PATH="$HOME/.ghostscope/bin:$PATH"' >> ~/.bashrc`
- Zsh: `echo 'export PATH="$HOME/.ghostscope/bin:$PATH"' >> ~/.zshrc`
- Fish: `echo 'set -Ux PATH $HOME/.ghostscope/bin $PATH' >> ~/.config/fish/config.fish`

Restart the terminal and run `ghostscope --version` to verify.

### Download from GitHub Releases

1. Download the latest release from [GitHub Releases](https://github.com/swananan/ghostscope/releases)

2. Extract the binary:
```bash
tar -xzf ghostscope-v0.1.6-x86_64-linux.tar.gz
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

**Use an explicit debug file without relying on debuglink:**
```bash
# Target mode: bind the debug file to this binary or shared library
sudo ghostscope -t /path/to/your_program --debug-file /path/to/your_program.debug

# PID mode: bind the debug file to /proc/<pid>/exe (the main executable)
sudo ghostscope -p $(pidof your_program) --debug-file /path/to/your_program.debug
```

When `--debug-file`/`-d` is used, GhostScope validates the `.gnu_debuglink`
CRC when the target has one, and compares Build-ID metadata when both the
target and debug file provide Build-IDs. CRC mismatches and Build-ID
mismatches are rejected unless `--allow-loose-debug-match` is explicitly set.
If Build-ID metadata is missing on either side, GhostScope logs a warning but
does not reject the file on that basis. The explicit debug file must contain
usable `.debug_info`.

By default, automatic `.gnu_debuglink` discovery is reported as `debuglink`
only when the separate file passes the debuglink CRC check, passes the Build-ID
check when both files provide Build-IDs, and contains usable `.debug_info`.
When `--allow-loose-debug-match` is set, CRC/Build-ID mismatches are accepted
with warnings; the file is still reported as `debuglink` if it contains usable
`.debug_info`. A file that does not contain DWARF is ignored, debuginfod
fallback is tried when enabled, and the module is otherwise reported as
`missing`.

**Debug file search paths:**

For automatic `.gnu_debuglink` discovery, GhostScope searches:
1. An absolute path from `.gnu_debuglink`, when present
2. Directories from `[dwarf].search_paths` (defaults: `/usr/lib/debug`,
   `/usr/local/lib/debug`)
3. Same directory as the binary: `/path/to/your_program.debug`
4. `.debug` subdirectory: `/path/to/.debug/your_program.debug`

> **Custom Search Paths**: The default configuration includes common system
> debug directories. If you override `[dwarf].search_paths`, include any system
> or custom directories that you still want GhostScope to search. See the
> [Configuration Reference - DWARF Debug Search Paths](configuration.md#dwarf)
> for details.

**Installing system debug packages:**
```bash
# Ubuntu/Debian - install debug symbols for libc
sudo apt install libc6-dbg

# Fedora/RHEL - install debug symbols
sudo dnf debuginfo-install glibc

# The debug files are typically installed in /usr/lib/debug/,
# which is included in the default [dwarf].search_paths.
```

**Verification:**

GhostScope will detect and use separate debug files when they are in the
searched locations. In script mode, when CLI status output is enabled on an
interactive terminal, the startup report shows the DWARF source mix and
per-module load details:
```text
DWARF ready: 11 modules, 49425 functions, 3393 variables, 152543 types, debug: embedded:2 missing:9, 3.0s | pid=2762799
Startup load report:
  target: pid=2762799
  debug sources: embedded:2 missing:9
  modules loaded: 11 completed, 0 failed
  module details:
    embedded /usr/sbin/nginx      49000 funcs   3300 vars 150000 types  1200ms  /usr/sbin/nginx
  missing DWARF: 9 modules (libc.so.6, libssl.so.3, libcrypto.so.3 +6 more; use --log --log-level debug --log-file <path> for full paths)
```

The startup report is status output, not tracing log output. It is hidden when
stderr is not a terminal or console stderr logging is active. Use logs when you
need the lower-level debuglink resolution steps:
```bash
# Run with debug logging to see debuglink resolution in script mode
sudo ghostscope -p $(pidof your_program) \
  --script-file /path/to/script.gs \
  --log --log-level debug

# RUST_LOG can set the filter too, but logging must still be enabled
sudo env RUST_LOG=debug ghostscope -p $(pidof your_program) \
  --script-file /path/to/script.gs \
  --log

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

4. Check if `bpffs` is mounted before running GhostScope:
   ```bash
   mount | grep bpf
   ```
   You should see `/sys/fs/bpf` mounted as filesystem type `bpf`.
   If `/sys/fs/bpf` exists but nothing is mounted there, GhostScope will fail when it tries to pin BPF maps.
   Some systems, including WSL2 and minimal/container environments, do not mount `bpffs` by default.
   In that case, run:
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
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
