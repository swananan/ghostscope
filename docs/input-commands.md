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

**Examples:**
```
trace main                    # Trace main function
trace calculate_something     # Trace specific function
trace /home/user/src/sample.c:42    # Full path
trace src/sample.c:42         # Relative path
trace sample.c:42            # Filename only (fuzzy match)
trace sample:42              # Partial filename (fuzzy match)
t process_data               # Use short form
```

**Description:**
After executing trace command, you enter Script Mode to write trace scripts. Press `Ctrl+S` to save and execute, `Ctrl+C` to cancel.

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

### info share - List Shared Libraries

**Syntax:**
```
info share
i sh                # Short form
```

**Description:**
Display all loaded shared libraries (dynamic libraries).

### info function - Function Debug Info

**Syntax:**
```
info function <name>
i f <name>          # Short form
```

**Parameters:**
- `<name>`: Function name

**Examples:**
```
info function main       # Show debug info for main
i f calculate           # Short form
```

### info line - Source Line Debug Info

**Syntax:**
```
info line <file:line>
i l <file:line>     # Short form
```

**Parameters:**
- `<file:line>`: File name and line number

**Examples:**
```
info line main.c:42     # Debug info for line 42
i l test.c:100         # Short form
```

### info address - Address Debug Info [TODO]

**Syntax:**
```
info address <addr>
i a <addr>          # Short form
```

**Parameters:**
- `<addr>`: Memory address

**Status:** Not yet implemented

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
| `info trace` | `i t` | View trace status |
| `info source` | `i s` | View source files |
| `info share` | `i sh` | View shared libraries |
| `info function` | `i f` | View function info |
| `info line` | `i l` | View line info |
| `info address` | `i a` | View address info |
| `save traces` | `s t` | Save trace points |
| `source` | `s` | Load script (except "s t") |

---

## Command Completion

GhostScope provides intelligent command completion in Input Mode:

1. **Tab Completion**: Press `Tab` to auto-complete commands and filenames
2. **Auto-suggestion**: Gray suggestion text appears as you type, press `→` or `Ctrl+E` to accept
3. **Smart Matching**: Completion works for both full commands and shortcuts

---

## Tips & Best Practices

1. **Use Shortcuts**: Master command shortcuts (`t`, `en`, `dis`) for faster workflow
2. **Tab Completion**: Use `Tab` extensively for completion and command discovery
3. **History Navigation**: Use `Ctrl+P`/`Ctrl+N` or `↑`/`↓` to quickly reuse commands
4. **History Search**: Press `Ctrl+R` to search through command history
5. **Batch Operations**: Use `all` parameter to operate on all traces at once
6. **Save Sessions**: Regularly save your trace configuration with `save traces`
7. **Script Reuse**: Save common trace patterns in files and load with `source`

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
