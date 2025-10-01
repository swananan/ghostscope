# TUI Reference Guide

GhostScope's TUI interface consists of three panels with distinct functionality. This guide focuses on keyboard shortcuts and panel operations.

## Quick Reference

- **Global Shortcuts**: Work across all panels
- **Panel 1**: Source Code Panel - Navigate and set trace points
- **Panel 2**: eBPF Output Panel - View real-time trace output
- **Panel 3**: Command Interaction Panel - Execute commands and edit scripts

## Global Shortcuts

**Important**: These shortcuts only work when the Command Interaction Panel is focused and in **Command Mode** (not Input Mode or Script Mode).

| Shortcut | Function | Description |
|----------|----------|-------------|
| `Tab` | Switch Panel | Cycle forward: Source → eBPF → Command |
| `Shift+Tab` | Reverse Switch | Cycle backward through panels |
| `Ctrl+W` + `h/j/k/l` | Vim Navigation | Jump to left/down/up/right panel |
| `Ctrl+W` + `z` or `F1` | Toggle Fullscreen | Fullscreen current panel or restore |
| `Ctrl+W` + `v` or `F2` | Toggle Layout | Switch panel layout arrangement |
| `Ctrl+C` (twice) | Quit | Press twice to exit GhostScope |

### Ctrl+C Behavior

- **First Press**:
  - Script Mode: Cancel script editing
  - Other modes: Show "Press Ctrl+C again to exit"
- **Second Press**: Exit program

### Window Navigation Mode

Press `Ctrl+W`, then:
- `h`: Jump to left panel
- `j`: Jump to bottom panel
- `k`: Jump to top panel
- `l`: Jump to right panel
- `v`: Toggle layout
- `z`: Toggle fullscreen

---

## Panel 1: Source Code Panel

Displays source code with trace point management. Operates in three modes: **Normal**, **Text Search**, and **File Search**.

### Mode: Normal

#### Basic Navigation

| Shortcut | Function |
|----------|----------|
| `h/j/k/l` | Vim navigation (left/down/up/right) |
| `↑/↓/←/→` | Arrow key navigation |
| `Ctrl+U` | Scroll up 10 lines (half page) |
| `Ctrl+D` | Scroll down 10 lines (half page) |
| `PgUp`/`PgDn` | Full page scroll |
| `gg` | Jump to file start |
| `G` | Jump to file end |
| `[number]G` | Jump to specific line (enter number then `G`) |

#### Vim-style Word Movement

| Shortcut | Function |
|----------|----------|
| `w` | Next word beginning |
| `b` | Previous word beginning |
| `^` | Line start (first non-blank character) |
| `$` | Line end |

#### Mode Switching

| Shortcut | Function |
|----------|----------|
| `/` | Enter Text Search mode |
| `o` | Enter File Search mode |
| `Space` | Set trace point at current line → Enter Script Mode |

### Mode: Text Search

Search for text within the current file.

| Shortcut | Function |
|----------|----------|
| `[char]` | Type to build search query |
| `n` | Next search match |
| `N` | Previous search match |
| `Esc` or `Ctrl+C` | Exit to Normal mode |

### Mode: File Search

Search and switch between source files.

| Shortcut | Function |
|----------|----------|
| `[char]` | Type to filter file list |
| `Backspace` | Delete character from search query |
| `Tab` or `Ctrl+N` | Select next file in results |
| `Shift+Tab` or `Ctrl+P` | Select previous file in results |
| `Enter` | Open selected file |
| `Esc` or `Ctrl+C` | Cancel and return to Normal mode |
| `Ctrl+A` | Move cursor to beginning of search input |
| `Ctrl+E` | Move cursor to end of search input |
| `Ctrl+B` or `←` | Move cursor left |
| `Ctrl+F` or `→` | Move cursor right |
| `Ctrl+W` | Delete previous word |

---

## Panel 2: eBPF Output Panel

Displays real-time trace events. Operates in two display modes: **Auto-Refresh** (default) and **Scroll** (manual navigation).

### Basic Navigation

| Shortcut | Function |
|----------|----------|
| `j` or `↓` | Scroll down (enters Scroll mode) |
| `k` or `↑` | Scroll up (enters Scroll mode) |
| `h` or `←` | Scroll left |
| `l` or `→` | Scroll right |
| `Ctrl+D` | Half page down |
| `Ctrl+U` | Half page up |
| `PgUp`/`PgDn` | Full page scroll |
| `g` or `gg` | Jump to oldest trace (top) |
| `G` | Jump to latest trace (bottom, returns to Auto-Refresh mode) |
| `[number]G` | Jump to specific line (enter number then `G`) |

### Display Modes

- **Auto-Refresh Mode** (default): Automatically shows latest traces, auto-scrolls
- **Scroll Mode**: Enter by pressing `j`, `k`, or other navigation keys; allows manual browsing of trace history

---

## Panel 3: Command Interaction Panel

Supports three interaction modes: **Input Mode**, **Command Mode**, and **Script Mode**.

### Mode Overview

| Mode | Purpose | Entry | Exit |
|------|---------|-------|------|
| **Input Mode** | Execute commands | `i` (from Command Mode) | `Esc` or `jk` |
| **Command Mode** | Browse command history | `Esc` or `jk` (from Input Mode) | `i` |
| **Script Mode** | Edit trace scripts | After `trace` command | `Ctrl+S` (submit) or `Ctrl+C` (cancel) |

### Mode: Input Mode

Execute commands and use command completion. See [Input Mode Commands](input-commands.md) for detailed command reference.

#### Input & Editing

| Shortcut | Function |
|----------|----------|
| `[char]` | Type characters |
| `Backspace` or `Ctrl+H` | Delete character before cursor |
| `Ctrl+W` | Delete previous word |
| `Ctrl+U` | Delete to line start |
| `Ctrl+K` | Delete to line end |
| `Enter` | Execute command |

#### Cursor Movement

| Shortcut | Function |
|----------|----------|
| `←` or `Ctrl+B` | Move cursor left |
| `→` or `Ctrl+F` | Move cursor right |
| `Ctrl+A` | Move to line start |
| `Ctrl+E` | Move to line end |

#### Command Completion & Suggestions

| Shortcut | Function |
|----------|----------|
| `Tab` | Auto-complete command or filename |
| `→` or `Ctrl+E` | Accept auto-suggestion (gray text) |

#### History Navigation

| Shortcut | Function |
|----------|----------|
| `↑` or `Ctrl+P` | Previous command |
| `↓` or `Ctrl+N` | Next command |
| `Ctrl+R` | Start history search mode |

#### History Search Sub-mode

After pressing `Ctrl+R`:

| Shortcut | Function |
|----------|----------|
| `[char]` | Type to search history |
| `Backspace` | Delete character from search query |
| `Ctrl+R` | Next matching command |
| `Enter` | Execute matched command |
| `Esc` | Use matched command as input (exit search) |
| `Ctrl+C` | Cancel and clear input |

#### Mode Switching

| Shortcut | Function |
|----------|----------|
| `Esc` or `jk` | Enter Command Mode (jk must be pressed within 100ms) |

### Mode: Command Mode

Browse and navigate command history with Vim-style navigation.

#### Navigation

| Shortcut | Function |
|----------|----------|
| `h/j/k/l` | Navigate left/down/up/right through history |
| `Ctrl+U` | Half page up |
| `Ctrl+D` | Half page down |
| `g` or `gg` | Jump to top of history |
| `G` | Jump to bottom of history |

#### Mode Switching

| Shortcut | Function |
|----------|----------|
| `i` | Return to Input Mode |

### Mode: Script Mode

Edit trace scripts after executing `trace` command.

#### Text Editing

| Shortcut | Function |
|----------|----------|
| `[char]` | Type characters |
| `Backspace` or `Ctrl+H` | Delete character before cursor |
| `Ctrl+W` | Delete previous word |
| `Ctrl+U` | Delete to line start |
| `Ctrl+K` | Delete to line end |
| `Enter` | Insert new line |
| `Tab` | Insert 4 spaces (indent) |

#### Cursor Movement

| Shortcut | Function |
|----------|----------|
| `←` or `Ctrl+B` | Move cursor left |
| `→` or `Ctrl+F` | Move cursor right |
| `↑` or `Ctrl+P` | Move to previous line |
| `↓` or `Ctrl+N` | Move to next line |
| `Ctrl+A` | Move to line start |
| `Ctrl+E` | Move to line end |

#### Script Control

| Shortcut | Function |
|----------|----------|
| `Ctrl+S` | Submit script (compile and load) |
| `Ctrl+C` | Cancel script edit |

---

## Tips

1. **Quick Tracing**: Press `Space` in Source Panel for fastest trace point setup
2. **Vim Navigation**: Master `h/j/k/l` keys for efficient navigation
3. **Command Completion**: Use `Tab` frequently to reduce typing
4. **History Search**: Press `Ctrl+R` in Input Mode for reverse history search
5. **Fullscreen Focus**: Use `Ctrl+W` `z` when you need to concentrate on one panel

## Related Documentation

- [Input Mode Commands](input-commands.md) - Detailed command reference for Input Mode
- [Script Language](scripting.md) - Trace script syntax and examples
- [Configuration](configuration.md) - Customize TUI behavior
- [Quick Tutorial](tutorial.md) - Step-by-step getting started guide
