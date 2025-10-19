# GhostScope Architecture

A deep dive into the design and implementation of GhostScope's eBPF-based runtime tracing system.

## System Overview

```
┌──────────────────────────────────────────────────────────┐
│                    Terminal UI (TUI)                     │
│         ┌──────────────────────────────────┐             │
│         │      TEA Architecture            │             │
│         │   (Model-Update-View Pattern)    │             │
│         └────────────┬─────────────────────┘             │
│                      │ Action Events                     │
└──────────────────────┼───────────────────────────────────┘
                       │
            ┌──────────▼──────────┐
            │  Event Registry     │  Channel-based Communication
            │  (mpsc channels)    │
            └──────────┬──────────┘
                       │
┌──────────────────────▼────────────────────────────────────┐
│              Runtime Coordinator                          │
│         (Tokio-based async orchestration)                 │
│                                                           │
│  ┌─────────────┐  ┌────────────┐  ┌─────────────┐         │
│  │ GhostSession│  │   DWARF    │  │    Trace    │         │
│  │  (State)    │  │  Analyzer  │  │   Manager   │         │
│  └─────────────┘  └────────────┘  └─────────────┘         │
│                                                           │
│  Event Loop: tokio::select! {                             │
│    - Wait for eBPF events (from all loaders)              │
│    - Handle runtime commands (from TUI)                   │
│    - Send status updates                                  │
│  }                                                        │
└───────────┬────────────────────────────┬──────────────────┘
            │                            │
   ┌────────▼─────────┐        ┌────────▼──────────┐
   │ Script Compiler  │        │  eBPF Loaders     │
   │  (Multi-stage)   │        │ (Per-Trace Pool)  │
   └──────────────────┘        └───────────────────┘
            │                            │
            └────────────┬───────────────┘
                         │
                  ┌──────▼──────┐
                  │   Target    │
                  │   Process   │
                  │  (uprobes)  │
                  └─────────────┘
```

## Workspace Structure

GhostScope uses Cargo workspace for modular design:

| Crate | Purpose |
|-------|---------|
| **ghostscope** | Main binary and runtime coordinator - orchestrates all components via async event loop |
| **ghostscope-compiler** | Script compilation pipeline - transforms user scripts into verified eBPF bytecode via LLVM |
| **ghostscope-dwarf** | Debug information analyzer - provides cross-module symbol resolution and type information |
| **ghostscope-loader** | eBPF program lifecycle manager - handles uprobe attachment and ring buffer management via Aya |
| **ghostscope-ui** | Terminal user interface - implements interactive TUI with TEA (The Elm Architecture) pattern |
| **ghostscope-protocol** | Communication protocol - defines message format for eBPF-userspace data exchange |
| **ghostscope-platform** | Platform abstraction - encapsulates architecture-specific code (calling conventions, ABIs) |
| **ghostscope-process** | Runtime process introspection and offsets — single source of truth for module cookies and ASLR section offsets in both `-p` and `-t` modes; provides PID/module enumeration and cached offsets for loaders/compilers |

## Core Architecture Components

### 1. Runtime Coordinator

**Role**: Async orchestrator that multiplexes eBPF events and UI commands.

**Key responsibilities**:
- Polls eBPF ring buffers for trace events (non-blocking)
- Receives commands from UI (script execution, trace enable/disable)
- Forwards events to UI for display
- Manages trace lifecycle

### 2. GhostSession

**Role**: Central state container for the entire tracing session.

**Manages**:
- DWARF analyzer (debug info for all loaded modules)
- Trace manager (pool of active traces)
- Target process information (PID, binary path)
- Configuration state

**Key feature**: Progressive loading with callbacks for UI progress updates.

### 3. DWARF Analyzer

**Role**: High-performance multi-module debug information system.

**Core Optimizations**:

1. **Parallel Module Loading**
   - Asynchronous parallel loading of all process modules (main executable + dynamic libraries)
   - Progress callbacks for real-time UI feedback during initialization
   - Efficient discovery via `/proc/PID/maps` parsing

2. **Cross-Module Symbol Resolution**
   - Unified namespace across all loaded modules
   - Function lookup spanning main binary and shared libraries
   - Source line to address mapping with inline function support
   - Type resolution across module boundaries

3. **Memory-Efficient Caching**
   - Multi-level cache for frequently accessed symbols
   - Lazy evaluation of debug information (parsed on-demand)
   - Minimizes memory footprint for large binaries with extensive debug info

4. **Address Translation**
   - Automatic ASLR/PIE address handling
   - Virtual address to file offset conversion
   - Runtime address mapping for process-specific traces

TODO: Still slow, need to research how GDB optimizes DWARF parsing performance.

### 4. Compilation Pipeline

Multi-stage pipeline with type safety at each level:

```
┌──────────────────────────────────────────────────────────┐
│ Stage 1: Script Parsing                                  │
│                                                          │
│   User Script (*.gs)                                     │
│         ↓                                                │
│   Pest Parser (PEG grammar)                              │
│         ↓                                                │
│   Abstract Syntax Tree (AST)                             │
└──────────────────────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────┐
│ Stage 2: LLVM IR Generation                              │
│                                                          │
│   AST + DWARF Info                                       │
│         ↓                                                │
│   Symbol Resolution (variables, types, locations)        │
│         ↓                                                │
│   LLVM IR (type-safe intermediate representation)        │
└──────────────────────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────┐
│ Stage 3: eBPF Backend                                    │
│                                                          │
│   LLVM IR                                                │
│         ↓                                                │
│   LLVM BPF Backend (optimizations + codegen)             │
│         ↓                                                │
│   eBPF Bytecode (verifier-friendly)                      │
└──────────────────────────────────────────────────────────┘
```

The diagram below is from [Crafting Interpreters](https://craftinginterpreters.com/), with the red path highlighting GhostScope's compilation flow. Of course, Pest and LLVM do the heavy lifting for us.

![Compile Pipeline](images/compile.png)
*Compilation pipeline diagram (red path shows GhostScope's flow)*

### 5. Trace Manager

**Role**: Manages lifecycle of multiple independent trace points.

**Architecture**:
- Each trace has its own eBPF program and ring buffer
- Traces can be independently enabled/disabled
- Resource isolation: one trace's failure doesn't affect others
- Concurrent execution: all uprobes run in parallel in kernel space

### 6. UI Architecture (TEA Pattern)

**Pattern**: The Elm Architecture (Model-Update-View)

```
┌──────────────┐
│    Model     │  AppState (immutable UI state snapshots)
└──────┬───────┘
       │
┌──────▼───────┐
│   Update     │  Event handlers (keypress → Action → State mutation)
└──────┬───────┘
       │
┌──────▼───────┐
│    View      │  Rendering (State → Terminal output)
└──────────────┘
```

**Benefits**:
- Testable: Pure functions for state updates
- Predictable: Same input always produces same output
- Debuggable: Can replay event sequences
- Maintainable: Clear data flow

**Communication**: Channels to runtime (send commands, receive trace events).

### 7. eBPF to Userspace Communication

**Core mechanism**: Ring buffer (per-CPU circular buffer in kernel memory).

#### Ring Buffer Architecture

```
┌───────────────────────────────────────────────────────┐
│              Kernel Space                             │
│                                                       │
│  ┌────────────┐                                       │
│  │  eBPF      │  Trace event occurs                   │
│  │  Program   │         ↓                             │
│  │  (uprobe)  │  Collect data (registers, memory)     │
│  └─────┬──────┘         ↓                             │
│        │         Serialize to protocol format         │
│        │                ↓                             │
│        │         bpf_ringbuf_output()                 │
│        │                ↓                             │
│        └────────►┌─────────────────────┐              │
│                  │  Ring Buffer        │              │
│                  │  (per-CPU, 256KB)   │              │
│                  │                     │              │
│                  │  [Event1][Event2]...│              │
│                  └──────────┬──────────┘              │
└─────────────────────────────┼─────────────────────────┘
                              │ Memory-mapped
                              ↓
┌─────────────────────────────┼─────────────────────────┐
│              User Space     │                         │
│                             │                         │
│  ┌──────────────────────────▼──────────┐              │
│  │  Trace Manager                       │             │
│  │  (polls ring buffer)                 │             │
│  └──────────────────────┬───────────────┘             │
│                         │                             │
│              Read events (non-blocking)               │
│                         ↓                             │
│  ┌──────────────────────────────────────┐             │
│  │  Streaming Parser                    │             │
│  │  (handles variable-length messages)  │             │
│  └──────────────────────┬───────────────┘             │
│                         │                             │
│              Parsed trace events                      │
│                         ↓                             │
│  ┌──────────────────────────────────────┐             │
│  │  Runtime Coordinator                 │             │
│  │  (forwards to UI)                    │             │
│  └──────────────────────────────────────┘             │
└───────────────────────────────────────────────────────┘
```

#### Communication Flow

1. **Event Generation** (Kernel):
   - Uprobe fires when target instruction executes
   - eBPF program collects data (registers, stack, memory via DWARF locations)
   - Serializes data according to protocol format
   - Calls `bpf_ringbuf_output()` to write to ring buffer

2. **Event Polling** (User Space):
   - Trace manager polls ring buffer (via Aya framework)
   - Non-blocking: Returns immediately if no events
   - Memory-mapped: Zero-copy access to kernel buffer

3. **Event Parsing**:
   - Streaming parser handles variable-length messages
   - State machine tracks partial reads across chunks
   - Reconstructs complete events

4. **Event Delivery**:
   - Parsed events sent to runtime coordinator
   - Coordinator forwards to UI via channel
   - UI updates display in real-time

#### Protocol Format

GhostScope uses an **instruction-based protocol** for flexible trace event representation:

```
┌─────────────────────────────────────────────────────┐
│ TraceEventHeader (4 bytes)                          │
│   - magic: u32 (0x43484C53 "CHLS")                  │
├─────────────────────────────────────────────────────┤
│ TraceEventMessage (24 bytes)                        │
│   - trace_id: u64                                   │
│   - timestamp: u64                                  │
│   - pid: u32                                        │
│   - tid: u32                                        │
├─────────────────────────────────────────────────────┤
│ Instruction Sequence (variable length)              │
│                                                     │
│   ┌──────────────────────────────────────┐          │
│   │ InstructionHeader (4 bytes)          │          │
│   │   - inst_type: u8                    │          │
│   │   - data_length: u16                 │          │
│   │   - reserved: u8                     │          │
│   ├──────────────────────────────────────┤          │
│   │ InstructionData (variable length)    │          │
│   │   - Depends on instruction type      │          │
│   └──────────────────────────────────────┘          │
│                                                     │
│   ... (more instructions) ...                       │
│                                                     │
│   ┌──────────────────────────────────────┐          │
│   │ EndInstruction (final marker)        │          │
│   │   - total_instructions: u16          │          │
│   │   - execution_status: u8             │          │
│   └──────────────────────────────────────┘          │
└─────────────────────────────────────────────────────┘
```

**Instruction Types**:

| Type | Code | Purpose |
|------|------|---------|
| **PrintStringIndex** | 0x01 | Print static string (indexed) |
| **PrintVariableIndex** | 0x02 | Print simple variable with type info |
| **PrintComplexVariable** | 0x03 | Print struct/array with access path |
| **PrintComplexFormat** | 0x05 | Formatted print with complex variables |
| **Backtrace** | 0x10 | Stack backtrace with frame addresses |
| **EndInstruction** | 0xFF | Marks end of instruction sequence |

**Variable Status Tracking**:

Each variable instruction includes a `status` field (u8) indicating data acquisition result:

| Status | Value | Meaning |
|--------|-------|---------|
| **Ok** | 0 | Variable read successfully |
| **NullDeref** | 1 | Attempted to dereference null pointer |
| **ReadError** | 2 | Memory read failed (invalid address) |
| **AccessError** | 3 | Memory access denied (permissions) |
| **Truncated** | 4 | Data truncated (exceeded size limit) |

This per-variable error reporting allows:
- **Partial success**: Print successfully read variables even if some fail
- **Precise diagnostics**: Identify exact failure point in complex expressions
- **Safe operation**: eBPF program continues execution despite individual read failures
