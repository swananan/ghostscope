# Uprobe Internals

Understanding how GhostScope uses Linux uprobe and eBPF for dynamic tracing.

## What is Uprobe?

Uprobe (User-space probe) is a Linux kernel feature that allows you to dynamically instrument user-space applications at runtime without modifying the binary or requiring recompilation. It is one of the core components of the Linux kernel's dynamic tracing infrastructure.

## How Uprobe Works

### Basic Execution Flow

```
User process executing
     ↓
  Hits breakpoint instruction (int3)
     ↓
  CPU traps into kernel mode
     ↓
  Kernel uprobe handler identifies it
     ↓
  Calls registered eBPF program
     ↓
  eBPF program executes and collects data
     ↓
  Single-steps original instruction
     ↓
  Resumes user mode execution
```

### 1. Probe Insertion

When you set a uprobe at a specific address:
1. The kernel replaces the original instruction at that address with a breakpoint instruction (`int3` on x86_64, occupies 1 byte)
2. The original instruction is saved in the kernel's uprobe management structure
3. When the program execution reaches that address, it triggers a breakpoint exception

### 2. Trap Handling

When the breakpoint is triggered, the complete flow:
1. **CPU Trap**: The breakpoint instruction causes the CPU to switch from user mode to kernel mode
2. **Uprobe Recognition**: The kernel trap handler identifies this as a uprobe breakpoint
3. **Callback Execution**: Calls all registered callbacks on this uprobe (including eBPF programs)
4. **eBPF Execution**: The eBPF program runs, can read registers, stack, memory, etc.
5. **Single-step**: Uses single-step debugging mechanism to execute the replaced original instruction
6. **Resume Execution**: Returns to user mode and continues normal execution

### 3. Performance Characteristics

- **Overhead**: ~1-3 microseconds per probe hit (including context switch and eBPF execution)
- **Context switch**: One complete user mode → kernel mode → user mode transition
- **Memory footprint**: Each probe occupies a few hundred bytes of kernel memory
- **Scalability**: The kernel can efficiently handle thousands of active probes

## 📢 Deep Dive into Key Uprobe Questions

### 1. What Information Does Uprobe Need?

Uprobe essentially needs only two core pieces of information:
- **File path**: Path to the executable or dynamic library (kernel finds the inode through it)
- **File offset**: The offset of the probed instruction within the file (not a virtual memory address!)

Working mechanism:
- Uprobe implements probing by modifying instructions
- eBPF programs are just one of the callbacks registered on the uprobe framework
- The kernel handles breakpoint management, eBPF only handles data collection

### 2. Which Processes Are Affected When Uprobe Is Attached?

**Core principle**: Uprobe works based on the filesystem's **inode**, not process PID.

#### Inode to Process Impact Path

```
                   uprobe_register(inode, offset)
                            ↓
                   Traverse inode's address space
                            ↓
        ┌───────────────────┴───────────────────┐
        │    inode->i_mapping->i_mmap           │
        │  (rbtree: all VMAs mapping this file) │
        └───────────────────┬───────────────────┘
                            ↓
        ┌───────────────────────────────────────┐
        │  Traverse each VMA (vm_area_struct)   │
        └───────────────────┬───────────────────┘
                            ↓
                ┌───────────┴───────────┐
                │                       │
         VMA 1: Process A        VMA 2: Process B
         (mm->mmap)              (mm->mmap)
                │                       │
                ↓                       ↓
         Insert breakpoint       Insert breakpoint
         at vaddr                at vaddr
         (via install_breakpoint)

Key data structures:
• inode: Unique identifier of the file
• i_mapping->i_mmap: All memory mappings of this file (rbtree)
• vm_area_struct (VMA): A mapped region in process address space
• mm_struct: Process memory descriptor
```

#### Impact Scope

**All processes that map this inode will be affected**, including:
1. Main executable: All running process instances of the program
2. Dynamic libraries: All processes that loaded this library (may span different programs)
3. Shared libraries: The system may have dozens of processes sharing the same libc.so

#### ⚠️ Important Edge Cases

**Inode Inconsistency Due to File Updates**:

```
Scenario: A running program file is updated

  Old Process         Filesystem         New Process
    │                    │                 │
    ├─ Mapped inode A    │                 │
    │  /usr/bin/app      │                 │
    │  (mapped at start) │                 │
    │                    │                 │
               Program is recompiled/replaced
                         ↓
    │                    │                 │
    │              inode B created         │
    │              /usr/bin/app            │
    │              (new version)           │
    │                    │                 │
    │                    │            New process starts
    │                    │                 │
    │                    │                 ├─ Maps inode B
    │                    │                 │
    │                    │                 │
  uprobe attached to inode B               │
         ↓                                 ↓
   ❌ Old process unaffected    ✅ New process probed
   (still mapped to inode A)    (mapped to inode B)
```

**Key Conclusions**:
- Old processes use the old file's inode (preserved via `mmap` at startup)
- File updates create a new inode (or modify the existing inode, depending on editor behavior)
- Uprobe only affects processes matching the inode registered with
- To probe old processes, you need to:
  - Use `-p PID` mode (GhostScope will find the actual inode mapped by that process)
  - Or keep the old version file and set uprobe on it

**Verification method**:
```bash
# View the file inode mapped by a process
cat /proc/$PID/maps | grep "r-xp"
ls -i /usr/bin/app  # View current file inode

# If inode doesn't match, uprobe won't take effect
```

### 3. Where Can Uprobe Be Attached?

Traditional tools (like bpftrace) typically only support:
- Function entry points (based on symbol table)
- Function return points (uretprobe)
- Manually specified file offsets

**GhostScope's Advantage**: With DWARF debug information, it can attach to:

| Location Type | Example | Implementation |
|--------------|---------|---------------|
| **Function Entry** | `main` | Symbol table lookup → file offset |
| **Function Return** | `main` (uretprobe) | Kernel uretprobe mechanism |
| **Source Line** | `sample.c:42` | DWARF `.debug_line` mapping |
| **Inline Function** | `inline_func` | DWARF `.debug_info` inline instances |
| **Arbitrary Address** | `file_path:0x401234` | Direct offset usage |

**Key Conversion Flow**:
```
Source line number (sample.c:42)
         ↓
  DWARF .debug_line table
         ↓
  Virtual memory address (0x401234)
         ↓
  Subtract load base (PIE/ASLR handling)
         ↓
  File offset (0x1234)
         ↓
uprobe_register(inode, 0x1234)
```

Note
- Script/CLI address targets use module-relative virtual addresses (DWARF PCs). That is, in a script `trace libc.so.6:0xADDR { ... }` or `trace 0xADDR { ... }`, the `0xADDR` is the module's DWARF PC. GhostScope converts this virtual address to the ELF file offset internally (for both PIE and non-PIE) before attaching the uprobe. Do not confuse this with raw file offsets.

### 4. ASLR's Impact on Uprobe

#### Background

Modern Linux systems enable **ASLR (Address Space Layout Randomization)** by default. Each time a process starts:
- Executable load base is randomized
- Dynamic library load base is randomized
- Stack, heap regions are also randomized

**Key point**: Uprobe uses **file offset** rather than virtual address, so it's **not affected by ASLR**. Once you understand this, the content below becomes less critical.

#### PIE vs Non-PIE Address Conversion

The two executable types differ fundamentally in address conversion:

##### PIE (Position Independent Executable)

**Characteristics**:
- Compiled with `-fPIE -pie` flags
- Can be loaded at any memory location
- DWARF records **relative addresses** (relative to load base)

**Address conversion**:
```
DWARF address (relative address)
         ↓
     Is directly the file offset
         ↓
  uprobe_register(inode, dwarf_addr)
```

**Example**:
```c
// Compile: gcc -g -fPIE -pie main.c -o app_pie

// DWARF info:
// main function address: 0x1234

// Actual conversion:
file_offset = 0x1234  // DWARF address is file offset
```

**Runtime behavior**:
```
Process A starts → Loads at 0x55ab1234 (base 0x55ab0000)
Process B starts → Loads at 0x7f3e1234 (base 0x7f3e0000)
                       └─────┬─────┘
                      Both map file offset 0x1234
                      Uprobe sets breakpoint here
```

##### Non-PIE (Traditional Executable)

**Characteristics**:
- Compiled without PIE flags (or with `-no-pie`)
- Loaded at a fixed virtual address (typically 0x400000)
- DWARF records **absolute virtual addresses**

**Address conversion**:
```
DWARF address (absolute virtual address)
         ↓
    Subtract ELF segment virtual base
         ↓
     Get file offset
         ↓
  uprobe_register(inode, file_offset)
```

**Example**:
```c
// Compile: gcc -g -no-pie main.c -o app_nopie

// ELF Program Header:
//   LOAD: VirtAddr=0x400000, FileOffset=0x0000, MemSize=0x2000

// DWARF info:
//   main function address: 0x401234 (absolute address)

// Actual conversion:
file_offset = 0x401234 - 0x400000 = 0x1234
```

**Key formula**:
```
file_offset = dwarf_addr - segment_vaddr
```

Where `segment_vaddr` is the `VirtAddr` field of the ELF `LOAD` segment.

#### Why Is Uprobe Not Affected by ASLR?

```
       Process A (PIE)               Process B (non-PIE)
            │                          │
  ┌─────────▼─────────┐      ┌────────▼────────┐
  │ Load base: random │      │ Load base: fixed │
  │ 0x55ab0000       │      │ 0x400000        │
  └─────────┬─────────┘      └────────┬────────┘
            │                          │
            │  mmap(file, offset)      │
            │                          │
            └────────┬─────────────────┘
                     ↓
         ┌───────────────────────┐
         │  Filesystem Inode     │
         │  File offset 0x1234   │  ← Uprobe set here
         └───────────────────────┘

Key points:
• Virtual address = load base + file offset
• Uprobe only cares about file offset
• Different processes may have different virtual addresses
• But file offset is always the same
```

#### Special Case: Accessing Global Variables

While uprobe is not affected by ASLR, if you need to read **global variables** or **absolute address data**, you must consider runtime addresses. However, this is an implementation detail of GhostScope and won't be elaborated here.

## GhostScope's Two Tracing Modes

### Mode 1: PID-Specific Mode (`-p`)

```bash
sudo ghostscope -p 12345
```

#### How It Works

```
    GhostScope starts
          ↓
    Reads /proc/12345/maps
          ↓
    Gets process memory mapping info
          ↓
    ┌──────────────────────────────┐
    │ Main executable: /usr/bin/app│ → inode A
    │ Dynamic lib 1: /lib/libc.so.6│ → inode B
    │ Dynamic lib 2: /lib/libssl.so│ → inode C
    └──────────────────────────────┘
          ↓
    Performs DWARF analysis
          ↓
    Registers uprobe based on target file and instruction offset
          ↓
    eBPF program includes PID filtering logic
          ↓
    if (bpf_get_current_pid_tgid() >> 32 != 12345) {
        return 0;  // Ignore other processes
    }
```

#### Technical Details

1. **Mapping Parsing**:
   - Parses `/proc/PID/maps` to get all executable mappings (`r-xp` permission)
   - Each mapping region corresponds to a file inode
   - Sets uprobe on these inodes (will affect all processes mapping these inodes)

2. **eBPF Filtering**:
   ```c
   // eBPF program header filtering logic
   u64 pid_tgid = bpf_get_current_pid_tgid();
   u32 pid = pid_tgid >> 32;

   if (pid != target_pid) {
       return 0;  // Quick return, don't collect data
   }

   // Continue tracing logic...
   ```

3. **Why Can't We Set Uprobe for a Specific Process Only?**
   - Uprobe is **inode-based**, can't specify PID
   - Must filter at the eBPF layer
   - Other processes trigger breakpoints, but eBPF program returns quickly (very small overhead)

#### Advantages and Limitations

✅ **Advantages**:
- Output focused on target process, no noise
- Suitable for debugging specific instance issues
- eBPF filtering is very efficient (< 100ns)

❌ **Limitations**:
- Cannot capture process startup phase (GhostScope attaches when process is already running)
- If program file is replaced, old process can still be traced (because it maps the old inode)
- Dynamically loaded libraries (`dlopen`) are not currently supported for automatic tracing

#### Use Cases

- Debugging abnormal behavior of specific processes
- Performance analysis of running service instances
- Scenarios requiring reduced trace output noise

---

### Mode 2: Binary-Wide Mode (`-t`)

```bash
sudo ghostscope -t /usr/bin/myapp
```

#### How It Works

```
    GhostScope starts
          ↓
    DWARF parsing and gets target file address
          ↓
    uprobe_register(inode, offset)
          ↓
    Kernel traverses all mappings of this inode
          ↓
    ┌─────────────────────────────────────┐
    │  Process A (PID 100): /usr/bin/myapp│ ✅ Probed
    │  Process B (PID 200): /usr/bin/myapp│ ✅ Probed
    │  Process C (PID 300): /usr/bin/other│ ❌ Different inode
    └─────────────────────────────────────┘
          ↓
    All processes mapping this inode trigger eBPF program
          ↓
    eBPF program **does NOT filter by PID**
          ↓
    All events are sent to userspace
```

#### Advantages and Limitations

✅ **Advantages**:
- Can capture the complete lifecycle from process start to exit
- Automatically traces all instances, no need to know PID
- Suitable for tracing short-lived processes (e.g., CGI scripts)
- Can trace dynamic library usage across processes

❌ **Limitations**:
- Output contains all processes using the binary (can be noisy)
- For shared libraries (like libc), may affect many processes in the system
- Need to manually filter output for processes of interest

#### Use Cases

- Debugging program startup issues
- Tracing all instances of a service (e.g., nginx worker processes)
- Monitoring shared library behavior across the system
- Capturing race conditions in multi-process environments
- Analyzing frequently started short-term processes

---
