# Uprobe source-line offset vs. file offset (tracking note)

## Symptoms
- Uprobe attach logs show success, but no events are received in user space.
- Loader waits on ringbuf fd, but never sees any segments; no parsing happens.
- LLVM IR for the probe function is correct (Header → Message → Instruction → EndInstruction).
- TraceContext matches the IR (e.g., 1 string for a PrintStringIndex path), yet ringbuf is empty.

## Confirmed non‑causes
- IR generation: Verified correct for both PrintStringIndex and PrintComplexVariable paths.
- Inst type header for complex variables: fixed to write `InstructionType::PrintComplexVariable`.
- Loader instrumentation: temporary traces showed the fd becomes readable only when segments exist (removed per request).

## Likely root cause
- Process and analyzed binary mismatch: even with a correct offset, attaching to the wrong on‑disk file will never trigger.
- Additionally, for source‑line probes, DWARF gives instruction addresses (PC/vaddr), but uprobes needs an ELF file offset. If a vaddr is mistakenly passed as the uprobe offset, attach may succeed but never trigger.

  Clarification:
  - DWARF line → PC (virtual address)
  - Uprobes API → file offset (within the ELF file)
  - Conversion needed: `file_off = vaddr - p_vaddr + p_offset` within the containing PT_LOAD segment.

## Why function‑name attach “looked” similar
- Our current loader path prefers `AbsoluteOffset(offset)` even when a function name is present, so both function and source‑line modes end up doing raw offset attach.
- Aya’s function‑name attach (`program.attach(name, target, …)`) internally resolves symbol + section mapping to compute the proper file offset. Using this path is more robust.

## Proposed fixes
1) Source‑line mode: compute file offset from DWARF PC before attaching
   - Find the PT_LOAD segment that contains the PC.
   - Convert `vaddr → file_off` using `file_off = pc - p_vaddr + p_offset`.
   - Attach `AbsoluteOffset(file_off)`.

2) Function‑name mode: prefer symbol attach when a name is available
   - Call `program.attach(function_name, target_binary, None, pid)`.
   - Only fall back to `AbsoluteOffset(file_off)` when symbol lookup is unavailable.

3) Optional: for source‑line, compute “symbol + relative offset” for sanity
   - Find containing function (symbol) for the PC.
   - Compute `rel_off = pc - sym.vaddr` and validate it’s within the function.
   - This helps detect obviously wrong locations before attaching.

## Validation plan
- Build fixtures (Debug, O0) and run:
  - Function‑name probe: `trace update_complex { print "hit"; }` → expect events.
  - Source‑line probe (proper conversion): `trace complex_types_program.c:25 { print "hit"; }` → expect events.
- Negative case (mismatched process/binary): verify no events as expected.
- Complex variable case: `trace update_complex { print c.flags; }` → expect `PrintComplexVariable` segments; verify parser output.

## Risks / considerations
- PIE/ET_DYN binaries: ensure conversion uses the on‑disk ELF phdrs, not runtime maps.
- Stripped binaries: symbol attach may fail; keep offset fallback.
- Inlined functions: source lines may map to inline callsites; still resolve to concrete machine PC before conversion.
- Multiple PT_LOAD segments: pick the one containing the PC.

## Current status
- Loader debug traces were removed as requested.
- Complex variable inst_type header bug fixed separately.
- This note records the address translation and binary mismatch issues for follow‑up implementation.

我已按你的要求移除了 loader 里新加的 trace 日志，保持原有行为不变。改动文件：ghostscope-loader/src/lib.rs，构建通过。
  - 关于 offset 语义
      - 你说的“uprobe 需要的是文件的符号偏移”，这和 uprobes 的接口语义一致：传入的是 ELF 文件内偏移（file offset），不是 DWARF 的虚拟
  地址 PC。
      - 我们这套代码的设计定义也是如此：ModuleAddress.address 注释就是“Address offset within the module file (not virtual address)”。
  loader 也用 aya 的 UProbeAttachLocation::AbsoluteOffset(offset) 做偏移式附着。
      - 你确认这次是“进程和二进制不匹配”，这正好解释了“attach 成功但无事件”的现象：哪怕我们的偏移和 IR 都对，只要目标进程的映像不是我
  们分析/编译的这份二进制，绝不会触发。这个问题独立于“PC vs file offset”的讨论。
  - 总结
      - loader trace 已撤；编译与 attach 流程不变。
      - 偏移语义仍按“文件偏移”处理，不需要改；你确认的“进程/二进制不匹配”就是核心原因。

  如果你后面需要，我可以把 source-line 模式也统一成“符号 + 相对偏移”的计算路径（最终还是生成 file offset 给内核），提高鲁棒性。但按你
  当前判断，这不是导致本次现象的关键。

▌ source-line 不就是对应指令的 file-offset 吗

> 不完全是。

  - DWARF 的 source-line 映射给的是“指令地址”（PC，虚拟地址域），不是磁盘上的 ELF 文件偏移。要给 uprobes 用的绝对 offset，必须把这个
  PC 用 ELF Program Header 做一次转换：
      - file_off = pc − p_vaddr + p_offset（取包含该 pc 的 PT_LOAD 段）
      - PIE/ET_DYN 还有基址问题，但按“文件偏移”算时就是走 phdr 的 vaddr→offset 映射
  - attach 接口本身只吃“文件路径 + 文件偏移”。我们用 Aya 走 AbsoluteOffset 时，入参必须是文件偏移。如果用 Aya 的“函数名 attach”，Aya
  会自己读符号表 + 段表把符号值（通常是 vaddr/ST_VALUE）换算成文件偏移，这就是我说“符号优先/相对偏移更稳”的原因：把转换交给 Aya，少
  踩坑。
  - 所以：
      - “source-line 就是对应指令的 file-offset 吗？”从 DWARF 原始语义看，答案是否定的；它给你的是 PC，需要转换后才能得到 file-
  offset。
      - 如果你的上层代码已经在生成 ModuleAddress.address 时做了“PC→文件偏移”的转换，那你看到的就是 file-offset（在这种前提下，source-
  line 的 address 才能直接给 uprobes）。否则，它只是 vaddr，看起来“刚好很小”的数（比如 0x1178）并不代表就是文件偏移。
  - 你前面已经定位“进程和二进制不匹配”是本次无事件的根因，这跟“PC vs file-offset”的理论问题是正交的；一旦二进制匹配，现有管道如果输入
  的确实是文件偏移，就能正常触发。为了鲁棒性，函数名 attach 让 Aya 帮你算 offset 是更保险的；source-line 路径也建议“先找所在符号 + 相
  对偏移”，最终还是得到 file-offset 再传给内核。

