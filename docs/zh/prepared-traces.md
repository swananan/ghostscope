# 预编译 trace bundle

先以普通用户编译，再将保存的 eBPF 程序附加到运行中的进程：

```bash
ghostscope prepare -t /path/to/app --script-file trace.gs -o trace.gsb
sudo ghostscope run-bundle trace.gsb -p <PID>
```

`prepare` 不需要 BPF 权限，不探测内核 BPF 能力，不加载或附加探针，不启动
sysmon，也不写入 bpffs。所有目标必须编译成功，输出文件已存在时会报错，避免覆盖。

`run-bundle` 校验格式版本、GhostScope 版本、本机架构、目标文件 SHA-256、模块
cookie，以及该文件在指定 PID 中的可执行映射。之后检查内核能力、初始化运行时
模块偏移并附加保存的程序，复用普通 CLI 的事件输出、丢失计数和退出清理。
不会回退到 DWARF 解析或 LLVM 编译。

首版范围：

- 单个可执行文件或共享库模块，目标必须是宿主机进程。
- 运行内核需要支持进程级 multi-uprobe，包括工作线程；准备机器不需要该能力。
- 暂不支持 `bt` / `backtrace`、`$input_pid` 或容器 PID namespace。
- `$pid` / `$tid` 在探针执行时读取，使用宿主机 PID 语义。
- 默认使用 RingBuf。可在准备时通过 `--config` 选择 PerfEventArray 或 sleepable
  uprobes；运行内核必须支持保存的配置，不会自动切换后端。

准备时可用 `--debug-file` 指定独立调试文件，仍执行通常的身份校验。
准备后可以移除独立调试文件，但目标二进制必须逐字节一致；strip 等处理应在
准备之前完成。可用 `run-bundle ... -t /new/path/to/app` 指定相同目标的新路径。
没有 ELF build ID 的目标必须保留原来的文件身份，复制到其他 inode 后需要重新准备。

bundle 是有版本的 JSON 文件，上限为 64 MiB，包含脚本、编译配置、探针偏移、
eBPF 对象及解码上下文。应像可执行文件一样，仅运行可信来源的 bundle。
目标身份校验不等于来源认证。目标、脚本、编译配置、GhostScope 版本或 bundle
格式变化后，应重新准备。

运行时使用 bundle 保存的 eBPF 配置，不读取当前用户的配置文件。
可用 `--script-output pretty|plain|jsonl` 和 `--no-status` 控制输出。

准备和附加阶段会报告耗时。运行阶段仍需目标校验、ELF 映射发现、内核能力检测和
BPF 验证/加载。测试中的小型 C fixture 会比较普通启动与 bundle 启动，并验证移除
调试文件后的读取、跨 PID 复用及线程覆盖；不使用容易波动的耗时阈值。
生产环境收益应使用有代表性的目标另行测量。
