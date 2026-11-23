# 预编译 trace bundle

先以普通用户编译，再将保存的 eBPF 程序附加到运行中的进程：

```bash
ghostscope prepare -t /path/to/app --script-file trace.gs -o trace.gsb
sudo ghostscope run-bundle trace.gsb -p <PID>
```

`prepare` 不需要 BPF 权限，不探测内核 BPF 能力，不加载或附加探针，不启动
sysmon，也不写入 bpffs。所有目标必须编译成功，输出文件已存在时会报错，避免覆盖。

`run-bundle` 在附加任何探针前校验格式版本、GhostScope 版本、本机架构，以及每个模块
的文件 SHA-256 和 cookie；使用 `-p` 时，还会校验主模块在指定 PID 中的可执行映射。之后检查内核
能力、初始化运行时模块偏移并附加保存的程序，复用普通 CLI 的事件输出、丢失计数和退出清理。
不会回退到 DWARF 解析或 LLVM 编译。

## 目标范围

- `run-bundle trace.gsb -p PID` 追踪一个已存在的宿主机进程，默认使用准备时的
  目标路径，也可用 `-t PATH` 指定其他位置的相同目标。
- `run-bundle trace.gsb -t /path/to/app` 不限定 PID，先向所有准备好的模块附加探针，
  再追踪使用其中任一文件的现有及后续进程，包括工作线程；目标重启后仍会继续追踪。
  启动 tracer 时不需要已有目标进程。

至少指定 `-p` 或 `-t` 中的一项。目标模式复用普通 `-t` 的生命周期跟踪和运行时
模块偏移维护，由 bundle 保存的 `enable_sysmon_for_target` 设置控制监控器，
仍不会解析 DWARF 或调用 LLVM。探针绑定到校验过的文件 inode；替换该路径下的
文件后，需要重新准备并附加。

## 多模块

显式列出额外的可执行文件或共享库；准备时不自动扫描依赖，也不需要已有进程：

```bash
ghostscope prepare -t /build/app \
  --module /build/libfoo.so --module /build/libbar.so \
  --script-file trace.gs -o trace.gsb
sudo ghostscope run-bundle trace.gsb -t /build/app
# 也可以将所有探针限定到一个进程：
sudo ghostscope run-bundle trace.gsb -p <PID>
```

函数和源码模式在所选模块中解析。不同模块中的同名函数生成独立探针，各自保留变量
上下文。使用 `trace libfoo.so:handle_request { ... }` 可只选择一个模块；
函数名含参数等字符时可写成 `trace libfoo.so:"ns::Handler::run(int)" { ... }`。
模块必须匹配已准备模块的完整路径或唯一后缀，不存在或有歧义时会报错。
裸地址默认指向 `-t` 主模块；其他模块可使用 `libfoo.so:0x1234`。
每个 bundle 最多包含 64 个模块，拒绝重复模块身份，包括具有相同 build ID 的副本。

使用 `-p` 时主模块必须已经映射，附加库可以稍后通过 `dlopen` 加载。不使用 `-p`
时各模块独立跟踪，也能覆盖只加载附加库、没有映射主模块的进程。后续加载和新进程的
运行时偏移维护需要 bundle 保存的 sysmon 设置允许相应模块跟踪。

部署路径可以逐个覆盖：

```bash
sudo ghostscope run-bundle trace.gsb -t /deploy/app \
  --module-path libfoo.so=/deploy/libfoo.so \
  --module-path libbar.so=/deploy/libbar.so
```

`--module-path MODULE=PATH` 左侧匹配保存的完整路径或唯一的路径后缀。匹配不唯一、
没有匹配或重复覆盖都会报错。`-t` 覆盖主模块路径；未覆盖的模块使用保存的路径。
所有文件均须通过身份校验，包括尚未映射的模块。

当前范围：

- 多个可执行文件或共享库模块，目标必须是宿主机进程。
- 运行内核需要支持进程级 multi-uprobe，包括工作线程；准备机器不需要该能力。
- 暂不支持 `bt` / `backtrace`、`$input_pid` 或容器 PID namespace。
- `$pid` / `$tid` 在探针执行时读取，使用宿主机 PID 语义。
- 默认使用 RingBuf。可在准备时通过 `--config` 选择 PerfEventArray 或 sleepable
  uprobes；运行内核必须支持保存的配置，不会自动切换后端。

准备时可用 `--debug-file` 指定主模块的独立调试文件，仍执行通常的身份校验；
附加模块使用通常的 debuglink、配置的搜索路径和 debuginfod 查找调试信息。
准备后可以移除独立调试文件，但每个模块的二进制必须逐字节一致；strip 等处理应在
准备之前完成。可用 `run-bundle ... -t /new/path/to/app` 指定相同目标的新路径。
没有 ELF build ID 的目标必须保留原来的文件身份，复制到其他 inode 后需要重新准备。

bundle 是有版本的 JSON 文件，上限为 64 MiB，包含脚本、编译配置、探针偏移、
eBPF 对象及解码上下文。应像可执行文件一样，仅运行可信来源的 bundle。
目标身份校验不等于来源认证。目标、脚本、编译配置、GhostScope 版本或 bundle
格式变化后，应重新准备。多模块格式版本为 2，版本 1 的 bundle（含单模块）须重新准备。

运行时使用 bundle 保存的 eBPF 配置，不读取当前用户的配置文件。
可用 `--script-output pretty|plain|jsonl` 和 `--no-status` 控制输出。

准备和附加阶段会报告耗时。运行阶段仍需目标校验、ELF 映射发现、内核能力检测和
BPF 验证/加载。测试中的小型 C fixture 会比较普通启动与 bundle 启动，并验证移除
调试文件后的读取、跨 PID 复用及线程覆盖；不使用容易波动的耗时阈值。
生产环境收益应使用有代表性的目标另行测量。
