# 容器环境

本文专门说明 GhostScope 在容器环境下的使用语义、主要场景和当前限制。


## 话题一：PID namespace 与 `-p` 模式
PID namespace 问题是容器环境里最核心、也最容易让人困惑的一部分，因此本节会重点展开这一点。

本文默认讨论的是本地 CLI 场景：你在哪里实际执行 `ghostscope -p`，GhostScope 就在哪里运行。GhostScope 自身运行在容器里的部署边界，会在后面的“话题四”里集中说明。

### 一条最重要的使用规则

使用 `ghostscope -p <PID>` 时，规则很简单：

你是在哪个环境里执行这条命令，就填写那个环境里 `ps` / `top` / `pgrep` 看到的 PID。

换句话说：

- 如果你在宿主机里执行 `ghostscope -p`，就输入宿主机里看到的 PID。
- 如果你在容器里执行 `ghostscope -p`，就输入该容器里看到的 PID。

用户不需要手工区分 “host PID” 和 “container PID”，也不需要自己换算。GhostScope 的职责是根据当前环境把用户输入转换成内部需要的 PID 语义。

### 为什么容器场景会变复杂

PID namespace 会让同一个进程同时拥有多套 PID。

典型例子：

- 宿主机里看到某个进程是 `81234`
- 容器内看到同一个进程是 `17`

这两个 PID 都是对的，只是观察视角不同。

GhostScope 同时依赖两类信息源：

- userspace `/proc/<pid>/...`
- 内核事件与 eBPF 过滤

这两类信息源不一定处在同一个 PID 视角里，所以容器场景下需要额外处理 PID 映射。

### 文中几个 PID 概念

为了描述方便，本文使用下面几个名字：

- `input_pid`
  用户执行 `ghostscope -p` 时输入的 PID，也就是该命令所在环境里当前可见的 PID。
- `proc_pid`
  GhostScope 当前 userspace `/proc` 视角里可见、可读取 `/proc/<pid>/maps` 的 PID。
- `host_pid`
  同一个目标进程在 host / 初始 PID namespace 里的 PID；传统 `bpf_get_current_pid_tgid()` 给出的也是这套 PID 视角。
- `container_pid`
  同一个目标进程在最内层 / 目标 PID namespace 视角下的 PID；当前实现里通常对应 `NSpid` 链条的最后一个值。对纯宿主机或 `--pid=host` 这类共享 PID namespace 的场景，它经常会和 `host_pid` 数值相同，因此不一定总是一个额外独立的 PID。
- `pid_filter`
  这个概念只在 `-p` 模式下成立。用户输入 `ghostscope -p <PID>` 之后，GhostScope 会先解析内部需要的几种 PID 视角，再在 eBPF 侧安装一层过滤条件，把运行时事件稳定地关联回这个原始 `input_pid`。它的目的，是即使在容器这类 PID namespace 场景下，userspace 里看到的 PID 和内核侧实际使用的 PID 语义不完全一样，GhostScope 仍然能过滤出用户真正想关注的那个进程。简单场景下，它更接近 host 视角 TGID 过滤；namespace-aware 场景下，则更接近“指定 PID namespace 里的 target PID”这组条件。
- `event_pid`
  运行时内核事件里携带的 PID。GhostScope 有一条进程生命周期监控链路，会监听进程的 exec / fork / exit 事件；这条链路首先拿到的就是这类 PID。当前实现里，`event_pid` 是通过 `bpf_get_current_pid_tgid() >> 32` 填出来的，因此对应的是 host / 初始 PID namespace 视角下的 TGID；当事件来自某个目标进程时，它通常会与该进程的 `host_pid` 对齐，而不能直接替代 `proc_pid` 去访问当前 `/proc` 或清理以 `proc_pid` 为 key 的缓存。

从产品语义上，用户只需要关心 `input_pid`。其余 PID 是 GhostScope 内部为了做 `/proc` 访问、eBPF 过滤和退出清理而维护的不同视角。

### 当前实现里的一个重要事实

当前代码里的 “container / host / unknown” 运行环境检测，判断的是 **GhostScope 自己** 的运行环境，而不是“目标进程是不是跑在容器里”。

这意味着：

- 产品文档需要从用户视角描述“你在哪个环境里执行 `ghostscope -p`，就输入哪个视角里看到的 PID”。
- 实现分析则还要额外关心 GhostScope 自己当前处在哪个 PID namespace，因为这会直接影响 `/proc` 可见性、helper 策略和 fallback 是否安全。

所以本文会同时区分：

- 用户视角下的场景语义
- 当前实现里 GhostScope 所在运行环境带来的技术差异

### 场景矩阵

下面按 “GhostScope 运行在哪里” 和 “被追踪进程运行在哪里” 两个维度来列出主要场景。

#### 场景 1：GhostScope 在宿主机，被追踪进程也在宿主机

这是最简单的情况。

- 用户输入宿主机可见 PID。
- `input_pid`、`proc_pid`、`host_pid` 通常相同。
- 不涉及额外的 PID namespace 映射。

#### 场景 2：GhostScope 在宿主机，被追踪进程在 `--pid=host` 容器里

这个场景和场景 1 非常接近，因为容器与宿主机共用同一套 PID namespace。

- 用户仍然输入宿主机可见 PID。
- 容器内看到的 PID 与宿主机一致。
- 通常 `input_pid`、`proc_pid`、`host_pid` 仍然相同。
- 即使 `bpf_get_ns_current_pid_tgid` 不可用，只要目标仍处在初始 PID namespace，GhostScope 也可以继续使用 host 视角 PID 过滤。

这个场景的关键点是：虽然“进程跑在容器里”，但从 PID 语义上看，它仍然处在 host PID namespace。

#### 场景 3：GhostScope 在宿主机，被追踪进程在 private PID namespace 容器里

这是当前容器 PID 问题最核心的场景。

- 用户在宿主机运行 GhostScope，因此输入的是宿主机可见 PID。
- 容器内会有另一套 namespace-local PID。
- 同一个目标进程会同时存在 `host_pid` 和容器内 PID。

这时常见现象是：

- GhostScope 的 `/proc` 读取更接近宿主机视角。
- 内核事件也通常以 host / 初始 PID namespace 的 PID 来表达。
- 如果脚本里用到 `$pid/$tid`，或者 helper 不可用时需要 fallback，容器内 PID 与宿主 PID 的差异就会暴露出来。
- 此时脚本里的 `$input_pid` 仍然是 host 侧输入值，`$host_pid` 也是 host 视角 PID，而 `$pid/$tid` 更接近目标 PID namespace 视角。

当前实现优先支持并重点处理的就是这一类场景。

#### 场景 4：GhostScope 在 `--pid=host` 容器里，被追踪进程在宿主机或其他 host PID namespace 进程中

从 PID 语义上看，这与场景 1/2 很像。

这一场景列在这里主要是为了说明：GhostScope 即使身处容器，也不一定意味着 PID 语义已经变化。

- GhostScope 运行在容器里，但它看到的是 host PID 视角。
- 用户在该容器 shell 中输入的 PID，通常就是 host PID。
- `/proc` 视角与 host 更接近。

这类场景主要影响的是“GhostScope 自己看起来是不是运行在容器里”，而不是 PID 本身是否发生转换。

#### 场景 5：GhostScope 在 private PID namespace 容器里，被追踪进程也在同一个 PID namespace 里

这时用户在容器里运行 GhostScope，因此输入的是容器内可见 PID。

这一场景之所以单独列出，是因为它最能说明“GhostScope 和目标进程共享同一个 private PID namespace”时，PID 语义会发生哪些变化。

- `input_pid` 通常等于当前容器视角的 `proc_pid`。
- `host_pid` 可能与之不同。
- 如果需要和内核事件或 host 视角对齐，就必须显式做 PID 映射。

从用户角度看，这个场景依然应该“按当前执行命令的环境里看到的 PID 输入”，但 GhostScope 内部的实现复杂度会比宿主机场景高很多。

#### 场景 6：GhostScope 在 private PID namespace 容器里，被追踪进程位于当前容器可见的更内层 / 子层 private PID namespace

这就是“当前容器启动 GhostScope，去观察子容器里的目标进程”这个场景，它处在场景 5 和场景 7 之间。

它和场景 5 的关键区别是：GhostScope 与目标进程并不共享同一个 PID namespace，但因为目标位于当前容器可见的 descendant / nested PID namespace 中，所以目标仍然能在当前 `/proc` 视角下被看到。

- 用户仍然是在外层容器里运行 GhostScope，因此 `input_pid` 是外层容器当前看到的 PID。
- `proc_pid` 通常仍然等于这个外层容器 `/proc` 视角里的 PID。
- 目标进程在子容器里通常还会有一套更内层 PID，因此 `container_pid` 可能同时不同于 `input_pid` 和 `proc_pid`。
- 如果这里要做 namespace-aware PID 过滤，那么比较对象就不能再直接拿“当前 `/proc` 视角里的 PID”，而是要拿目标在其最内层命名空间里的 PID。

这个场景现在已经成为一个单独验证过的 `-p` 路径：GhostScope 仍然接受外层容器 `/proc` 视角里可见的 PID，但 namespace-aware 过滤需要拿目标最内层的 `container_pid` 来比较。如果 helper 路径不可用、且 `NSpid` 也不能给出可信的 host 映射，GhostScope 仍然应该 fail fast，而不是猜测。

#### 场景 7：GhostScope 在一个 private PID namespace 容器里，被追踪进程不在这个 PID namespace 里

这是最容易产生歧义和失败的场景之一。

当前实现里，这一场景不属于支持路径。

这一场景更多是为了说明为什么 GhostScope 不能跨 namespace 盲目猜测 PID 映射。

可能出现的问题包括：

- 目标 PID 在当前 `/proc` 视角根本不可见。
- GhostScope 可以收到某些内核视角事件，但无法稳定反查到当前 namespace 的 `/proc` 路径。
- helper 不可用时，fallback 可能不可靠。

对于这类场景，GhostScope 当前应该明确报错或 fail fast，而不是猜测映射关系。

### 场景对照表

上面的段落是在讲语义，下面这张表则把同一批场景压成 `-p` 模式下的速查表。

这里的“场景”固定指两边的关系：

- GhostScope 自己运行在什么环境里
- 被观测进程运行在什么环境里

| 场景 | `input_pid` | `proc_pid` | `host_pid` | `container_pid` | `pid_filter` | `event_pid` | 支持情况 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1. 宿主机 -> 宿主机 | 在宿主机输入、宿主机里可见的 PID | 通常等于 `input_pid` | 通常等于 `input_pid`，也等于 `proc_pid` | 通常等于 `host_pid`，因为没有额外的 PID namespace 分层 | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`，通常等于 `host_pid` | 支持 |
| 2. 宿主机 -> `--pid=host` 容器 | 在宿主机输入、宿主机里可见的 PID | 通常等于 `input_pid` | 通常等于 `input_pid`，也等于 `proc_pid` | 通常等于 `host_pid`，因为容器与宿主机共享同一套 PID namespace | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`，通常等于 `host_pid` | 支持 |
| 3. 宿主机 -> private PID namespace 容器 | 在宿主机输入、宿主机里可见的 PID | 在宿主机 `/proc` 视角下，通常等于 `input_pid` | 通常等于 `input_pid`，也等于 `proc_pid` | 目标在更内层 PID namespace 里的 PID，可能和 `host_pid` 不同 | `bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`，通常等于 `host_pid` | 支持 |
| 4. `--pid=host` 容器 -> 宿主机 / 共享 PID 目标 | 在该容器 shell 中输入、但本质上已经是 host 可见的 PID | 通常等于 `input_pid` | 通常等于 `input_pid`，也等于 `proc_pid` | 通常等于 `host_pid` | helper 可用：`bpf_get_ns_current_pid_tgid(...).tgid == proc_pid`；helper 不可用：`bpf_get_current_pid_tgid() >> 32 == host_pid` | `bpf_get_current_pid_tgid() >> 32`，通常等于 `host_pid` | 支持 |
| 5. private PID namespace 容器 -> 同一个 private PID namespace | 在该容器内输入、容器里可见的 PID | 在当前容器 `/proc` 视角下，通常等于 `input_pid` | 通常不同于 `input_pid` 和 `proc_pid`；对应 `NSpid` 第一项 | 当 GhostScope 与目标共享同一个 PID namespace 时，通常等于 `input_pid`，也等于 `proc_pid` | helper 可用：`bpf_get_ns_current_pid_tgid(...).tgid == proc_pid`；helper 不可用：只有在 `NSpid` 给出明确 host 映射时才回退到 `bpf_get_current_pid_tgid() >> 32 == host_pid`，否则直接 fail fast | `bpf_get_current_pid_tgid() >> 32`，通常更接近 `host_pid`，而不是 `input_pid` | 条件支持 |
| 6. private PID namespace 容器 -> 当前容器可见的更内层 / 子层 private PID namespace | 在当前容器 shell 中输入、且是当前容器 `/proc` 视角可见的 PID，不是子容器里看到的局部 PID | 在当前容器 `/proc` 视角下，通常等于 `input_pid` | 通常不同于 `input_pid` 和 `proc_pid`；对应 `NSpid` 第一项 | 通常不同于 `input_pid` 和 `proc_pid`；对应 `NSpid` 链条尾部，往往就是子容器内看到的 PID | helper 可用：`bpf_get_ns_current_pid_tgid(...).tgid == container_pid`；helper 不可用：只有在 `NSpid` 给出明确 host 映射时才回退到 `bpf_get_current_pid_tgid() >> 32 == host_pid`，否则直接 fail fast | `bpf_get_current_pid_tgid() >> 32`，通常仍对齐 `host_pid` | 条件支持 |
| 7. private PID namespace 容器 -> 目标不在这个 PID namespace 里 | 往往根本无法满足，因为目标在当前 `/proc` 视角下不可见 | 当前 `/proc` 往往拿不到 | 从当前视角通常也无法稳定解析；即使存在，也属于当前 `/proc` 视角之外的 PID | 当前 namespace 下不可靠，甚至不可见 | 不会安装稳定的比较条件；GhostScope 应直接 fail fast | 不能假定存在稳定的 `event_pid` -> `proc_pid` 对应关系 | 不支持 |

说明：

- `pid_filter` 只存在于 `-p` 模式里，它的职责是在 eBPF 侧把运行时事件稳定地关联回原始 `ghostscope -p <PID>` 输入。
- 这里的 `container_pid` 指的是“GhostScope 当前能解析到的 `NSpid` 链条尾部值”。在宿主机或共享 PID namespace 场景里，它经常不会形成一个额外独立的 PID。
- 当表里写 `bpf_get_current_pid_tgid() >> 32 == host_pid` 时，表示 GhostScope 正在把“当前命中事件的 host 视角 TGID”和解析出来的目标 `host_pid` 做比较。
- 当表里写 `bpf_get_ns_current_pid_tgid(...).tgid == proc_pid` 时，表示 GhostScope 正在把“当前命中事件在目标 PID namespace 下的 TGID”和解析出来的目标 `proc_pid` 做比较。
- `event_pid` 始终来自 `bpf_get_current_pid_tgid() >> 32`，因此它始终对齐 host 视角 TGID，即使 `pid_filter` 这一列使用了 namespace-aware 过滤。
- 表里写“通常”或“可能不同”的地方，仍然要以运行时实际拿到的 `/proc`、`NSpid` 和 helper 能力为准。

### 目前 `-p` 模式的判断顺序

上面的场景矩阵主要是为了帮助理解语义。当前实现并不是先判断“现在属于场景 1 还是场景 3”，而是根据一组信号逐步推导：

#### 1. 先校验用户输入的 PID 是否符合这条契约

依赖：

- 当前环境里的 `/proc/<input_pid>`

前提：

- `input_pid` 的语义已经约定为“当前执行 `ghostscope -p` 的环境里可见的 PID”。

判断结果：

- 如果当前 `/proc` 中根本没有这个 PID，GhostScope 会直接报错。
- 这说明当前输入不符合 `-p` 的使用契约，而不是 GhostScope 去尝试跨 namespace 猜测另一个 PID。

这一步先把明显不成立的情况排除掉，也把场景 7 这类“目标根本不在当前 `/proc` 视角里”的情况尽早挡住。

#### 2. 判断 GhostScope 自己当前像不像运行在容器里

依赖：

- `/.dockerenv`
- `/run/.containerenv`
- `/proc/1/cgroup`

判断结果：

- 得到 `container-likely` / `host-likely` / `unknown`

这一判断针对的是 **GhostScope 自己**，不是目标进程。它主要影响后续的保守策略，例如 helper 不可用时是否应该更早 fail fast。

这里的 `container-likely` 更适合理解成一个风险信号：

- 它表示 GhostScope 当前环境可能存在 PID namespace 视角差异，因此后续 PID 推断要更谨慎。
- 它不能单独说明目标进程是不是在容器里，也不能单独判断 `input_pid` 是否已经是 `host_pid`。

即使 GhostScope 运行在 host，上述关系也不是机械地恒等成立：

- GhostScope 在 host PID 视角里运行时，用户输入的 `input_pid` 通常就是 host 这边 `/proc` 里看到的 PID。
- 但目标进程仍然可能运行在 private PID namespace 容器里，因此同一个目标仍可能同时拥有另一套容器内 namespace-local PID。

#### 3. 读取目标 PID 的 `NSpid` 和 PID namespace 信息

依赖：

- `/proc/<input_pid>/status` 里的 `NSpid`
- `/proc/<input_pid>/ns/pid`

这些信息分别表示：

- `NSpid`
  同一个进程在多层 PID namespace 里的 PID 链条。对 GhostScope 当前关心的场景来说，可以先近似理解成“同一个进程在 host 视角和容器视角里分别是多少 PID”。
- `/proc/<pid>/ns/pid`
  这个进程当前所在的 PID namespace 对象本身。GhostScope 读取它的 `dev` 和 `inode`，不是为了拿一个新的 PID，而是为了唯一标识“这到底是哪一个 PID namespace”。

例如：

- 如果 `/proc/<pid>/status` 里看到 `NSpid: 81234 17`
- 那么可以近似理解成：
  - 这个进程在 host / 初始 PID namespace 里是 `81234`
  - 在更内层的 PID namespace 里是 `17`

这里要注意两点：

- `NSpid` 提供的是“同一个进程在不同 PID 视角里的编号关系”
- `/proc/<pid>/ns/pid` 提供的是“这个进程当前属于哪个 PID namespace”

判断结果：

- `proc_pid`
  当前 `/proc` 视角里用于读 `/proc/<pid>/maps` 的 PID，当前实现里通常就是 `input_pid`
- `host_pid`
  `NSpid` 第一项，对应 host / 初始 PID namespace 的 PID
- 目标 PID namespace 的 inode / dev
- `NSpid` 链条是否提供了明确映射

这些结果分别用于不同用途：

- `proc_pid`
  用于 userspace 侧访问 `/proc/<pid>/maps`、`/proc/<pid>/status` 等文件
- `host_pid`
  用于和传统 `bpf_get_current_pid_tgid()` 返回的那套 PID 视角对齐
- PID namespace 的 `dev/inode`
  用于传给 `bpf_get_ns_current_pid_tgid()`，告诉 eBPF“请按这个 PID namespace 的视角返回当前任务的 pid/tgid”
- `NSpid` 是否明确
  用于判断 helper 不可用时，回退到 host 视角过滤是不是仍然可靠

其中最关键的不是“又读到了一个 PID”，而是 GhostScope 借这一步回答了两个问题：

- 当前 `/proc` 里看到的这个 PID，和 host / 初始 PID namespace 里的 PID 是不是同一个值
- 如果不是同一个值，eBPF 应该按哪个 PID namespace 视角去解释当前命中的任务

这一步是区分场景的关键：

- 如果目标处在初始 PID namespace，通常更接近场景 1、2、4。
- 如果目标不在初始 PID namespace，但当前 `/proc` 仍然可见它，就更接近场景 3 或 5。
- 如果 `NSpid` 没有给出足够信息，后面 fallback 是否安全就会变得敏感。

#### 4. 探测内核是否支持 namespace-aware helper

依赖：

- 内核是否支持 `bpf_get_ns_current_pid_tgid`

判断结果：

- 如果 helper 可用，可以按指定 PID namespace 获取 PID/TGID，过滤更稳妥。
- 如果 helper 不可用，就必须更依赖 `NSpid`、当前 `/proc` 可见性和已有 namespace 信息。
- 传统 helper `bpf_get_current_pid_tgid()` 返回的是内核默认 PID 视角下的 `pid/tgid`；在容器语义里，可以近似理解成 host / 初始 PID namespace 视角下的值，而不是容器内看到的 namespace-local PID。

这一步决定了 GhostScope 是不是能直接做 namespace-aware PID 过滤。

#### 5. 根据前面几步的结果选择 PID 过滤策略

依赖：

- GhostScope 自身运行环境判断
- `NSpid` 是否给出明确 host 映射
- 目标 PID namespace 信息
- helper 是否可用

判断结果：

- 当前实现里，GhostScope 实际上是在两种 filter 形式之间做选择：host 视角 TGID 过滤，或者 namespace-aware TGID 过滤。
- 如果 helper 可用，并且 GhostScope 判断这次 `-p` 运行确实需要 namespace-aware 过滤，才会使用 namespace-aware 那一支。
- 如果当前场景并不被判断为“需要 namespace-aware 过滤”，即使 helper 可用，GhostScope 也可能继续使用 host 视角 PID 过滤。
- helper 不可用时，才考虑回退到 host PID 过滤。
- 如果目标仍处在初始 PID namespace，例如 `--pid=host` 场景，helper 不可用时仍然可以安全回退到 host PID 过滤。
- 只有当前环境偏容器、helper 又不可用、`NSpid` 也不给出明确映射、且目标不在初始 PID namespace 时，当前实现才会直接 fail fast，而不是猜测。

这一层正是场景 2 和场景 3 容易分叉的地方：

- `--pid=host` 容器虽然“看起来在容器里”，但目标进程仍可能处在初始 PID namespace。
- private PID namespace 容器则通常需要更明确的 namespace 信息或 helper 支持。

#### 6. 运行时还要把内核事件 PID 和 `/proc` PID 对齐

依赖：

- 内核事件里的 `event_pid`
- 当前 userspace `/proc` 视角里的 `proc_pid`

判断结果：

- 插入 offsets、缓存 PID、退出清理时，必须围绕同一组 PID key 做对齐。
- 如果写入时用了 `proc_pid`，退出时就必须还能找回同一个 `proc_pid`；否则会留下 stale cache 或 stale offset entries。

这一步不决定“属于哪个场景”，但它决定了前面判断出来的 PID 语义能不能在运行时一直保持一致。

### 常见误区

#### 误区 1：用户应该永远输入 host PID

不对。

正确规则是：

- 用户输入自己执行 `ghostscope -p` 时所在环境里可见的 PID。

不要手工把它换算成宿主机 PID，也不要反向换算成某个容器内 PID。

#### 误区 2：只要“运行在容器里”，PID 就一定和宿主机不同

不对。

如果容器使用 `--pid=host`，容器与宿主机本来就是同一套 PID namespace。

#### 误区 3：只要知道目标进程在容器里，就一定能自动推断正确映射

不对。

真正决定映射是否可靠的，是：

- GhostScope 当前的 PID namespace 视角
- 目标进程是否在当前 `/proc` 中可见
- helper 是否可用
- `NSpid` 是否提供了足够明确的映射信息

## 话题二：`-t` 模式与 sysmon

### `sysmon` 是什么

`sysmon` 是 GhostScope 在运行时维护进程生命周期信息的一条监控链路。

它主要监听：

- `exec`
- `fork`
- `exit`

当前实现里，`-p` 模式不启动这条链路；`sysmon` 主要服务于 `-t` 模式，尤其是需要在目标进程启动后持续维护模块 offsets、allowlist 和退出清理的时候。

### `sysmon` 依赖什么 PID 视角

`sysmon` 的内核事件来自 tracepoint，事件里的 `event_pid` 不是从当前 `/proc` 里读出来的，而是通过 `bpf_get_current_pid_tgid() >> 32` 填出来的。

这意味着：

- `event_pid` 对齐的是 host / 初始 PID namespace 视角下的 TGID
- 在 `-t` 语义里，它对齐的是 host / 初始 PID namespace 这套 PID 视角，而不是当前 `/proc` 视角
- 它不能直接替代 `proc_pid`

但 `sysmon` 的 userspace 部分又必须依赖 `proc_pid` 去做这些事：

- 读取 `/proc/<pid>/maps`
- 预填充模块 offsets
- 清理以 `proc_pid` 为 key 的缓存和 pinned map 条目

所以 `-t` 模式下，`sysmon` 实际上同时依赖两套 PID 语义：

- 内核事件侧的 `event_pid`
- 当前 `/proc` 侧的 `proc_pid`

### `-t` 模式在容器里为什么会出问题

如果 GhostScope 和目标进程处在同一个 PID namespace，或者至少当前 `/proc` 能稳定把 `event_pid` 对应回同一个 `proc_pid`，那么这条链路通常还能成立。

但如果 GhostScope 和目标进程不在同一个 PID 视角里，问题就会暴露出来：

- `sysmon` 先收到的是 host 视角的 `event_pid`
- userspace 真正能访问的却是当前环境里的 `proc_pid`
- 这两者不一定相同

这会直接影响：

- `exec` / `fork` 后能否稳定找到正确的 `/proc/<pid>/maps`
- offsets 写入时和退出清理时是否还能使用同一组 PID key

因此，`-t` 模式在跨 PID namespace 场景下的核心问题不是“有没有收到事件”，而是：

- 即使事件收到了，`event_pid` 和 `proc_pid` 之间的关系也不一定能稳定恢复

一旦这个关系恢复不了，`sysmon` 的生命周期维护链路就会被打穿。

### 当前对 `-t` 的结论

当前实现下，可以把 `-t` 模式分成两类理解：

- 同一 PID namespace 或 PID 视角基本一致的场景：`sysmon` 更容易按预期工作
- 跨 PID namespace，尤其 private PID namespace 场景：`sysmon` 当前并不可靠，问题不在事件采集本身，而在 `event_pid` 和 `proc_pid` 的对齐

这也是为什么：

- `event_pid` 可以拿来和 host / 初始 PID namespace 视角对齐
- 但不能直接替代 `proc_pid`
- `-t` 模式在容器场景下，不能简单套用 `-p` 的那套 PID 语义

当前容器 e2e 还没有真正覆盖“GhostScope 在 host、目标在 private PID namespace 容器里”的 `-t` 生命周期维护问题；“外层容器 -> 更内层 / 子层 PID namespace 目标”这个拓扑目前有专门的 `-p` 验证路径，但在 nested PID aliasing 完成之前，还没有重新放回 full container-e2e CI 矩阵。

## 话题三：WSL

GhostScope 当前并不支持把 WSL 作为运行环境。

关键原因是 WSL 的 PID 语义和 GhostScope 当前假设对不上：

- `bpf_get_current_pid_tgid()` 返回的 PID/TGID，可能和 WSL distro 里 userspace 看到的 PID 不一致。
- `bpf_get_ns_current_pid_tgid()` 目前也不能作为这件事的通用修复。
- 在当前 WSL + Docker 容器拓扑验证里，还实际观察到过 GhostScope 在超时退出时卡在内核 perf 清理路径上，例如 `perf_event_detach_bpf_prog`、`perf_event_free_bpf_prog`、`__fput`。

所以这里不是普通的容器 PID 映射问题，而是当前平台限制。

相关背景可参考：

- [WSL issue #12408](https://github.com/microsoft/WSL/issues/12408)
- [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115)

## 话题四：GhostScope 自身运行在容器里时的部署边界

GhostScope 目前没有计划支持“自身运行在容器里，然后观察机器上的任意进程”这类部署方式。

最主要的原因，是可观测范围本身会受限：

- 如果 GhostScope 自己运行在容器里，它可能根本看不到运行在该容器 PID namespace 之外的进程。
- 唯一比较重要的例外，是 GhostScope 运行在 `--pid=host` 容器里，因为这种情况下它和宿主机共享同一套 PID namespace。

因此，当前文档里说的“容器支持”，更准确地应该理解成下面几类能力：

- GhostScope 运行在宿主机上，观察同一台宿主机上容器内部的被观测进程。这是当前最主要的容器场景。
- GhostScope 运行在容器里，观察本容器 PID namespace 内的进程。
- 从当前容器仍可见的更内层 / 子层 PID namespace，仍然属于预期范围，而且 `-p` 现在已经有“外层容器 -> 子容器目标”的专门验证路径；把它重新放回 full container-e2e CI 矩阵，要等 nested PID aliasing 做完。`-t` 的生命周期维护仍然是另一条限制链路。
- GhostScope 运行在 `--pid=host` 容器里，利用与宿主机共享的 PID 视角去观察宿主机可见进程。

## 当前实现限制摘要

下面这些限制此前散落在 `limitations.md` 中，现统一收口到本页：

- GhostScope 在 `-p` 模式下目前按以下顺序决策：
  运行环境检测 -> `NSpid` 解析 -> helper 探测 -> 过滤策略选择。
- 当前实现并不是“只要 helper `bpf_get_ns_current_pid_tgid`（id 120）可用，就一定切到命名空间 PID 过滤”。
- 更准确地说，在 `-p` 模式下，GhostScope 目前会结合运行环境判断、解析出的 PID 映射，以及 helper 是否可用，在 host 视角 TGID 过滤和命名空间 TGID 过滤之间做选择。
- 若 helper 不可用，则回退到 `NSpid` 推导出来的 host PID 映射，但只有在映射足够明确时才安全。
- `-p` 必须是当前 PID namespace 可见的进程号。如果当前 `/proc` 中看不到该 PID，GhostScope 会直接报错，不会跨 namespace 猜测映射。
- 当前实现里还有一层额外严格策略：在“容器倾向环境 + helper 不可用 + `NSpid` 不能给出明确 host 映射”时，GhostScope 会直接报错，不做猜测。
- 场景 6（GhostScope 在 private PID namespace 容器里、目标位于当前容器可见的更内层 / 子层 private PID namespace）现在已经作为 `-p` 的单独验证路径存在；要把它重新放回 full container-e2e CI 矩阵，需要先完成 nested PID aliasing。尤其在 namespace-aware PID 过滤下，需要显式区分“当前 `/proc` 视角 PID”和目标最内层 `container_pid`；如果这一映射不能被安全建立，GhostScope 仍会直接失败而不是猜测。
- 场景 7（GhostScope 在一个 private PID namespace 容器里、目标不在这个 PID namespace 里）当前不支持；`-p` 模式应直接失败，而不是尝试跨 namespace 猜测 PID 映射。
- 在容器 PID namespace 环境下，如果 helper 不可用，脚本里的 `$pid/$tid` 可能表现为宿主机 namespace 的值，而不是容器内看到的 PID。
- `-t` 模式依赖 `sysmon` 维护运行时进程生命周期；而 `sysmon` 的 `event_pid` 来自 `bpf_get_current_pid_tgid() >> 32`，对齐的是 host 视角 PID。跨 PID namespace 场景下，`event_pid` 与 `proc_pid` 的对齐目前并不可靠，因此 `-t` 的生命周期维护链路在这类场景下存在结构性限制。

这些限制并不改变本文前面定义的用户契约；它们描述的是 GhostScope 当前实现能可靠覆盖到哪里、在哪些边界条件下会主动拒绝继续执行。

## 当前文档中其他相关位置

- `-p` 模式的配置入口与基本规则见 [configuration.md](configuration.md)
- `$pid/$tid` 在容器 PID namespace 下的行为见 [scripting.md](scripting.md)
- 当前实现限制的摘要见 [limitations.md](limitations.md)
