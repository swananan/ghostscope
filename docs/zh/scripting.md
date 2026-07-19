# GhostScope 脚本语言参考

GhostScope 使用专门的领域特定语言来定义追踪点和操作。脚本可以在 TUI 中使用 `trace` 命令时编写，或从脚本文件加载。

## 目录
1. [基础语法](#基础语法)
2. [追踪语句](#追踪语句)
3. [源语言支持现状](#源语言支持现状)
4. [变量](#变量)
5. [打印语句](#打印语句)
6. [条件语句](#条件语句)
7. [表达式](#表达式)
8. [内置函数](#内置函数)
9. [特殊变量](#特殊变量)
10. [栈回溯语句](#栈回溯语句)
11. [示例](#示例)
12. [限制](#限制)
13. [运行时表达式失败（ExprError）](#运行时表达式失败exprerror)

## 基础语法

### 注释

```ghostscope
// 单行注释

/*
   多行
   注释
*/
```

### 语句类型

GhostScope 支持以下语句类型：
- `trace` - 定义追踪点及其操作
- `print` - 输出格式化文本
- `backtrace` / `bt` - 输出基于 DWARF unwind 的栈回溯
- `if`/`else` - 条件执行
- `let` - 变量声明
- 表达式语句

## 追踪语句

`trace` 语句是定义追踪点的顶层结构。它只在脚本文件中使用，不在追踪块内部使用。

在真正 attach uprobe 之前，可以先验证脚本并查看解析结果：

```bash
ghostscope -p 1234 --script-file trace.gs --dry-run
ghostscope -p 1234 --script-file trace.gs --dry-run --dry-run-details
```

`--dry-run` 会解析 DWARF、编译脚本、解析 PC 和 uprobe 文件偏移，然后直接退出，不 attach。它仍会执行与真实运行相同的启动权限和内核能力检查；如果当前系统要求，请使用 `sudo` 或等价 eBPF 权限。`--dry-run-details` 会追加源码位置、inline 分类、脚本用到的变量、当前 PC 可见变量，以及 optimized-out/不可用变量诊断。

### 语法

```ghostscope
trace <模式> {
    // 命中追踪点时执行的语句
}
```

### 追踪模式

#### 函数名
```ghostscope
trace main {
    print "Main 函数被调用";
}

trace calculate_something {
    print "正在计算...";
}
```

#### 源代码行
```ghostscope
// 追踪特定文件和行号
trace sample.c:42 {
    print "到达第 42 行";
}

// 支持各种路径格式
trace /home/user/project/src/utils.c:100 {
    print "工具函数";
}
```

#### 地址
```ghostscope
// 按模块相对虚拟地址（DWARF/符号表 PC）追踪
trace 0x401234 {
    print "命中地址";
}

// 指定模块 + 地址（支持全路径或唯一后缀匹配）
trace libc.so.6:0x1234 {
    print "命中 libc 地址";
}
```

说明：
- 当 `-t` 和 `-p` 同时出现时，所有 trace pattern（函数、源码行、裸地址、模块限定地址）都在 `-t` 目标内解析。`-p` 只把运行时事件限制到该进程。
- `0xADDR` 的默认模块取决于启动模式：`-t <binary>` 使用 `<binary>`；`-p <pid>` 使用主可执行文件。如果 `-t` 和 `-p` 同时出现，目标解析以 `-t` 为准，`-p` 只把运行时事件限制到该 PID。
- `模块后缀:0xADDR` 可通过“全路径”或“唯一后缀”选中模块；若后缀不唯一，会提示候选项。在 `-t -p` 会话中，该模块必须匹配 `-t` 目标。
- 地址 trace 目标始终使用该模块的 DWARF/符号表虚拟地址。不要填写原始 ELF 文件偏移，也不要填写 `/proc/<pid>/maps` 中 ASLR 后的运行时地址；GhostScope 会在内部把虚拟地址转换为 uprobe 需要的文件偏移。

## 源语言支持现状

GhostScope 的脚本语法本身与源语言无关，但实际效果取决于被追踪程序的 DWARF 信息能否较直接地映射回运行时内存。目前支持程度并不均衡：

| 源语言 | 支持程度 | 当前现状 |
| --- | --- | --- |
| C | 最好 | 这是当前的主要优化目标。局部变量、全局变量、x86_64 可执行文件中的 static 线程局部变量、指针、数组、结构体、枚举和 C 字符串这类 C 风格布局，与现有 DWARF 读取和脚本运算最匹配。 |
| C++ | 有限 | `trace ...` 里的函数名匹配，以及全局/静态变量查找，支持自动 demangle（符号名自动反混淆）。除名字解析外，C++ 语言特性目前大多还没有建模，实际更接近“按 DWARF 布局访问”，适合简单、接近 C 的数据布局和标量字段。 |
| Rust | 定向支持 | 见 [Rust 值详情](#rust-值展示)。 |

实践建议：
- 需要较高成功率的复杂 DWARF 表达式时，优先选择 C 目标。
- GhostScope 能识别 `DW_OP_form_tls_address`，这个操作既会用于 static TLS，也会用于 dynamic TLS。运行时地址解析目前只支持 x86_64 可执行文件 static TLS；dynamic/shared-library TLS 尚未建模。
- C++ 目前仍主要按 DWARF 布局访问。
- Rust 支持根据每个目标类型的源语言、类型身份和经过验证的 DWARF 布局
  决定。从 `DW_AT_producer` 解析出的 rustc 版本只作为提示性元数据；
  它本身不能证明任何私有布局。
- 若名字解析有歧义，优先退回到按源码行号或地址下探。

### Rust 值展示

Rust 值支持不会给 DSL 增加 Rust 专用语法。DSL 解析表达式后，DWARF 层
可以为根类型选择一个有界的语义读取计划。如果具体类型的身份或布局未通过
验证，GhostScope 会保留原生 DWARF 展示，而不会猜测 Rust ABI。

GhostScope 自身使用 Rust 1.88 构建，但这不会限制被追踪目标使用的 rustc
版本。CI 会使用[兼容性矩阵](../../e2e-tests/rust-compat-toolchains.txt)中的
版本构建有代表性的目标二进制。该矩阵记录的是已审计的 DWARF 布局，而不是
版本 gate：覆盖范围取决于具体 adapter，并非每个类型族都在每个列出的版本
上验证过；不匹配的旧布局会退回原生 DWARF 展示。

目前支持以下类型族：

- UTF-8 字符串：`&str`、`&mut str`、`String` 和 `Box<str>`；
- 平台原生字节串：`OsString`、`PathBuf`，以及布局验证通过的 `&Path`；
- 序列：`Vec<T>`、`&[T]`、`&mut [T]` 和 `VecDeque<T>`；
- 透明包装和状态包装：`NonZero*`、`Cell<T>` 和 `RefCell<T>`；
- 借用守卫：`Ref<T>` 和 `RefMut<T>`；
- 引用计数：`Rc<T>` 和 `Arc<T>`；
- 集合：`HashMap`、`HashSet`、`BTreeMap` 和 `BTreeSet`；
- 枚举：无字段、unit、tuple 和 struct variant，包括 `Option<NonZero*>`
  等 niche 优化类型在 DWARF 中使用的默认分支；
- tuple 和 tuple struct 投影，例如 `value.0`。

`Rc<str>` 和 `Arc<str>` 会显示目标地址以及对外可见的 strong/weak 计数。
GhostScope 不会通过这些所有者读取动态大小字符串的内容。

Rust enum 的格式化依据目标程序的 DWARF，而不是 rustc ABI 表。对于带
payload 的 enum，GhostScope 解析 `DW_TAG_variant_part`，跟随其
`DW_AT_discr` 成员，并处理精确判别值、判别值范围和默认分支，随后递归
格式化当前激活的内联 payload。无字段 enum 使用
`DW_TAG_enumeration_type` 和 `DW_AT_enum_class`。DSL 目前还不提供 Rust
模式匹配或直接投影当前 variant payload 的语法；enum payload 内嵌套的
语义适配器仍按原生 DWARF 格式展示。

语义值沿用现有格式占位符：

```ghostscope
trace do_stuff {
    print "text={} ascii={:s} bytes={:x}", text, text, text;
    print "items={}", values;
}
```

- `{}` 使用选中的语义展示。
- 当语义值支持无长度的 `{:s}` 或 `{:x}` 时，格式化器使用逻辑采集结果，
  不会暴露内部协议元数据。
- `{:s.16}`、`{:x.*}` 和 `{:s.n$}` 等带长度形式仍保留通用的显式内存
  读取语义。
- `ebpf.mem_dump_cap` 限制每个间接参数，默认值为 256 字节。若语义值的
  逻辑长度超过已采集的前缀，输出会标记 `<truncated>`。

例如，当 `mem_dump_cap = 3` 时，内容为 `"hello from rust"` 的 `&str`
会显示为：

```text
"hel" <truncated>
```

如果目标 DWARF 暴露了已知成员，也可以显式读取：

```ghostscope
trace do_stuff {
    print "manual={:s.*}", text.length, text.data_ptr;
    print "manual_hex={:x.*}", text.length, text.data_ptr;
}
```

这种显式写法依赖目标的物理成员路径；语义形式会先验证并隐藏这些路径。

#### 嵌套 Rust 值

内联 DWARF 结构格式化会递归执行，最大深度为 32。外层适配器采集 Rust
值后，其中的内联值也遵循这一规则：

```text
Outer { inner: Pair }     内联 Pair 使用递归 DWARF 格式化
Vec<Pair>                 Vec 采集元素，Pair 按结构格式化
Rc<Pair>                  Rc 投影 Pair 和计数，Pair 内联格式化
Cell<(i32, u16)>          Cell 投影并格式化内联 tuple 值
```

语义适配器目前只根据根表达式类型选择一次，不会再次递归采集嵌套语义容器：

```text
Rc<Vec<i32>>              不会递归采集内部 Vec 的元素
Cell<String>              不会递归采集内部 String 的字节
Vec<String>               String 元素保留物理 DWARF 展示
HashMap<String, Vec<i32>> key 和 value 不会运行嵌套适配器
```

已知的嵌套字段仍可在 DSL 中显式访问。该限制只影响整个根值的自动语义展示。
要支持递归语义采集，需要限制深度、字节数、元素数和解引用次数，并提供循环
检测、确定性的事件空间预留，以及每个子值独立的读取错误和截断状态。

## 变量

### 脚本变量

**脚本变量为“不可变变量”（immutable）**：同一追踪块内，变量名只能绑定一次；不可重复声明，也没有赋值语句（不支持 `x = ...`）。

使用 `let` 关键字声明脚本变量：

```ghostscope
let count = 0;
let threshold = 100;
let message = "hello";
let result = a + b;
```

#### 脚本变量的类型与能力

| 类型 | 字面量/示例 | 描述 | 运算/比较支持 |
| --- | --- | --- | --- |
| 整数（int，内部统一为 i64） | `123`, `-42` | 有符号 64 位整数 | 支持 `+`、`-`、`*`、`/`、`%`，以及位运算 `&`、`|`、`^`、`~`、`<<`、`>>`；可与 DWARF 整数类标量进行算术与比较 |
| 布尔（bool） | `true`、`false` 字面量，或由比较产生（如 `a < b`） | 由字面量/比较/逻辑表达式得到的布尔值 | 支持逻辑与/或（仅脚本内）；与 DWARF 整数类比较时按 0/1 参与比较与算术 |
| 字符串（string） | `"hello"` | UTF-8 字符串字面量 | 支持与 DWARF C 字符串做等值（==、!=）；不支持大小关系比较 |
| 别名（DWARF 表达式别名） | `let a = global.arr;`、`let p = &buf[0];` | 给任意 DWARF 表达式（变量、成员访问、数组、指针解引用或取地址）起一个脚本名，便于复用复杂类型/路径。 | 与底层 DWARF 类型具备相同的“复杂访问”能力：成员访问（`a.field`）、字面量或表达式下标（`a[0]`、`a[i + 1]`）、取地址（`&a`），并可用于 `memcmp/strncmp/starts_with` 以及 `{:x.N}`/`{:s.N}`/`{:p}`。当 GhostScope 能确定指针指向类型时，指针算术会按指向类型大小缩放。 |

说明：
1. 目前脚本层不直接暴露结构体/数组/指针类型；对于这些聚合类型，请通过 DWARF 变量访问（成员访问、解引用、字面量或表达式下标）先得到标量再参与运算。例外是“别名”变量：它可以绑定到任意 DWARF 表达式，并作为可复用的“基表达式”用于成员/下标访问、取地址与内存格式化。

示例：

```ghostscope
// 将复杂的 DWARF 访问起别名并复用
let a = global_var.arr;   // arr 为 DWARF 数组/聚合
print "ptr={:p}", &a;     // 对别名取地址
print a[1];               // 在别名上做整数字面量下标访问
print a[i + 1];           // 在别名上做表达式下标访问

// 传统的取地址别名依然可用
let p = &conn.buf[0];
print "h={:x.16}", p;
```
2. eBPF 不支持浮点运算，故当前脚本变量不支持浮点字面量与浮点运算
3. 一元负号（`-`）已支持并可嵌套：例如 `-1`、`-(-1)` 均合法；解析等价于 `0 - x` 的语义。
4. 布尔传输层使用 0/1 表示，展示层统一渲染为 `true/false`。

#### 变量作用域与遮蔽

- 块级作用域：每个 `{ ... }` 形成新作用域；`if` 的 then/else 为独立子作用域。变量只在其声明作用域及其嵌套子作用域内可见；离开作用域后不可见。
- 禁止脚本变量之间的遮蔽：内层作用域不得使用外层脚本变量的同名标识符重新绑定（即使两者在不同作用域）。
- 友好错误：
  - 赋值：`Assignment is not supported: variables are immutable. Use 'let a = ...' to bind once.`
  - 同域重声明：`Redeclaration in the same scope is not allowed: 'x'`
  - 内层遮蔽：`Shadowing is not allowed for immutable variables: 'x'`
  - 跨域引用：`Use of variable 'y' outside of its scope`

### DWARF 变量

DWARF 变量其实就是被跟踪的程序里面定义的**局部变量、参数和全局变量**，这类变量都是根据 DWARF 信息获取，所以在这里被统称为 DWARF 变量。

#### DWARF 变量类型

下表列出了按照 DWARF 类型定义，GhostScope 识别与显示/访问支持的主要类型：

| DWARF 类型 | 示例（来源语言） | 映射/显示 | 访问/运算支持 |
| --- | --- | --- | --- |
| 有符号/无符号整数（1/2/4/8 字节） | `int`, `long`, `unsigned int`, `size_t` | I8/I16/I32/I64 或 U8/U16/U32/U64 | 可打印；可与“脚本变量”的整数/布尔进行算术与比较（统一宽度与符号后） |
| 布尔 | `bool` | Bool（true/false） | 可打印；可与“脚本变量”的布尔/整数比较 |
| 浮点 | `float`, `double` | 可打印 | eBPF 不支持浮点运算；GhostScope 脚本不支持浮点字面量与浮点运算 |
| 字符 | `char`, `unsigned char` | 1 字节整数/字符 | 作为 1 字节整数打印；数组/指针见下 |
| C 字符串 | `char*`, `const char*`, `char[]` | CString（以字符串显示） | 可打印为字符串；可与“脚本变量”的字符串做等值（==、!=） |
| 指针 | `T*`, `void*`, 函数指针 | Pointer/NullPointer（地址显示） | 支持 `*` 解引用、`==`/`!=` 比较；对局部/参数/全局启用“自动解引用” |
| 数组 | `T[n]` | Array | 支持一维数组的字面量/表达式下标读取，包括顶层、链尾和数组元素后继续取成员；暂不支持多维数组 |
| 结构体/类 | `struct Foo`/`class Bar` | Struct | 支持 `.` 成员访问；不直接参与算术/比较（访问到标量成员后即可参与） |
| 联合体 | `union U` | Union | 同上，支持成员访问后再进行标量运算 |
| 枚举 | `enum E` | Enum（按底层整型） | 打印为枚举名；在运算/比较时按底层整数处理 |
| 位域 | `int flags:3` | Bitfield → 整数视图 | 抽取为整数；可与“脚本变量”的整数/布尔混用比较与算术 |
| 类型别名/限定 | `typedef`/`const`/`volatile` | Typedef/QualifiedType | 按底层类型处理（行为与底层类型一致） |
| 优化移除 | 变量被优化掉 | OptimizedOut | 读取失败；打印为 `<OPTIMIZED_OUT>`；运算/比较按失败语义处理 |
| 未知 | 不支持或未知 | Unknown | 打印为 `<UNKNOWN_TYPE_N_BYTES>` |

#### GhostScope 支持对复杂的 DWARF 变量访问：

```ghostscope
// 简单变量
print x;

// 成员访问（结构体字段）
print person.name;
print config.settings.timeout;

// Rust tuple 与 tuple struct 成员
print GLOBAL_TUPLE.0;
print GLOBAL_PAIR.1;

// 数组访问（支持字面量和表达式下标）
print arr[0];
print arr[1];
print arr[i + 1];

// 指针解引用
print *ptr;
print *(ptr);

// 取地址
print &variable;

// 复杂链式访问
print obj.field.subfield;
print obj.field.items[i + 1];
```

提示：
- 目前“局部变量、参数、全局变量”均已支持自动解引用（无需显式 `*ptr`，也不需要 `->`，统一使用 `.`，在安全范围内会自动加载并解引用指针值，类似于 Rust 的自动解引用）。
- 数组访问：已支持一维数组，如顶层 `arr[index]`、“链尾”`a.b.c[index]`，以及数组元素后继续取成员的 `arr[index].field` 或 `a.b[index].c`，其中 `index` 可以是整数字面量，也可以是 `i + 1` 这类整数表达式。`&arr[i]`、`&a.b.c[i]` 这类取地址形式可以按指针打印，也可以用于内存格式化（`{:x.N}`/`{:s.N}`）或作为 `memcmp` 参数。暂不支持：多维数组。

#### 显式类型转换

使用 `cast(expr, "TYPE")` 可以强制 GhostScope 将表达式解释成另一种类型。这个能力最适合用于地址、`void*`，或者当前 DWARF 类型不够精确但用户明确知道内存真实布局的场景。

```ghostscope
trace handle_request {
    let req = cast(ctx, "struct request *");
    print req.id;
    print req.headers[0];
}
```

`cast` 的类型字符串会按 DWARF 类型名解析。应把 DWARF 的 `DW_AT_name` 当作最真实的类型名称来源：`struct`、`union`、`enum`、`class` 这类 C 风格前缀只是为了方便书写和表达 tag hint，通常不是 DWARF 里保存的名字。例如 C 里的 `struct request`，在 DWARF 的结构体 DIE 上通常叫 `request`；`typedef` 则通常以 typedef 自己的名字出现。

`int`、`unsigned int`、`bool`、`float`、`double` 这类普通基础类型在 DWARF 里通常也会以 base type DIE 的形式存在。GhostScope 也接受常见 builtin 写法作为便利入口，标量 cast 在宽度、符号和布尔归一化这类场景仍然有用。不过 `cast` 的主要价值是用户自定义且带布局信息的类型：结构体、类、联合体、枚举、typedef、指针和数组。只有这些类型才能让 GhostScope 依据 DWARF 的成员偏移和元素布局，从内存中读出有意义的字段。

类型解析按模块作用域进行。这里的“模块”指运行时加载的 ELF object：主可执行文件或共享库；不是源码文件、包名、namespace 或 Rust crate。解析会先查当前 trace 命中的模块，再回退到其他带 DWARF 信息的已加载模块。

不同模块可能定义同名类型，例如主可执行文件和某个共享库都定义了 `struct request`。这种碰撞场景下，当前 trace 模块里的类型优先。如果该类型只存在于另一个已加载模块，GhostScope 可能解析到那个 fallback 结果；如果多个 fallback 模块同时命中，`cast` 会报告歧义，而不是随意选择一个。目前还没有显式 `module=` 或模块限定的 cast 语法；后续版本可能会加入，用于跨模块消歧。

### 特殊变量

特殊变量以 `$` 开头，提供运行时信息访问。

当前已支持：

- `$pid` — 当前进程 ID（tgid）。若配置了目标 PID namespace 上下文且内核支持 `bpf_get_ns_current_pid_tgid`，则按目标 PID namespace 视角取值；否则回退到 host / 初始 PID namespace 视角。
- `$tid` — 当前线程 ID（tid）。若配置了目标 PID namespace 上下文且内核支持 `bpf_get_ns_current_pid_tgid`，则按目标 PID namespace 视角取值；否则回退到 host / 初始 PID namespace 视角。
- `$host_pid` — 当前进程在 host / 初始 PID namespace 视角下的进程 ID（tgid），来自 `bpf_get_current_pid_tgid() >> 32`。
- `$input_pid` — `ghostscope -p <PID>` 中输入的原始 PID，也就是当前执行 `ghostscope -p` 环境里可见的 PID。仅在 `-p` 模式下可用。
- `$timestamp` — 单调时间戳（纳秒），来自 `bpf_ktime_get_ns`。

以上均作为整数参与比较与计算。

示例

```ghostscope
trace sample.c:42 {
    if $host_pid == 12345 { print "match"; }
    print "PID:{} HOST:{} INPUT:{} TID:{} TS:{}", $pid, $host_pid, $input_pid, $tid, $timestamp;
}
```

提示：目前仅支持 `$pid`、`$tid`、`$host_pid`、`$input_pid`、`$timestamp`。后续可能按需加入“寄存器相关”的特殊变量。
在容器 PID namespace 场景下，`$pid/$tid` 与 `$host_pid/$input_pid` 不一定相同：

- `$pid/$tid` 优先表达目标 PID namespace 视角
- `$host_pid` 固定表达 host / 初始 PID namespace 视角
- `$input_pid` 固定表达 `-p` 输入语义

若内核不支持 `bpf_get_ns_current_pid_tgid`（helper id 120），`$pid/$tid` 可能回退为宿主机 namespace 值。

### 变量查找顺序

当脚本中遇到变量时，GhostScope 按以下顺序查找：
1. 脚本定义的变量（使用 `let` 声明的）
2. 被追踪程序的局部变量和参数
3. 被追踪程序的全局变量

**注意**：脚本变量可能会遮蔽程序变量，命名时需要特别注意。

## 打印语句

`print` 语句在追踪期间输出信息。

### 基本形式

```ghostscope
// 打印字符串字面量
print "Hello, World";

// 打印变量
print count;

// 打印复杂表达式
print person.name;
print arr[0];
print *ptr;
```

### 格式化打印

使用贴近 Rust 的占位符：

```ghostscope
// 带参数的格式字符串
print "值: {}", value;
print "X: {}, Y: {}", x, y;
print "姓名: {}, 年龄: {}", person.name, person.age;
```

扩展占位符与动态长度

```ghostscope
// 十六进制 / 指针 / ASCII 字符串
print "A={:x} B={:X}", a, b;     // 十六进制字节视图
print "p={:p}", ptr;             // 指针地址 0x...
print "s={:s}", cstr;            // ASCII 字节视图；char*/char[N] 的 `{}` 仍打印带引号 C 字符串

// 指针/数组的内存转储
print "h={:x.16}", buf;          // 从 buf 读 16 字节按十六进制打印
print "ascii={:s.32}", name;      // 读 32 字节按 ASCII 打印（char* 遇到首个 NUL 停止）

// 动态长度（Rust 风格星号）：长度实参在值之前
print "buf={:x.*}", len, buf;    // 依次是 len、buf 两个实参

// 动态长度（捕获变量）：不消耗额外参数
let n = tail_len;                 // 脚本变量
print "tail={:s.n$}", p;          // 长度来自变量 n
```

说明
- `{}` 默认；`{:x}`/`{:X}` 将已经捕获到的参数 payload 按十六进制字节渲染；`{:p}` 渲染地址；`{:s}` 渲染 ASCII 字节。
- 长度后缀会把 `{:x}`/`{:s}` 变成内存转储语义。`{:x}` 格式化参数已经捕获到的值；`{:x.4}` 会把参数当成可寻址的内存来源，并从该地址/来源读取 4 字节。
- 长度后缀：
  - `.{N}`：静态长度（读取 N 字节）。`N` 支持十进制、十六进制（`0x..`）、八进制（`0o..`）和二进制（`0b..`）。
  - `.*`：动态长度，占位符会消费两个实参（先长度、后值）
  - `.name$`：捕获脚本变量 `name` 作为长度，不额外消费实参
- 读取方式会受类型影响。对于 `{:x}`，DWARF/脚本类型决定捕获值的大小，以及这个值如何被 materialize。对于 `{:x.N}`/`{:s.N}`，指针使用指针值作为读取地址，数组/聚合使用基地址，可取地址的 DWARF 标量变量使用自己的存储地址。纯脚本整数不是地址，除非显式 cast 成指针类型，否则会被拒绝。
- 内核侧会为内存转储形式做有界读取；用户态负责十六进制/ASCII 渲染。`{:s}` 的 ASCII 渲染遇到首个 NUL 字节即停止；不可打印字节显示为 `\xNN`。
- 内存转储的单参数上限由配置项 `ebpf.mem_dump_cap` 控制（默认 256 字节）。若请求长度超过该上限，将被截断；若超过事件负载上限，输出也可能被截断并以 `…` 表示。
- 读取失败（如空指针、偏移不可用、权限等）时，扩展占位符会输出 `<MISSING_ARG>`。

示例：

```ghostscope
trace foo.c:42 {
    // int a = 10;
    print "value-hex={:x}", a;     // a 这个 int 值的十六进制字节视图，如 0a 00 00 00
    print "mem-hex={:x.4}", a;     // 从 a 的 DWARF 存储地址读取 4 字节
    print "bad={:x.4}", 10;        // 会被拒绝：脚本整数字面量不是地址
    print "forced={:x.4}", cast(10, "u8 *"); // 强制从地址 0xa 读 4 字节
}
```

**注意**：格式字符串遵循 Rust 风格，不支持 `%d`/`%s`（C 风格）。

## 条件语句

GhostScope 使用 Rust 风格的条件语句语法：

```ghostscope
// 简单 if
if x > 100 {
    print "值很大";
}

// If-else
if result == 0 {
    print "成功";
} else {
    print "失败";
}

// 嵌套 if-else
if x > 100 {
    print "大";
} else if x > 50 {
    print "中";
} else {
    print "小";
}
```

提示：条件表达式在运行时若读取 DWARF 变量失败，不会被静默当作 false；将发送一条结构化的 `ExprError` 并按“软中止”语义处理分支。详见下文“运行时表达式失败（ExprError）”。

### 比较运算符

- `==` - 等于
- `!=` - 不等于
- `<` - 小于
- `<=` - 小于等于
- `>` - 大于
- `>=` - 大于等于

## 表达式

### 算术运算

```ghostscope
let sum = a + b;       // 加法
let diff = a - b;      // 减法
let product = a * b;   // 乘法（不用于指针）
let quotient = a / b;  // 除法
let remainder = a % 4; // 取模

// 整数字面量
let x = 123;           // 十进制
let h = 0x1f;          // 十六进制（31）
let o = 0o755;         // 八进制（493）
let b = 0b1010;        // 二进制（10）
let neg = -0x10;       // 一元负号作用于字面量（解析为 0 - 16）
```

### 位运算

```ghostscope
let masked = flags & 0x4;
let combined = flags | 0x10;
let flipped = flags ^ 0xff;
let inverse = ~flags;
let high = value >> 8;
let scaled = value << 2;
```

位运算要求操作数为整数或布尔。动态移位计数会按操作数位宽做掩码，
避免运行时出现未定义的移位。

### 表达式优先级

1. 括号 `()`
2. 成员访问 `.`，数组访问 `[]`
3. 指针解引用 `*`，取地址 `&`，一元负号 `-`，逻辑非 `!`，按位取反 `~`
4. 乘法 `*`，除法 `/`，取模 `%`
5. 加法 `+`，减法 `-`
6. 移位 `<<`、`>>`
7. 大小比较 `<`, `<=`, `>`, `>=`
8. 等值比较 `==`, `!=`
9. 按位与 `&`
10. 按位异或 `^`
11. 按位或 `|`
12. 逻辑与 `&&`
13. 逻辑或 `||`

### 逻辑运算符

- `!`（逻辑非）、`&&`（逻辑与）、`||`（逻辑或）
- 操作数按“非零为真”处理
- 逻辑非：`!expr` 在 `expr` 为 0/false 时为 true，否则为 false
- `||`、`&&` 均采用短路求值：
  - `||`：左侧为真则不再计算右侧
  - `&&`：左侧为假则不再计算右侧

示例

```ghostscope
trace main {
    if a > 10 && b == 0 {
        print "AND";
    } else if a < 100 || p == 0 {
        print "OR";
    }

    // 一元逻辑非：对产生布尔的表达式取反
    print "NOT1:{}", !starts_with(activity, "main");
    print "NOT2:{}", !strncmp(record, "HTTP", 4);
}
```

### 指针算术（按 C 语义）

受控地支持 C 风格的指针算术：

- 允许：`ptr + int`、`int + ptr`、`ptr - int`。
- 步长缩放：按指针目标类型的元素大小缩放偏移量（C 语义）。例如 `int* p`，`p + 2` 前进 `2 * sizeof(int)` 个字节。
- 在 `print` 中的行为：当用于 `print` 参数时，`p ± n` 会在计算出的地址按被指向的 DWARF 类型读取并展示内容。比如在 `int* numbers` 上 `print numbers + 1;` 会显示第二个整型。
- `void*`/未知类型：若无法获得类型信息，则按 1 字节缩放。
- 不支持：函数指针的算术；指针与指针的算术（`p + q`、`p - q`）。指针的有序比较（`<`、`<=`、`>`、`>=`）会被编译期拒绝；使用 `==`/`!=`。

示例：

```ghostscope
trace calculate_average {
    print numbers;       // 依据上下文打印地址或首元素
    print numbers + 1;   // 打印第二个 int（按照 sizeof(int) 缩放）
}

trace log_activity {
    print activity + 1;  // 对于 const char* activity，打印下一个字符
}
```

### 脚本变量与 DWARF 变量的跨类型运算

#### 整数算术与位运算
（`+`、`-`、`*`、`/`、`%`、`&`、`|`、`^`、`~`、`<<`、`>>`）

- 支持：脚本变量（整数/布尔） 与 DWARF 变量中的“整数类标量”混用。
  - 整数类标量包括：BaseType（有符/无符 1/2/4/8 字节）、Enum（按底层整型）、Bitfield（位域抽取为整数）、`char/unsigned char`（1 字节整数）。
- 布尔参与算术时等价于 `0/1`。
- 不支持：聚合（struct/union/array）、指针、浮点（运行时）。

示例（算术）

```ghostscope
// DWARF 整数与脚本整数相加
trace foo.c:42 {
    print "sum:{}", s.counter + 5;
}

// 枚举/位域（当作整数）参与运算/比较
trace foo.c:43 {
    print "active:{}", a.active == 1;
}

// 布尔作 0/1 参与算术
trace foo.c:60 {
    let ok = true;
    print "S:{}", ok + 41; // 42
}
```

#### 指针算术

GhostScope 以受控且安全的方式支持 C 风格的指针算术：

- 允许：ptr + int、int + ptr、ptr - int。
- 步长缩放：整数偏移按指针目标类型的元素大小缩放（C 语义）。例如，对于 int* p，p + 2 会前进 2 * sizeof(int) 个字节。
- 在 print 中的类型化读取：当用于 print 时，p ± n 会在计算出的地址上，按指向的 DWARF 类型读取并渲染该值。例如，print numbers + 1;
  可显示 int* numbers 的第二个 int。
- void*/未知类型：如果指向的类型为 void 或不可获取，则缩放退化为 1 字节。
- 不支持：函数指针上的指针算术；指针—指针算术（p + q、p - q）。指针的有序比较（<、<=、>、>=）会被拒绝；请使用 ==/!=。

示例：

```ghostscope
trace calculate_average {
    // numbers 类型是 int*
    print numbers;       // 根据上下文打印地址或第一个元素
    print numbers + 1;   // 打印第二个 int（按 sizeof(int) 缩放）
}

trace log_activity {
    print activity + 1;  // 对于 const char* activity，打印下一个字符
}
```

#### 比较（==、!=、<、<=、>、>=）

- 支持：脚本变量（整数/布尔） 与上述 DWARF 整数类标量。
- 有序比较 `< <= > >=` 的语义：
  - 脚本整数始终是有符号 `i64`；布尔按 `0`/`1` 参与比较。
  - 显式类型转换使用 `cast(expr, "TYPE")`，详见上文“显式类型转换”。不支持 C/Rust 原生写法，例如 `(uint32_t)x` 或 `x as u32`。
  - 对 DWARF 侧 C 整数类标量，有序比较会先按 C 的 integer promotions 与 usual arithmetic conversions 选择比较宽度和有符号/无符号语义。
  - `char`、`unsigned char`、`short`、`unsigned short` 等窄整数会先提升。按当前支持的 C 目标模型，`int8_t(-5) < uint8_t(250)` 会按有符号 `int` 比较，结果为真。
  - 对有符号/无符号混合比较，GhostScope 会选择转换后的比较宽度和符号。例如 `int32_t(-1) > uint32_t(4000000000)` 按 `uint32_t` 比较；`uint32_t(4000000000) > -10000000000` 则把脚本侧视为有符号 `i64` 参与比较。
  - 如果转换后选择无符号比较，左右两侧会先转换到该无符号宽度，再应用无符号比较谓词。因此 `INT32_MIN < uint32_t(4000000000)` 会保持 C 语义。
- 指针比较：仅支持等值/不等（DWARF 指针 == DWARF 指针、DWARF 指针 == 0）。
  - 注意：指针的有序比较（`<`、`<=`、`>`、`>=`）不被支持，会在编译期直接报错并给出提示。若需比较地址是否相等，请使用 `==/!=`。若需对地址做偏移，请在“取地址”语境下使用 `&expr + <非负常量>`；若要比较值，请先选择标量字段（如 `obj.field`）。
- C 字符串等值：DWARF 变量（`char*` 或 `char[]`） 与 脚本变量（字符串字面量）可做 `==/!=` 等值比较（通过有界读取再比较）。（可以参考下面一小节）
- 不支持：字符串大小关系比较、聚合整体比较、浮点与 DWARF 值混用比较。

示例（比较）

```ghostscope
// 跨有符号/无符号的等值比较
if count == size { print "EQ"; }

// 有序比较按 C integer promotions / usual arithmetic conversions
let t = 1024;
if size > t { print ">1K"; }

// 脚本整数是有符号 i64；当前还不支持显式 cast
if u32_count > -10000000000 { print "script-signed-i64"; }

// 指针等值比较（不支持大小关系）
trace foo.c:50 {
    print "isNull:{}", p == 0;       // 指针与 NULL
}
```

注意：当 DWARF 变量运行时读取失败的呈现与分支行为，参见下文“运行时表达式失败（ExprError）”。

### C 字符串等值比较（char*/char[]）

GhostScope 支持将脚本字符串字面量与 DWARF 侧的 C 字符串进行等值比较：

- 支持的 DWARF 形式：`const char*` / `char*` 指针，以及固定长度 `char[N]`。
- 支持的运算符：`==` 与 `!=`。
- 比较语义（严格 `\0`）：设脚本字面量长度为 `L`。
  - 对 `char*`：使用有界的 `bpf_probe_read_user_str` 读取至多 `L+1` 字节。若 helper 返回值恰为 `L+1`，且读取到的第 `L` 个字节为 `\0`，且前 `L` 个字节逐字节等于字面量，则判等。
  - 对 `char[N]`：使用有界的 `bpf_probe_read_user` 读取 `min(N, L+1)` 字节。要求 `L+1 <= N`，且缓冲区第 `L` 个字节为 `\0`，且前 `L` 个字节逐字节等于字面量，才判等。
  - 任何读取失败（无效地址/权限等）一律按“不相等”处理。

```ghostscope
// C 字符串等值：DWARF char*/char[] 与脚本字符串字面量
trace foo.c:60 {
    print "greet-ok:{}", gm == "Hello, Global!"; // gm: const char* 或 char[]
}
```

## 内置函数

### `strncmp(a, b, n)`
  - 在前 `n` 个字节范围内判断 `a` 与 `b` 是否相等（不要求出现终止符 `\0`）。
  - 至少一侧（`a` 或 `b`）必须是“字符串”：字符串字面量，或脚本字符串变量（如 `let s = "AB";`）。
  - 另一侧可以是：DWARF 指针/数组、DWARF 别名，或字符串（字面量/脚本字符串变量）。
  - 两侧均为字符串时编译期直接折叠；仅一侧为字符串时，运行时从“非字符串一侧”读取并比较（失败会产生 ExprError）。
  - 比较长度由 `n` 指定，`n` 必须是非负整数字面量；实际比较长度取 `min(n, compare_cap, 字符串长度, 内存可读长度)`。`compare_cap` 默认 64 字节，可在配置中调整。
  - 运行时读取失败的呈现与分支行为，参见下文“运行时表达式失败（ExprError）”。

示例：`strncmp`

```ghostscope
// 函数参数（const char* activity）
trace log_activity {
    print "eq5:{}", strncmp(activity, "main_", 5);
}

// 全局/只读字符串或定长数组
trace globals_program.c:32 {
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);    // lm: const char*
}

// 通用指针（读取失败 → false）
trace process_record {
    print "rec_http:{}", strncmp(record, "HTTP", 4); // record: struct* -> false
}
```
### `starts_with(a, b)`
  - 判断是否“以 b 为前缀”，等价于 `strncmp(a, b, len(b))`。
  - 至少一侧为字符串（字面量或脚本字符串变量）；另一侧可以为地址表达式（DWARF 指针/数组或别名）或字符串。
  - 两侧均为字符串时编译期折叠；仅一侧为字符串时，运行时从另一侧读取 `len(b)` 个字节进行比较（失败会产生 ExprError）。

示例：`starts_with`

```ghostscope
// 前缀匹配（等价于 strncmp(expr, lit, len(lit)))
trace log_activity {
    print "is_main:{}", starts_with(activity, "main");
}

trace globals_program.c:32 {
    print "gm_hello:{}", starts_with(gm, "Hello"); // gm: const char*
}
```

### `memcmp(expr_a, expr_b, len)`
  - 布尔语义：若 `expr_a` 与 `expr_b` 所指内存的前 `len` 个字节完全一致，返回 `true`，否则 `false`。
  - 指针来源：`expr_a`/`expr_b` 可为 DWARF“指针或数组”表达式（元素类型不限）、取址表达式（如 `&expr`、`&arr[0]`）。若需与字符串字面量比较，请使用 `strncmp`/`starts_with`。
  - 不支持将“裸整型地址”作为指针实参。若要比对原始字节，请使用下文 `hex("...")`。
    - 若任一参数为 `hex("...")`，可省略第三个 `len` 参数；解析器会用 `hex` 的字节数作为长度。若两侧都是 `hex(...)`，两者字节数需一致。
    - 当 `memcmp(expr, hex(...), len_literal)` 使用字面量长度时，解析器会检查 `len_literal` 不得超过字节串长度，且不能为负，否则报错。
  - `len` 支持脚本整数表达式，且整数字面量支持十进制、十六进制（`0x..`）、八进制（`0o..`）与二进制（`0b..`）。运行时会将负值钳为 0；但解析器会拒绝“字面量负长度”。
  - 不涉及 NUL 终止；按原始字节比较（单位为字节）。
  - 若 `len == 0`，结果为 `true`，且不会执行任何用户内存读取（快速路径）。
  - 运行时读取 DWARF 变量失败的呈现与分支行为，参见下文“运行时表达式失败（ExprError）”。

示例：`memcmp`

```ghostscope
// 两个指针之间的原始内存等值比较
trace globals_program.c:32 {
    // 完全相等
    if memcmp(&lib_pattern[0], &lib_pattern[0], 16) { print "EQ"; } else { print "NE"; }
    // 偏移后产生差异
    if memcmp(&lib_pattern[0], &lib_pattern[1], 16) { print "EQ2"; } else { print "NE2"; }
    // len=0 → true（不发生任何用户态读取）
    if memcmp(&lib_pattern[0], &lib_pattern[1], 0) { print "Z0"; }
    // 动态长度来自脚本变量
    let n = 10;
    if memcmp(&lib_pattern[0], &lib_pattern[0], n) { print "DYN_EQ"; }
}
```

### `hex("<HEX BYTES>")`

- 语法：`hex("<HEX BYTES>")`
  - `<HEX BYTES>` 仅允许十六进制字符（`0-9a-fA-F`）与空格分隔（不支持 Tab 等其他分隔符）；去掉空格后十六进制字符数量必须为偶数。
  - 解析期校验：若出现非十六进制字符（除空格外）或为奇数字节，直接报错并给出明确原因。配合 `memcmp(expr, hex(...), len_literal)` 且长度为字面量时，还会检查 `len_literal` 不能超过字节串长度，且不能为负。
- 语义：按书写顺序逐字节解析（每两个十六进制字符组成一个字节），不涉及大小端；不支持在字符串中写 `0x` 前缀。
- 使用范围：作为 `memcmp` 的参数，用于和原始字节序列比较（如文件头、魔数）。
- 示例：

```ghostscope
trace foo {
    // 比较前 2 字节是否为 ASCII "PO"
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }

    // 比较 4 字节 0xDE 0xAD 0xBE 0xEF
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }
}
```

## 栈回溯语句

`backtrace;` 和 `bt;` 会在探针触发点输出源码感知的调用栈。unwinder 直接使用 DWARF CFI；没有 `unwind=` 参数，也不暴露 helper/fp 之类的后端选择。

```ghostscope
trace test_function {
    print "before";
    bt;
    print "after";
}
```

参数：

- `bt raw;` 输出原始 module cookie、模块内偏移和运行时 IP，不做源码符号化。
- `bt full;` 输出符号化的源码感知栈帧。raw IP/cookie 调试元数据不会出现在 `bt full` 中，只由 `bt raw` 显示。
- `bt inline;` 输出 inline 调用链；这是默认行为。
- `bt noinline;` 关闭 inline 调用链输出。

Backtrace 深度是全局配置，不再写在脚本里。使用命令行 `--backtrace-depth <N>`，或在配置文件 `[ebpf]` 中设置 `backtrace_depth = N`。合法范围是 `1..=128`，默认值是 `128`。
在 `--script-output pretty` 下，如果 `[script] color` 启用了 ANSI 输出，backtrace payload 会带颜色。`--script-output plain` 始终输出不带 ANSI 的原始 payload 文本。

示例：

```ghostscope
trace test_function {
    bt full;
    bt raw noinline;
}
```

典型输出：

```text
backtrace: complete, 4 frames (max 128)
  #0 test_function(int argc, char** argv) at sample_program.c:8:5 [sample_program+0x1189]
  #1 caller(int value) at sample_program.c:42:9 [sample_program+0x1234]
  #2 main(int argc, char** argv) at sample_program.c:88:12 [sample_program+0x13a0]
  #3 <unknown function> at ?? [libc.so.6+0x2a1ca]
```

`bt raw;` 使用相同的 header，但会输出面向排障的机器字段：

```text
backtrace: truncated, 2 frames (max 2)
  #0 0x1189 [sample_program+0x1189] raw=0x55... cookie=0x...
  #1 0x1234 [sample_program+0x1234] raw=0x55... cookie=0x...
```

`status=complete` 表示 DWARF unwind 在达到配置的深度上限前自然结束。`status=truncated` 表示 GhostScope 达到了配置的深度上限，或先达到了 eBPF tail-call unwind 预算。其他状态会说明 unwind 停止的原因，例如当前 PC 没有可用的 unwind row、CFI 不支持、模块偏移不可用、读取用户栈内存失败，或下一帧地址/CFA 不合法。可用时，`stopped:` 会附带稳定的原因标签和数字 code。

只要进程模块映射和对应模块的 compact DWARF CFI 可用，`bt` 可以跨模块 unwind。在 `-p` 和启用 sysmon 的独立 `-t` 下，运行时模块刷新可以为后续通过 `dlopen` 加载的库补充 backtrace 元数据；它不会为 setup 阶段尚未知的目标自动新增 trace probe。具体覆盖边界见[使用限制](limitations.md#6-栈回溯覆盖范围)。

## 示例

本节集中展示常见的用法示例。

### 基础函数追踪与进程信息

```ghostscope
trace main {
    print "程序启动";
    print "PID:{} TID:{} TS:{}", $pid, $tid, $timestamp;
}
```

### 条件追踪

```ghostscope
trace malloc {
    if size > 1_048_576 {  // 1 MB
        print "大内存分配: {} 字节", size;
    }
}
```

### DWARF 自动解引用与成员访问

```ghostscope
trace process_user {
    // 结构体字段
    print "用户:{}", user.name;
    print "状态:{}", user.status;

    // 自动解引用指针（安全前提下，无需手写 * 与 ->）
    print "好友:{}", user.friend_ref.name;
}
```

### 数组访问与取址（&）

```ghostscope
trace foo.c:42 {
    // 顶层下标与链尾下标，支持字面量和表达式
    print "arr0:{}", arr[0];
    print "name0:{}", person.names[0];
    print "next:{}", person.names[i + 1];

    // 取地址后参与内置比较/内存转储
    print "p(&buf[0])={:p}", &buf[0];
    print "p(&buf[i])={:p}", &buf[i];
}
```

### C 字符串比较（char*/char[]）

```ghostscope
// 参数 activity: const char*
trace log_activity {
    print "前缀:{}", starts_with(activity, "main");
    print "等值:{}", strncmp(activity, "main_", 5);
}

// 全局/只读字符串
trace globals_program.c:32 {
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);    // lm: const char*
}
```

### 原始内存比较（memcmp）与 hex 字节串

```ghostscope
trace globals_program.c:32 {
    // 指针对比（完全相等/有偏移）
    if memcmp(&lib_pattern[0], &lib_pattern[0], 16) { print "EQ"; } else { print "NE"; }
    if memcmp(&lib_pattern[0], &lib_pattern[1], 16) { print "EQ2"; } else { print "NE2"; }

    // len=0 → true（不发生任何用户态读取）
    if memcmp(&lib_pattern[0], &lib_pattern[1], 0) { print "Z0"; }

    // 动态长度来自脚本变量
    let n = 10;
    if memcmp(&lib_pattern[0], &lib_pattern[0], n) { print "DYN_EQ"; }
}

// 与字节模式（hex）匹配
trace foo {
    if memcmp(buf, hex("50 4F"), 2) { print "HDR"; }          // 前 2 字节为 "PO"
    if memcmp(ptr, hex("DE AD BE EF"), 4) { print "MAGIC"; }  // 魔数
}
```

### else-if 链与 ExprError 软中止

```ghostscope
// G_STATE.lib 某些时刻为 NULL，读取失败会触发 ExprError
trace globals_program.c:32 {
    if memcmp(G_STATE.lib, hex("00"), 1) { print "A"; }
    else if memcmp(gm, hex("48"), 1) { print "B"; }
    else { print "C"; }
}
// 预期：出现 ExprError 警告行，并打印 B；A/C 不出现（软中止抑制 THEN/ELSE）
```

### 结构体 Pretty Print 与指针解引用

```ghostscope
// 以 complex_types_program 为例
trace complex_types_program.c:25 {
    print s.name;   // char[16] → 字符串
    print s;        // pretty-print 结构体
    print *ls;      // 解引用指针并 pretty-print
}
```

### 动态长度格式化与内存转储

```ghostscope
trace foo {
    let n = 32;
    print "h={:x.*}", n, buf;       // 以十六进制打印 n 字节
    print "ascii={:s.n$}", name;    // 捕获变量 n 为长度，不额外消耗实参
}
```

## 限制

1. **无循环**：出于安全考虑，不支持循环（`for`、`while`）
2. **无函数定义**：不能定义自定义函数
3. **只读**：不能修改被追踪程序的状态
4. **字符串操作有限**：支持 C 字符串等值（==/!=）与内置函数 `strncmp`/`starts_with`；不支持字符串连接或一般性字符串处理
5. **整数运算限定**：支持整数算术与位运算；不支持浮点运算
6. **无动态内存**：不能分配内存
7. **源语言支持与具体类型和 DWARF 布局有关**：详见
   [源语言支持现状](#源语言支持现状)

## 最佳实践

1. **保持简单**：追踪操作应该轻量以减少开销
2. **尽早过滤**：使用条件减少追踪频率
3. **有意义的输出**：在打印语句中包含上下文
4. **避免复杂逻辑**：保持追踪逻辑直观简单
5. **渐进测试**：从简单追踪开始，逐步增加复杂性

## 注意事项

- 变量声明（`let`）创建脚本局部变量，而非程序变量
- 所有变量都是动态类型
- 字符串字面量必须使用双引号
- 大多数语句需要分号
- 追踪模式匹配支持文件模糊匹配（参见[命令参考](input-commands.md)）

## 运行时表达式失败（ExprError）

当 `if/else if` 条件或内置函数（如 `memcmp`、`strncmp`、`starts_with`）在运行时读取 DWARF 变量失败时，GhostScope 不会静默将条件当作 false，而是发送一条结构化的“表达式错误（ExprError）”指令到用户态并按“软中止”语义处理：

- 软中止：
  - 对出错的 `if`：跳过 then/else；`else if` 链继续评估；若后续某个条件为真则执行该分支。
  - 对 `print`：不终止，行内展示变量读取错误；若 `print` 参数是 `memcmp/strncmp` 且失败，会附加一条 `ExprError` 警告。

### ExprError 的字段

- `expr`：表达式的可读文本（UTF‑8 安全截断）。
- `code`：错误码，对齐 `VariableStatus` 语义：
  - 1 = NullDeref（空指针解引用）
  - 2 = ReadError（读失败，含 probe_read_user 等）
  - 3 = AccessError（权限/访问错误）
  - 4 = Truncated（长度被截断）
  - 5 = OffsetsUnavailable（缺少 ASLR 偏移等运行时信息）
  - 6 = ZeroLength（请求长度为 0）
- `flags`：位掩码，提供额外上下文（不同内置函数有各自语义）：
  - `memcmp`：
    - `0x01` → first-arg read-fail（arg0）
    - `0x02` → second-arg read-fail（arg1）
    - `0x04` → len-clamped（长度被 compare_cap 裁剪）
    - `0x08` → len=0（有效长度为 0）
  - `strncmp/starts_with`：
    - `0x01` → read-fail（目标读取失败）
    - `0x04`、`0x08` 预留用于长度裁剪与长度为 0
- `failing_addr`：失败涉及的指针地址（若可用，否则为 0）。

控制台模式下的示例输出：

```
ExprError: memcmp(buf, hex("504f"), 2) (read error at 0x0000000100000000, flags: first-arg read-fail,len-clamped)
```

当失败地址为 0 时，会显示为 `at NULL`：

```
ExprError: memcmp(G_STATE.lib, hex("00"), 1) (read error at NULL, flags: first-arg read-fail)
```
