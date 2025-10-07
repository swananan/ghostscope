# GhostScope 脚本语言参考

GhostScope 使用专门的领域特定语言来定义追踪点和操作。脚本可以在 TUI 中使用 `trace` 命令时编写，或从脚本文件加载。

## 目录
1. [基础语法](#基础语法)
2. [追踪语句](#追踪语句)
3. [变量](#变量)
4. [打印语句](#打印语句)
5. [条件语句](#条件语句)
6. [表达式](#表达式)
7. [内置函数](#内置函数)
8. [特殊变量](#特殊变量)
9. [示例](#示例)
10. [限制](#限制)

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
- `backtrace` / `bt` - 打印调用栈（实现中）
- `if`/`else` - 条件执行
- `let` - 变量声明
- 表达式语句

## 追踪语句

`trace` 语句是定义追踪点的顶层结构。它只在脚本文件中使用，不在追踪块内部使用。

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

## 变量

### 脚本变量

使用 `let` 关键字声明脚本变量：

```ghostscope
let count = 0;
let threshold = 100;
let message = "hello";
let result = a + b;
```

脚本变量的类型与能力如下：

| 类型 | 字面量/示例 | 描述 | 运算/比较支持 |
| --- | --- | --- | --- |
| 整数（int，内部统一为 i64） | `123`, `-42` | 有符号 64 位整数 | 支持 +、-、*、/；可与 DWARF 整数类标量进行算术与比较 |
| 布尔（bool） | 由比较产生：`a < b` | 通过比较/逻辑表达式得到的布尔值 | 支持逻辑与/或（仅脚本内）；与 DWARF 整数类比较时按 0/1 参与比较与算术 |
| 字符串（string） | `"hello"` | UTF-8 字符串字面量 | 支持与 DWARF C 字符串做等值（==、!=）；不支持大小关系比较 |

说明：
1. 目前脚本层不支持自定义结构体/数组/指针类型；对于这些聚合类型，请通过 DWARF 变量访问（成员访问、解引用、常量下标）来获取标量后再参与运算。
2. eBPF 不支持浮点运算，故当前脚本变量不支持浮点字面量与浮点运算
3. 一元负号（`-`）已支持并可嵌套：例如 `-1`、`-(-1)` 均合法；解析等价于 `0 - x` 的语义。
4. 布尔传输层使用 0/1 表示，展示层统一渲染为 `true/false`。

### DWARF 变量

DWARF 变量其实就是被跟踪的程序里面定义的**局部变量、参数和全局变量**，这类变量都是根据 DWARF 信息获取，所以在这里被统称为 DWARF 变量。

#### DWARF 变量类型

下表列出了按照 DWARF 类型定义，GhostScope 识别与显示/访问支持的主要类型：

| DWARF 类型 | 示例（来源语言） | 映射/显示 | 访问/运算支持 |
| --- | --- | --- | --- |
| 有符号/无符号整数（1/2/4/8 字节） | `int`, `long`, `unsigned int`, `size_t` | I8/I16/I32/I64 或 U8/U16/U32/U64 | 可打印；可与“脚本变量”的整数/布尔进行算术与比较（统一宽度与符号后） |
| 布尔 | `bool` | Bool（true/false） | 可打印；可与“脚本变量”的布尔/整数比较 |
| 浮点 | `float`, `double` | 不支持 | eBPF 不支持浮点运算；GhostScope 脚本不支持浮点字面量与浮点运算 |
| 字符 | `char`, `unsigned char` | 1 字节整数/字符 | 作为 1 字节整数打印；数组/指针见下 |
| C 字符串 | `char*`, `const char*`, `char[]` | CString（以字符串显示） | 可打印为字符串；可与“脚本变量”的字符串做等值（==、!=） |
| 指针 | `T*`, `void*`, 函数指针 | Pointer/NullPointer（地址显示） | 支持 `*` 解引用、`==`/`!=` 比较；对局部/参数/全局启用“自动解引用” |
| 数组 | `T[n]` | Array | 支持常量下标读取（顶层或链尾）；暂不支持动态/中间索引、多维数组 |
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

// 数组访问
print arr[0];
print arr[i];

// 指针解引用
print *ptr;
print *(ptr);

// 取地址
print &variable;

// 复杂链式访问
print obj.field.subfield;
print arr[0].name;
```

提示：
- 目前“局部变量、参数、全局变量”均已支持自动解引用（无需显式 `*ptr`，也不需要 `->`，统一使用 `.`，在安全范围内会自动加载并解引用指针值，类似于 Rust 的自动解引用）。
- 数组访问：已支持顶层 `arr[常量]` 与“链尾”`a.b.c[常量]`。暂不支持：链中间索引（如 `a.b[2].c`）、动态下标（`arr[i]`）和多维数组。

### 特殊变量（实现中）

特殊变量以 `$` 开头，提供运行时信息访问：

```ghostscope
// 函数参数（x86_64 调用约定）
$arg0, $arg1, $arg2, $arg3, $arg4, $arg5

// 进程信息
$pid    // 进程 ID
$tid    // 线程 ID
$comm   // 进程名称

// 返回值（在返回探针中）
$retval

// CPU 寄存器（架构特定）
$pc     // 程序计数器
$sp     // 栈指针
```

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

使用 `{}` 作为格式字符串中的占位符：

```ghostscope
// 带参数的格式字符串
print "值: {}", value;
print "X: {}, Y: {}", x, y;
print "姓名: {}, 年龄: {}", person.name, person.age;
```

**注意**：格式字符串使用 `{}` 占位符（Rust 风格），而不是 `%d`/`%s`（C 风格）。

## 内置函数

GhostScope 提供两个字符串内置函数，用于高效、对 verifier 友好的比较：

- `strncmp(expr, "lit", n)`
  - 将 `expr` 指向的内存前 `n` 个字节与字面量 `lit` 比较。
  - 在 `n` 字节内不要求出现终止符 `\0`。
  - `expr` 可为 DWARF 的 `char*`、`char[N]`，也可为通用指针；GhostScope 会做有界的用户态内存读取并按字节比较。
  - 任何读取失败均返回 `false`。
  - 为安全起见比较长度固定上限为 64 字节（编译器常量 `STRING_BUILTIN_READ_CAP`，见 `ghostscope-compiler/src/ebpf/expression.rs`）；若 `n` 超过上限或数组可用长度，会自动裁剪。

- `starts_with(expr, "lit")`
  - 等价于 `strncmp(expr, "lit", len("lit"))`。
  - 失败与安全语义同上。

Verifier 友好与性能：
- 内置函数生成的比较逻辑尽量少分支（如按字节 XOR/OR 累积），降低 verifier 状态数量。
- 避免在极热的探针里塞入大量大字符串比较；必要时拆分脚本或选择不那么热的落点。

示例

```ghostscope
// 函数参数（const char* activity）
trace log_activity {
    print "is_main:{}", starts_with(activity, "main");
    print "eq5:{}", strncmp(activity, "main_", 5);
}

// 全局只读字符串与定长数组
trace globals_program.c:32 {
    print "gm_hello:{}", starts_with(gm, "Hello"); // gm: const char*
    print "lm_libw:{}", strncmp(lm, "LIB_", 4);    // lm: const char*
}

// 通用指针（读取失败 → false）
trace process_record {
    print "rec_http:{}", strncmp(record, "HTTP", 4); // record: struct* -> false
}
```

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

#### C 字符串等值比较（char*/char[]）

GhostScope 支持将脚本字符串字面量与 DWARF 侧的 C 字符串进行等值比较：

- 支持的 DWARF 形式：`const char*` / `char*` 指针，以及固定长度 `char[N]`。
- 支持的运算符：`==` 与 `!=`。
- 比较语义（严格 `\0`）：设脚本字面量长度为 `L`。
  - 对 `char*`：使用有界的 `bpf_probe_read_user_str` 读取至多 `L+1` 字节。若 helper 返回值恰为 `L+1`，且读取到的第 `L` 个字节为 `\0`，且前 `L` 个字节逐字节等于字面量，则判等。
  - 对 `char[N]`：使用有界的 `bpf_probe_read_user` 读取 `min(N, L+1)` 字节。要求 `L+1 <= N`，且缓冲区第 `L` 个字节为 `\0`，且前 `L` 个字节逐字节等于字面量，才判等。
  - 任何读取失败（无效地址/权限等）一律按“不相等”处理。

性能与安全提示：

- 比较逻辑以“有界、低分支”的方式生成，更友好于 eBPF 验证器。但在同一个探针中堆叠过多字符串比较，或挂在极热路径上，仍可能带来额外的 CPU 与验证负载。
- 仅需偶尔确认时，建议挂在“更新字符串字段”的代码行；或将多个较重的比较拆分为多个 `trace`。
- 读取长度内部设有上限保护；对于非常长的字面量，出于安全考虑可能被截断到内部上限。

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
```

### 表达式优先级

1. 括号 `()`
2. 成员访问 `.`，数组访问 `[]`
3. 指针解引用 `*`，取地址 `&`，一元负号 `-`
4. 乘法 `*`，除法 `/`
5. 加法 `+`，减法 `-`
6. 比较 `==`, `!=`, `<`, `<=`, `>`, `>=`
7. 逻辑与 `&&`
8. 逻辑或 `||`

### 表达式分组

```ghostscope
// 使用括号明确优先级
let result = (a + b) * c;
let complex = (x + y) / (a - b);
```

### 逻辑运算符

- `&&`（逻辑与）、`||`（逻辑或）
- 操作数按“非零为真”处理
- `||`、`&&` 均采用短路求值：
  - `||`：左侧为真则不再计算右侧
  - `&&`：左侧为假则不再计算右侧

示例

```ghostscope
trace main:entry {
    if a > 10 && b == 0 {
        print "AND";
    } else if a < 100 || p == 0 {
        print "OR";
    }
}
```

### 脚本变量与 DWARF 变量的跨类型运算

- 算术（+、-、*、/）
  - 支持：脚本变量（整数/布尔） 与 DWARF 变量中的“整数类标量”混用。
    - 整数类标量包括：BaseType（有符/无符 1/2/4/8 字节）、Enum（按底层整型）、Bitfield（位域抽取为整数）、`char/unsigned char`（1 字节整数）。
  - 不支持：聚合（struct/union/array）、指针、浮点（运行时）。
- 比较（==、!=、<、<=、>、>=）
  - 支持：脚本变量（整数/布尔） 与上述 DWARF 整数类标量；比较前会对宽度与符号进行统一。
  - 指针比较：仅支持等值/不等（DWARF 指针 == DWARF 指针、DWARF 指针 == 0）。
  - C 字符串等值：DWARF 变量（`char*` 或 `char[]`） 与 脚本变量（字符串字面量）可做 `==`/`!=` 等值比较（通过有界读取再比较）。
  - 不支持：字符串大小关系比较、聚合整体比较、浮点与 DWARF 值混用比较。
- 浮点
  - 不支持浮点运算；脚本与 DWARF 层均不支持。

错误语义：当 DWARF 变量读取失败（空指针、读失败、偏移不可用等）时，比较结果为 false、算术结果为 0，同时在事件状态中带出错误码。

示例

```ghostscope
// 与 DWARF 局部/全局的整型混合运算与比较
trace foo.c:42 {
    // 脚本 int 与 DWARF int（如 s.counter）
    if s.counter > 100 {
        print "hot";
    }
    print "sum:{}", s.counter + 5;

    // 枚举/位域比较（当作整数）
    print "active:{}", a.active == 1;
}

// 指针等值比较（不支持大小关系）
trace foo.c:50 {
    print "isNull:{}", p == 0;       // 指针与 NULL
    // print "same:{}", p == q;     // 指针与指针（若二者在作用域内）
}

// C 字符串等值：DWARF char*/char[] 与脚本字符串字面量
trace foo.c:60 {
    print "greet-ok:{}", gm == "Hello, Global!"; // gm: const char* 或 char[]
}


```

## 栈回溯语句（实现中）

打印当前调用栈：

```ghostscope
// 完整形式
backtrace;

// 简写形式
bt;
```

## 示例

### 基础函数追踪

```ghostscope
trace main {
    print "程序启动";
    print "PID: {}", $pid;
}
```

### 监控函数参数

```ghostscope
trace calculate {
    print "calculate({}, {})", $arg0, $arg1;

    if $arg0 > 1000 {
        print "检测到大输入";
        bt;
    }
}
```

### 条件追踪

```ghostscope
trace malloc {
    if $arg0 > 1048576 {  // 1 MB
        print "大内存分配: {} 字节", $arg0;
        backtrace;
    }
}
```

### 结构体字段访问

```ghostscope
trace process_user {
    print "用户: {}", user.name;
    print "ID: {}", user.id;

    if user.status == 1 {
        print "活跃用户";
    }
}
```

### 复杂变量访问

```ghostscope
trace handle_request {
    // 数组访问
    print "第一项: {}", items[0];

    // 嵌套结构体访问
    print "配置值: {}", config.network.timeout;

    // 指针操作
    print "解引用: {}", *ptr;
    print "地址: {}", &variable;
}
```

### 脚本文件中的多个追踪点

```ghostscope
// script.gs 文件
trace server_accept {
    print "新连接";
}

trace server_process {
    print "处理请求类型: {}", $arg0;
}

trace server_respond {
    print "发送响应代码: {}", $arg1;
}
```

## 限制

1. **无循环**：出于安全考虑，不支持循环（`for`、`while`）
2. **无函数定义**：不能定义自定义函数
3. **只读**：不能修改被追踪程序的状态
4. **字符串操作有限**：支持 C 字符串等值（==/!=）与内置函数 `strncmp`/`starts_with`；不支持字符串连接或一般性字符串处理
5. **有限的算术运算**：仅支持基本运算，不支持位运算
6. **无动态内存**：不能分配内存

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
- 追踪模式匹配支持文件模糊匹配（参见[命令参考](command-reference.md)）
### 一元负号（Unary Minus）

- 语义：对表达式取相反数，支持递归嵌套。
- 解析：按 `0 - expr` 处理，确保 `-1`、`-x`、`-(-1)` 等都按有符号整数求值。
- 示例：

```ghostscope
trace foo.c:42 {
    let a = -1;          // a = -1
    let b = -(-1);       // b = 1
    print a;             // 输出: a = -1
    print "X:{}", b;     // 输出: X:1
}
```
